<#
.SYNOPSIS
    Repeatedly sweeps an IPv4 range until a target MAC address is found in the
    ARP/neighbor cache, then reports the IP associated with that MAC.

.DESCRIPTION
    A ping sweep forces ARP resolution (layer 2) for each host BEFORE the ICMP
    request, so the ARP cache is populated even for hosts that drop pings.
    After each sweep the script checks the neighbor cache for the target MAC.
    If not found, it waits and rescans -- forever by default, or up to -MaxAttempts.

    NOTE: ARP only works inside the same layer-2 broadcast domain. The target
    device must be on the same subnet/VLAN as the machine running this script.

.PARAMETER Subnet
    The /24 to sweep, e.g. "192.168.1". "192.168.1.0", "192.168.1.x" and
    "192.168.1.0/24" are accepted too; other prefix lengths are refused.

.PARAMETER StartHost
    First last-octet to sweep (default 1).

.PARAMETER EndHost
    Last last-octet to sweep (default 254).

.PARAMETER TargetMac
    MAC to look for. Any format accepted: 00-11-22-33-44-55, 00:11:22:33:44:55,
    or 001122334455.

.PARAMETER DelaySeconds
    Seconds to wait between rescans (default 10).

.PARAMETER MaxAttempts
    Max number of sweeps. 0 = infinite (default).

.PARAMETER PingTimeoutMs
    Per-host ping timeout in ms (default 200).

.EXAMPLE
    .\Find-IpByMac.ps1 -Subnet 192.168.1 -TargetMac "AA-BB-CC-11-22-33"

.EXAMPLE
    .\Find-IpByMac.ps1 -Subnet 10.0.0 -StartHost 1 -EndHost 50 `
        -TargetMac "aabbcc112233" -DelaySeconds 5 -MaxAttempts 100
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Subnet,
    [ValidateRange(0,255)] [int]$StartHost = 1,
    [ValidateRange(0,255)] [int]$EndHost   = 254,
    [Parameter(Mandatory)] [string]$TargetMac,
    [int]$DelaySeconds   = 10,
    [int]$MaxAttempts    = 0,
    [int]$PingTimeoutMs  = 200
)

function Convert-Mac {
    param([string]$Mac)
    ($Mac -replace '[^0-9A-Fa-f]', '').ToUpper()
}

function Invoke-PingSweep {
    param([string]$Subnet, [int]$Start, [int]$End, [int]$TimeoutMs)
    $pingers = @()
    $tasks   = @()
    foreach ($i in $Start..$End) {
        $p = New-Object System.Net.NetworkInformation.Ping
        $pingers += $p
        $tasks   += $p.SendPingAsync("$Subnet.$i", $TimeoutMs)
    }
    try {
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks)
    } catch {
        # Individual failures (unreachable hosts) are expected; ignore them.
    } finally {
        $pingers | ForEach-Object { $_.Dispose() }
    }
}

function Find-IpByMac {
    param([string]$NormalizedTarget)

    # Prefer Get-NetNeighbor (Win8 / Server 2012+) -- cleaner than parsing arp -a.
    # Only Reachable (confirmed within the last ~30s -- a host that just answered
    # the sweep's ARP is Reachable) and Permanent (static) entries count. Stale,
    # Delay and Probe are unconfirmed: if this PC last talked to the device at
    # an older address, that entry survives here and would be reported as FOUND
    # on the first sweep, before the device is even plugged in. A device whose
    # entry had gone Stale is confirmed by Windows within seconds and shows up
    # on the next sweep instead.
    if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LinkLayerAddress -and
                $_.State -in @('Reachable','Permanent') -and
                (Convert-Mac $_.LinkLayerAddress) -eq $NormalizedTarget
            }
        if ($neighbors) { return @($neighbors.IPAddress) }
    }
    else {
        $arp = arp -a
        $hits = foreach ($line in $arp) {
            if ($line -match '(\d{1,3}(\.\d{1,3}){3})\s+([0-9A-Fa-f-]{17})') {
                if ((Convert-Mac $Matches[3]) -eq $NormalizedTarget) { $Matches[1] }
            }
        }
        if ($hits) { return @($hits) }
    }
    return $null
}

# --- validate / normalize the target MAC ---
$target = Convert-Mac $TargetMac
if ($target.Length -ne 12) {
    Write-Error "Invalid MAC address: '$TargetMac' (needs 12 hex digits)."
    return
}

# --- validate / normalize the subnet ---
# Accept the ways people actually write a /24 -- 192.168.1, 192.168.1.0,
# 192.168.1.x, 192.168.1.0/24 -- and reduce them to the three octets the sweep
# needs. Taken as-is, "192.168.1.0" would be swept as "192.168.1.0.42": not an
# IP, so .NET looks it up as a hostname, the lookup fails, no ping goes out,
# ARP never fires, and every sweep would report "not found" forever.
$subnetInput = $Subnet
if ($Subnet.Trim() -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\.(?:\d{1,3}|x|\*))?\.?(?:/(\d{1,2}))?$') {
    Write-Error "Invalid subnet: '$subnetInput'. Give the first three octets of the network, e.g. -Subnet 192.168.1"
    return
}
$m = $Matches
$octets = @([int]$m[1], [int]$m[2], [int]$m[3])
if ($octets | Where-Object { $_ -gt 255 }) {
    Write-Error "Invalid subnet: '$subnetInput'. Each octet must be 0-255."
    return
}
$Subnet = $octets -join '.'
if ($m[4] -and $m[4] -ne '24') {
    Write-Error "Only one /24 is swept at a time, and '$subnetInput' is a /$($m[4]). Run it once for each /24 to search, e.g. -Subnet $Subnet"
    return
}

$prettyMac = ($target -split '(..)' -ne '' ) -join ':'

Write-Host "Looking for MAC $prettyMac on $Subnet.$StartHost-$EndHost" -ForegroundColor Cyan
Write-Host "Rescan delay: ${DelaySeconds}s | Max attempts: $(if($MaxAttempts -le 0){'infinite'}else{$MaxAttempts})`n"

$attempt = 0
while ($true) {
    $attempt++
    Write-Host ("[{0}] Sweep #{1} ..." -f (Get-Date -Format HH:mm:ss), $attempt) -NoNewline

    Invoke-PingSweep -Subnet $Subnet -Start $StartHost -End $EndHost -TimeoutMs $PingTimeoutMs
    Start-Sleep -Milliseconds 300   # let the ARP cache settle

    $found = Find-IpByMac -NormalizedTarget $target
    if ($found) {
        Write-Host " FOUND" -ForegroundColor Green
        foreach ($ip in $found) {
            Write-Host ("`n  {0}  =>  {1}" -f $prettyMac, $ip) -ForegroundColor Green
        }
        return $found
    }

    Write-Host " not found"
    if ($MaxAttempts -gt 0 -and $attempt -ge $MaxAttempts) {
        Write-Warning "MAC $prettyMac not found after $attempt sweep(s)."
        break
    }
    Start-Sleep -Seconds $DelaySeconds
}