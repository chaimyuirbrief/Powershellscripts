<# 
Fix-IQVW64E-BlockedDriver.ps1
Removes the blocked iqvw64e.sys driver (vulnerable driver blocklist / Memory Integrity).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [string]$LogPath = "$env:ProgramData\IQVW64E_Removal_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

function Write-Log {
    param([string]$Msg)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Msg
    $line | Tee-Object -FilePath $LogPath -Append
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        throw "Run this script in an elevated PowerShell (Run as Administrator)."
    }
}

Assert-Admin
Write-Log "Starting iqvw64e.sys remediation..."
Write-Log "Log: $LogPath"

$driverPath = Join-Path $env:windir "System32\drivers\iqvw64e.sys"

if (Test-Path $driverPath) {
    Write-Log "Found file: $driverPath"
    try {
        $sig = Get-AuthenticodeSignature $driverPath
        Write-Log ("Signature: {0} | Signer: {1}" -f $sig.Status, ($sig.SignerCertificate.Subject -as [string]))
    } catch {
        Write-Log "Could not read Authenticode signature: $($_.Exception.Message)"
    }
} else {
    Write-Log "iqvw64e.sys not found in System32\drivers. Will still search Driver Store packages."
}

# 1) Find any driver service pointing to iqvw64e.sys
$svc = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
       Where-Object { $_.PathName -and $_.PathName.ToLower().Contains("iqvw64e.sys") }

if ($svc) {
    foreach ($s in $svc) {
        Write-Log "Driver service found: Name=$($s.Name) DisplayName=$($s.DisplayName) State=$($s.State)"
        if ($PSCmdlet.ShouldProcess($s.Name, "Stop and delete driver service")) {
            try {
                if ($s.State -ne "Stopped") {
                    Write-Log "Stopping service $($s.Name)..."
                    sc.exe stop $s.Name | Out-Null
                    Start-Sleep -Seconds 2
                }
                Write-Log "Deleting service $($s.Name)..."
                sc.exe delete $s.Name | Out-Null
            } catch {
                Write-Log "Failed to remove service $($s.Name): $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Log "No Win32_SystemDriver service referencing iqvw64e.sys was found."
}

# 2) Identify Driver Store package(s) containing iqvw64e
Write-Log "Enumerating driver store packages via pnputil..."
$pnputilOut = & pnputil.exe /enum-drivers 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Log "pnputil /enum-drivers failed: $pnputilOut"
    throw "pnputil failed; cannot continue."
}

# Parse blocks and look for ones mentioning iqvw64e
$blocks = ($pnputilOut -split "Published Name\s*:\s*") | Where-Object { $_ -and $_.Trim() -ne "" }
$matches = @()

foreach ($b in $blocks) {
    $published = ($b -split "`r?`n")[0].Trim()
    if (-not $published) { continue }

    # rebuild the block text with the header for searching
    $blockText = "Published Name : $published`n" + $b

    if ($blockText.ToLower().Contains("iqvw64e")) {
        $provider = ($blockText -split "Driver Package Provider\s*:\s*")[1] -split "`r?`n" | Select-Object -First 1
        $class    = ($blockText -split "Class\s*:\s*")[1] -split "`r?`n" | Select-Object -First 1
        $version  = ($blockText -split "Driver Version and Date\s*:\s*")[1] -split "`r?`n" | Select-Object -First 1

        $matches += [pscustomobject]@{
            PublishedName = $published
            Provider      = ($provider ?? "").Trim()
            Class         = ($class ?? "").Trim()
            VersionDate   = ($version ?? "").Trim()
        }
    }
}

if (-not $matches -or $matches.Count -eq 0) {
    Write-Log "No driver store packages mentioning iqvw64e were found."
    Write-Log "If you still get the popup, the source may be an app re-dropping the file (often Intel driver utilities)."
    Write-Log "Done."
    return
}

Write-Log "Found matching driver store package(s):"
$matches | ForEach-Object {
    Write-Log (" - {0} | Provider={1} | Class={2} | Ver/Date={3}" -f $_.PublishedName, $_.Provider, $_.Class, $_.VersionDate)
}

# 3) Remove those packages
foreach ($m in $matches) {
    $inf = $m.PublishedName
    $action = "Delete driver package $inf (pnputil /delete-driver $inf /uninstall)"
    if ($PSCmdlet.ShouldProcess($inf, $action)) {
        Write-Log "Removing $inf ..."
        $args = @("/delete-driver", $inf, "/uninstall")
        if ($Force) { $args += "/force" }

        $out = & pnputil.exe @args 2>&1
        Write-Log $out
        Write-Log "ExitCode=$LASTEXITCODE for $inf"
    }
}

# 4) Try to remove the file if it remains (it often will be removed after reboot)
if (Test-Path $driverPath) {
    Write-Log "iqvw64e.sys still present at $driverPath. Attempting delete..."
    try {
        Remove-Item -Path $driverPath -Force -ErrorAction Stop
        Write-Log "Deleted $driverPath"
    } catch {
        Write-Log "Could not delete now (likely in use / protected). Reboot usually completes removal. Error: $($_.Exception.Message)"
    }
}

Write-Log "Completed. REBOOT recommended."
Write-Log "If it returns after reboot, uninstall/update the Intel utility that is reinstalling it (commonly Intel Driver & Support Assistant / older Intel PROSet components)."
