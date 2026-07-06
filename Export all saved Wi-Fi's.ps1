<#
.SYNOPSIS
    Export every saved Wi-Fi profile on this machine (SSID, auth, cipher and
    cleartext password) to a CSV on the Desktop.

.DESCRIPTION
    Reads profiles via "netsh wlan". Passwords are written in PLAIN TEXT, so
    treat the output file as sensitive - anyone who reads it gets your Wi-Fi
    keys. Delete it when you're done.

    Parsing splits each netsh line on the FIRST colon only, so SSIDs and keys
    that themselves contain ":" are handled correctly.

    Note: netsh output is localized. On non-English Windows the field labels
    below ("Authentication", "Cipher", ...) differ and matching may miss;
    adjust the labels for your language if so.
#>
param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\WiFi_Profiles.csv"
)

# netsh only reveals the cleartext key (key=clear) for all-user profiles when
# run elevated. Warn rather than fail, since per-user profiles may still work.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Not running as Administrator - passwords for all-user profiles may come back blank. Re-run elevated for full results." -ForegroundColor Yellow
}

# Return the value of a "Label : value" field. Matches the label against the
# KEY (text before the first colon), not the whole line, so an SSID whose name
# happens to contain a field word (e.g. "Authentication") can't poison a field.
function Get-NetshValue {
    param([string[]]$Text, [string]$Label)
    foreach ($line in $Text) {
        $s = "$line"
        $idx = $s.IndexOf(':')
        if ($idx -lt 0) { continue }
        $key = $s.Substring(0, $idx).Trim()
        if ($key -like "*$Label*") { return $s.Substring($idx + 1).Trim() }
    }
    return ''
}

# Get all saved Wi-Fi profile names (split on first ':' to survive SSIDs with colons)
$profileNames = netsh wlan show profiles | Select-String 'All User Profile|Profile\s' | ForEach-Object {
    $s = $_.ToString()
    $idx = $s.IndexOf(':')
    if ($idx -ge 0) { $s.Substring($idx + 1).Trim() }
} | Where-Object { $_ } | Select-Object -Unique

if (-not $profileNames) {
    Write-Host "No saved Wi-Fi profiles found." -ForegroundColor Yellow
    return
}

$wifiProfiles = foreach ($name in $profileNames) {
    # quote the name so SSIDs with spaces/special chars are passed intact
    $details = netsh wlan show profile name="$name" key=clear

    [PSCustomObject]@{
        SSID           = $name
        Authentication = Get-NetshValue $details 'Authentication'
        Encryption     = Get-NetshValue $details 'Cipher'
        SecurityKey    = Get-NetshValue $details 'Security key'
        Password       = Get-NetshValue $details 'Key Content'
    }
}

$wifiProfiles | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($wifiProfiles.Count) Wi-Fi profile(s) to: $OutputPath" -ForegroundColor Green
Write-Host "WARNING: this file contains cleartext Wi-Fi passwords. Delete it when done." -ForegroundColor Yellow
