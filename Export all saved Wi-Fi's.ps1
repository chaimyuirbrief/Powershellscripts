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

# pull the value after the first ':' on the first line that matches $label
function Get-NetshValue {
    param([string[]]$Text, [string]$Label)
    $line = $Text | Select-String -SimpleMatch "$Label" | Select-Object -First 1
    if (-not $line) { return '' }
    $s = $line.ToString()
    $idx = $s.IndexOf(':')
    if ($idx -lt 0) { return '' }
    return $s.Substring($idx + 1).Trim()
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
