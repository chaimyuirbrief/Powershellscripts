# PowerShell Scripts

A collection of standalone Windows administration and cleanup scripts. Each is
self-contained — download the `.ps1` and run it in an elevated PowerShell window
unless noted otherwise.

Most target **Windows PowerShell 5.1** (the built-in shell) and also work in
PowerShell 7+.

## Running a script

Scripts that modify the system need an elevated (Administrator) PowerShell. If
script execution is blocked, bypass the policy for that one process:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\<script>.ps1
```

## Index

| Script | Purpose | Elevation | Notes |
|--------|---------|-----------|-------|
| `getridofmcafee.ps1` | Fully removes McAfee: runs official uninstallers, then force-removes leftover processes, services, drivers, tasks, AppX packages, folders and registry keys. | Admin | Supports `-Force` (unattended), `-DeepScan` (whole-drive sweep), `-SkipUninstallers`. Writes a transcript to `%TEMP%`. |
| `UninstallEdge.ps1` | Uninstalls Microsoft Edge via its own `setup.exe`. Does **not** delete shared folders or WebView2 by default. | Admin | `-RemoveWebView2` to also remove the WebView2 runtime. Consumer Windows often blocks Edge removal. |
| `Fix_iqvw64e.sys_error/` | Removes Dell SupportAssist / PC-Doctor leftovers that trigger HVCI / Code Integrity blocks (e.g. the `iqvw64e.sys` popup). | Admin | Logs to `C:\Logs`. Reboot afterwards. |
| `RemoveAdobeCredentials/Remove-Adobe-Creds.ps1` | Deletes only Credential Manager entries whose target contains "adobe". | User | `-WhatIf` previews. Writes before/after inventories. |
| `DISM AND SFC script/Run-DISM-SFC.ps1` | Runs DISM ScanHealth → CheckHealth → RestoreHealth, then SFC /scannow, with a summary log. | Admin | Detailed logs stay in `C:\Windows\Logs\DISM` and `\CBS`. |
| `Orphaned MSI files cleanup.ps1` | Finds orphaned MSI/MSP packages in the Windows Installer cache, exports a CSV, and moves them to a backup folder. | Admin | Non-destructive — moves rather than deletes. |
| `ForceDeleteStuckDirectory.ps1` | Force-deletes a stubborn folder/file, escalating through takeown/icacls and queuing locked items for deletion at next reboot. | Admin | `-Path` is required; refuses to touch drive roots and system folders. |
| `LiveBitlockerDecryptionMonitor.ps1` | Live progress + ETA for a BitLocker decrypt/encrypt job. | User | `-DriveLetter C:` `-IntervalSeconds 10`. |
| `PingMonitor.ps1` | Continuous timestamped ping monitor with logging. | User | `-Target`, `-IntervalSeconds`, `-LogDir`. |
| `Export all saved Wi-Fi's.ps1` | Exports saved Wi-Fi profiles (incl. cleartext passwords) to a CSV. | User | Output contains plaintext passwords — handle with care. |

## ⚠️ Safety

Several of these scripts **delete files, services, or software**. They include
guards against removing drive roots and core system folders, but you should
still read a script before running it and make sure you have backups. The
Wi-Fi export writes cleartext passwords to disk — delete the CSV when done.
