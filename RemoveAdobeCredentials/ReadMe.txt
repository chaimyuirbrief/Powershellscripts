Preview first (no changes):

powershell -ExecutionPolicy Bypass -File C:\Temp\Remove-Adobe-Creds.ps1 -WhatIf

Delete only “adobe” entries:

powershell -ExecutionPolicy Bypass -File C:\Temp\Remove-Adobe-Creds.ps1

Notes

Works on the current user’s Credential Manager (“Windows/Generic Credentials”).

Uses cmdkey so it only touches entries whose Target string matches “adobe”; nothing else is modified.

Creates three files (before/after inventories + action log) next to the script for auditability.

Want a one-liner? Preview:

cmdkey /list | Select-String -Pattern '^\s*Target:\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Where-Object { $_ -match 'adobe' }


Delete (careful—no preview):

cmdkey /list | Select-String '^\s*Target:\s*(.+)$' | % { $_.Matches[1].Value } | ? { $_ -match 'adobe' } | % { cmdkey /delete:"$_" }


If you want this to run against another user profile, run it as that user (or in their session) so it operates on their credential store.