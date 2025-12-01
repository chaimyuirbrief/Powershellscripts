✅ How to Run the Script
Open PowerShell as Administrator
Run the following command exactly as shown:
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\Temp\Run-DISM-SFC.ps1

This does the following:
Temporarily bypasses script execution restrictions
Runs your script directly from C:\Temp

✅ Confirm Script Is Running Correctly
You should see output like:
=== Starting DISM ScanHealth ===
<live terminal output>
=== Starting DISM CheckHealth ===
...
=== Starting SFC Scan ===
...
All steps completed. Log saved to C:\Logs\dism_sfc_log.txt