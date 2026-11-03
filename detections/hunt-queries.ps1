# Attack A - password spray: failed logons from attacker IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Where-Object { $_.Message -match '192.168.56.101' } | Format-List TimeCreated, Message

# Attack B - LSASS dump tooling via process creation (4688, command-line auditing on)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'lsass' -and $_.Message -match 'procdump|MiniDump|comsvcs' } |
  Format-List TimeCreated, Message

# Attack B - Sysmon ProcessAccess on lsass (fires when PPL is off)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'TargetImage:.*lsass.exe' } | Format-List TimeCreated, Message

# Verify Sysmon config is loaded
& 'C:\Windows\Sysmon64.exe' -c
