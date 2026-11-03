# --- Attack A: password spray ---
# Timeline of failures and successes from the attacker IP
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624; StartTime=(Get-Date).AddMinutes(-10)} |
  Where-Object { $_.Message -match '192.168.56.101' } |
  ForEach-Object { [PSCustomObject]@{ Time=$_.TimeCreated; EventId=$_.Id; Account=$_.Properties[5].Value } } |
  Format-Table -AutoSize

# Alert-style: any source IP failing against 3+ distinct accounts in 10 minutes
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-10)} |
  ForEach-Object { [PSCustomObject]@{ Src=$_.Properties[19].Value; User=$_.Properties[5].Value } } |
  Group-Object Src |
  Where-Object { ($_.Group.User | Sort-Object -Unique).Count -ge 3 } |
  Select-Object @{n='SourceIP';e={$_.Name}}, @{n='Failures';e={$_.Count}}, @{n='DistinctAccounts';e={($_.Group.User | Sort-Object -Unique).Count}}

# --- Attack B: LSASS dumping ---
# Process creation with dump-related command lines (requires 4688 command-line auditing)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'lsass' -and $_.Message -match 'procdump|MiniDump|comsvcs' } |
  Format-List TimeCreated, Message

# Sysmon ProcessAccess on lsass (produces events on hosts without PPL)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'TargetImage:.*lsass.exe' } | Format-List TimeCreated, Message

# --- Sensor health ---
& 'C:\Windows\Sysmon64.exe' -c
