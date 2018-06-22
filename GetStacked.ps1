$Stack = Get-SysmonLog -ComputerName 157meusrv -LogID 1

$Stack | Group-Object Command_Line | Sort-Object Count | Select-Object Count, Name | Format-Table -AutoSize