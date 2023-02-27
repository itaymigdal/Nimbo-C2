$reg_paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*", 
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
Get-ItemProperty $reg_paths |
Where-Object DisplayName -GT 0 | 
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
Sort-Object DisplayName | 
Format-Table -AutoSize