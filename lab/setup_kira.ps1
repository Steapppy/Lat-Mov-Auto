# Run this on KIRA (10.0.2.14) as local admin
# Makes helpdesk a local admin and enables WinRM

Add-LocalGroupMember -Group "Administrators" -Member "ICCN\helpdesk"
Write-Host "[+] helpdesk added to local Administrators on KIRA"

Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985

Write-Host "[+] WinRM enabled on KIRA (port 5985)"
Write-Host "[*] Verify with: Test-NetConnection -ComputerName 10.0.2.14 -Port 5985"
