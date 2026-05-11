# Run this on DEAGLE (10.0.2.6) as local admin
# Makes jsmith a local admin (so Mimikatz can dump LSASS)

Add-LocalGroupMember -Group "Administrators" -Member "ICCN\jsmith"
Write-Host "[+] jsmith added to local Administrators on DEAGLE"

# Force helpdesk to log in here so their creds are cached in LSASS
# Option A: log in interactively as helpdesk once
# Option B: trigger NTLM auth via a mapped drive while logged in as helpdesk:
Write-Host ""
Write-Host "[*] To cache helpdesk creds in LSASS, run this on DEAGLE while logged in as helpdesk:"
Write-Host '    net use \\10.0.2.8\SYSVOL /user:ICCN\helpdesk Helpdesk123!'
Write-Host '    net use * /delete /y'
