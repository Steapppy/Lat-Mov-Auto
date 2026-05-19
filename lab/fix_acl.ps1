# Run on DC (10.0.2.8) as Domain Admin
# Re-applies GenericAll from helpdesk to svc_backup and verifies it.
# Also sets adminCount=0 so SDProp stops overwriting the ACL.

Import-Module ActiveDirectory

# Remove AdminSDHolder protection — SDProp resets ACLs on objects with adminCount=1
# (happens automatically when svc_backup joined Domain Admins).
# Setting it to 0 stops SDProp from touching this object going forward.
Set-ADUser svc_backup -Replace @{adminCount = 0}
Write-Host "[+] adminCount set to 0 on svc_backup (SDProp protection removed)"

$helpdeskSid = (Get-ADUser "helpdesk").SID
$svcDN       = (Get-ADUser "svc_backup").DistinguishedName

$acl = Get-Acl "AD:\$svcDN"

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $helpdeskSid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:\$svcDN" $acl
Write-Host "[+] GenericAll ACE applied"

# Verify
Write-Host "`n[*] Verifying ACL on svc_backup:"
$check = Get-Acl "AD:\$svcDN"
$check.Access | Where-Object {
    $_.IdentityReference -like "*helpdesk*" -or
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $helpdeskSid.Value
} | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table -AutoSize
