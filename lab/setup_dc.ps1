# Run this on the DC (10.0.2.8) as Domain Admin
# Domain: ICCN.local

Import-Module ActiveDirectory

$domain = "ICCN.local"

# ── 1. Create users ──────────────────────────────────────────────────────────
$users = @(
    @{ Name = "jsmith";     Pass = "Password123!"; Desc = "Regular domain user — initial foothold on WS01" },
    @{ Name = "helpdesk";   Pass = "Helpdesk123!"; Desc = "Helpdesk account — cached on WS02, has SPN" },
    @{ Name = "svc_backup"; Pass = "Backup2024!";  Desc = "Backup service account — over-privileged DA member" }
)

foreach ($u in $users) {
    if (-not (Get-ADUser -Filter { SamAccountName -eq $u.Name } -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $u.Name `
                   -SamAccountName $u.Name `
                   -UserPrincipalName "$($u.Name)@$domain" `
                   -AccountPassword (ConvertTo-SecureString $u.Pass -AsPlainText -Force) `
                   -Enabled $true `
                   -Description $u.Desc
        Write-Host "[+] Created user: $($u.Name)"
    } else {
        Write-Host "[~] Already exists: $($u.Name)"
    }
}

# ── 2. svc_backup → Domain Admins ────────────────────────────────────────────
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_backup"
Write-Host "[+] svc_backup added to Domain Admins"

# ── 3. helpdesk SPN (makes it Kerberoastable) ────────────────────────────────
Set-ADUser -Identity "helpdesk" -ServicePrincipalNames @{Add = "HTTP/ws02.ICCN.local"}
Write-Host "[+] SPN set on helpdesk: HTTP/ws02.ICCN.local"

# ── 4. helpdesk GenericAll on svc_backup ─────────────────────────────────────
$helpdeskSid = (Get-ADUser "helpdesk").SID
$svcDN       = (Get-ADUser "svc_backup").DistinguishedName
$acl         = Get-Acl "AD:\$svcDN"

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $helpdeskSid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl "AD:\$svcDN" $acl
Write-Host "[+] GenericAll granted: helpdesk -> svc_backup"

Write-Host ""
Write-Host "=== DC setup done. Now run setup_ws01.ps1 on WS01 and setup_ws02.ps1 on WS02 ==="
