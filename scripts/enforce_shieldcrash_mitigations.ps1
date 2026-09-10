<#
.SYNOPSIS
    Applies interim host-hardening compensating controls for ShieldCrash (CVE-2026-69414 bypass).
#>

Write-Host "[*] Applying ShieldCrash Zero-Day Compensating Controls..." -ForegroundColor Cyan

# 1. Enforce PowerShell Constrained Language Mode system-wide
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
Write-Host "[+] PowerShell Constrained Language Mode enforced (__PSLockdownPolicy = 4)." -ForegroundColor Green

# 2. Audit DACLs on raw credential hives
$Targets = @(
    "$env:SystemRoot\System32\config\SAM",
    "$env:SystemRoot\System32\config\SECURITY"
)

foreach ($file in $Targets) {
    $acl = Get-Acl -Path $file
    Write-Host "`n[+] DACL Audit for $file" -ForegroundColor Yellow
    $unauthAccess = $acl.Access | Where-Object { $_.IdentityReference -match "Users" }
    if ($null -eq $unauthAccess) {
        Write-Host "    Compliant: Standard Users have no direct ACL read permissions." -ForegroundColor Green
    } else {
        $unauthAccess | Format-Table IdentityReference, FileSystemRights, AccessControlType
    }
}
