<#
.SYNOPSIS
    Audits local Attack Surface Reduction rule enforcement state.
#>

$Preferences = Get-MpPreference

$Rules = [ordered]@{
    "LSASS Protection    " = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    "Block Office Child  " = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    "Block Obfuscated Scr" = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
}

Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "     GKB ENDPOINT SECURITY BASELINE COMPLIANCE      " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Host Name: $env:COMPUTERNAME"

foreach ($name in $Rules.Keys) {
    $guid = $Rules[$name]
    $idx = [array]::IndexOf($Preferences.AttackSurfaceReductionRules_Ids, $guid)
    $action = if ($idx -ne -1) { $Preferences.AttackSurfaceReductionRules_Actions[$idx] } else { "Not Set" }
    
    $status = switch ($action) {
        "1" { "ENFORCED (Block)" }
        "2" { "AUDIT ONLY" }
        default { "DISABLED" }
    }
    Write-Host "$name : $status" -ForegroundColor Green
}
Write-Host "====================================================`n" -ForegroundColor Cyan
