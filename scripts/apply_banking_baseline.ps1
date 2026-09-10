<#
.SYNOPSIS
    Applies Gatekeeper Bank ASR hardening baseline to local Windows endpoint.
.DESCRIPTION
    Enforces three critical Attack Surface Reduction rules in Block Mode (1):
    - Block credential stealing from LSASS
    - Block Office applications from creating child processes
    - Block obfuscated scripts
#>

Write-Host "[*] Applying GKB Banking Endpoint Baseline..." -ForegroundColor Cyan

Set-MpPreference -AttackSurfaceReductionRules_Ids @(
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block LSASS credential stealing
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # Block Office child processes
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc"  # Block obfuscated scripts
) -AttackSurfaceReductionRules_Actions @("1", "1", "1")

Write-Host "[+] ASR Banking Baseline Rules successfully applied in Block Mode." -ForegroundColor Green
