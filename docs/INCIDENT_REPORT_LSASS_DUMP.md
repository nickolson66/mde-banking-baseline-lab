# Incident Report: Credential Theft Attempt Interception (LotL)

**Incident ID:** INC-20260909-01  
**Severity:** High  
**Asset:** `GKB-CORP-WS01`  
**Detection Source:** Microsoft Defender Antivirus Operational Log  

---

## 1. Incident Overview
On endpoint `GKB-CORP-WS01`, Microsoft Defender intercepted an unauthorized attempt to dump process memory from the Local Security Authority Subsystem Service (`lsass.exe`). The attack executed a Living-off-the-Land technique abusing `rundll32.exe` to invoke the `MiniDump` export in `comsvcs.dll`.

---

## 2. Telemetry Artifacts
* **Event ID:** 1116 (Threat Detected) & 1121 (ASR Block Rule Triggered)
* **Threat Classification:** `HackTool:Win32/DumpLsass.H`
* **Calling Process:** `rundll32.exe`
* **Target Object:** `lsass.exe`
* **Enforcing ASR Rule:** `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from LSASS)
* **Final Disposition:** Blocked — Kernel Memory Handle Denied (`Access is denied`)

---

## 3. Containment & Remediation Actions Taken
1. Verified no dump file was written to disk (`%TEMP%` and `%LOCALAPPDATA%\Temp` audited clean).
2. Validated endpoint baseline compliance using automated audit tooling.
3. Deployed custom KQL Advanced Hunting query to identify any broader reconnaissance or dump attempts across the subnet.
