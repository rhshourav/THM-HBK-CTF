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
