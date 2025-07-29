# 🔒 Nmap 25 Pro Tools - Cybersecurity Scanning Toolkit

Welcome to the **Nmap Advanced Scanning Toolkit** – a professional-grade collection of 25 powerful Nmap commands categorized for penetration testers, ethical hackers, and cybersecurity students.

---

## 🚀 Basic Port & Service Scanning

### 1. SYN Scan (Stealth Scan)
```bash
nmap -sS  <target>
```
#### Performs a stealthy TCP SYN scan, harder to detect by firewalls
### 2. TCP Connect Scan
```bash
nmap -sT <target>
```
#### It shows only open TCP ports which are available
### 3. UDP Scan
```bash
nmap -sU <target>
```
#### It shows only open UDP ports which are available
### 4. Service Version Detection
```bash
nmap -sV <target>
```
#### Tries to detect versions of running services
### 5. OS Detection
```bash
nmap -O <target>
```
#### Attempts to detect the operating system of the target.

---

## 🛡️ Vulnerability Scanning with NSE Scripts

### 6. Run All Vulnerability Scripts
```bash
nmap --script vuln <target>
```
#### Scans target with all vulnerability detection scripts.
### 7. SMB Vulnerability Detection
```bash
nmap --script smb-vuln* -p 445  <target>
```
#### Detects SMB-related vulnerabilities like:
 ##### smb-vuln-ms17-010 (EternalBlue!)
 ##### smb-vuln-cve2009-3103
 ### 8. Heartbleed (CVE-2014-0160)
```bash
nmap --script ssl-heartbleed -p443 <target>
```
#### is used to detect if a server is vulnerable to the Heartbleed bug (CVE-2014-0160), which can leak sensitive memory like passwords and private keys.
### 9. HTTP SQL Injection
```bash
nmap --script http-sql-injection -p80 <target>
```
#### Checks for SQL injection points in web applications
### 10. HTTP Shellshock
```bash
nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p80 <target>
```
#### It checks if the target is vulnerable to the Shellshock bug through a web server.

---

## 🎭 Firewall/IDS Evasion Techniques

### 11. Packet Fragmentation
```bash
nmap -f <target>
```
#### It breaks the scan into tiny packets to bypass firewalls and avoid detection.
### 12. Decoy Scan
```bash
nmap -D RND:<no> <target>
```
#### It tries to break the firewall by sending random ip addresses , rnd: random ip address and no: how many ip addresses required .
### 13. Source Port Spoofing (Port 53)
```bash
nmap --source-port 53 <target>
```
#### It tricks the firewall by making the scan look like normal DNS traffic.
#### 14. Timing Evasion (Speed Control):
```bash
nmap -T1 <target>
```
##### Very slow speed
```bash
nmap -T2 <target>
```
##### slow speed
```bash
nmap -T3 <target>
```
##### normal speed
```bash
nmap -T4 <target>
```
##### fast speed
```bash
nmap -T5 <target>
```
##### insane speed
#### Use -T0 to -T5 to control scan speed & stealth.
### 15. Scan & Detect MAC Address (on local network):
```bash
nmap -sP  <target>/24
```
#### Shows live hosts with their IP + MAC + vendor (if on same LAN).

---

## 🧠 NSE Scripting Examples

### 16. FTP Vulnerability Checks
```bash
nmap --script ftp-vsftpd-backdoor -p  <target>
```
#### Checks if backdoor exists in vsFTPd service
### 17. SSH Authentication Brute Force:
```bash
nmap --script ssh-brute -p 22  <target>
```
#### Tries to brute-force SSH login. Good for internal pen-testing labs.
### 18. DNS Zone Transfer
```bash
nmap --script dns-zone-transfer -p53 <target>
```
#### It tries to get all DNS records from the target, which can reveal sensitive info.
### 19. HTTP Enum (Directory Detection)
```bash
nmap --script http-enum -p80 <target>
```
#### It finds hidden folders and files on a website.
### 20. Service Banner Grabbing
```bash
nmap --script banner <target>
```
#### It collects information about services running on the target, like software name and version.

---

## ⚙️ Advanced & Combo Scans

### 21. Aggressive Scan 
```bash
nmap -A <target>
```
#### Performs OS detection, version detection, script scanning, and traceroute — all together.
### 22. Default Scripts
```bash
nmap -sC <target>
```
#### It runs a set of common scripts to quickly find basic info and vulnerabilities.
### 23. Idle Scan
```bash
nmap -sI <zombie_ip> <target>
```
#### It scans a target without revealing your IP by using another idle device (zombie).
### 24. No Ping (Useful if ICMP is blocked)
```bash
nmap -Pn <target>
```
#### It skips pinging and scans the target directly, useful when ping is blocked.
### 25. Apache Struts Exploit (CVE-2017-5638)
```bash
nmap -sV --script=http-vuln-cve2017-5638 -p80 <target>
```
#### It checks if the target's Apache Struts server is vulnerable to a known remote code execution bug.

---
1. replace 'target' with the IP/domain that  you want to scan.
2. Combine multiple flags/scripts for deeper scans.
3. Use responsibly and legally. This toolkit is for **ethical hacking** only.

---

## 👨‍💻 Author
**AKSHIT.PATI (Cybersecurity Student)**  
🔗 GitHub: [https://github.com/Akshit-Pati]  
🔗 LinkedIn: [https://www.linkedin.com/in/akshitpati/]  
💡 Currently learning Cyber security

---

## 🛑 Disclaimer
This content is for **educational purposes only**. Always take **permission** before scanning any system or network.

---

🧠 *Keep learning. Keep hacking (ethically).* 💻
