# **🌐 Advanced Network Penetration Testing: The Master Blueprint (No. 1 Practical Notes)**

> **Standard:** Aligned with **CEH v13 (AI-Powered)**, **CPENT (Certified Penetration Tester)**, **NIST SP 800-115**, aur **Real-World Red Teaming Standards**.  
> **Philosophy:** _"Penetration testing can prove the presence of security flaws, but never their total absence. Hum system ko todte nahi hain, hum use wo karne par majboor karte hain jo uske designer ne socha bhi nahi tha."_

---

                       NETWORK PENTESTING LIFECYCLE

                                    │

  ┌─────────────────────────────────┼─────────────────────────────────┐

  ↓                                 ↓                                 ↓

PHASE 1: SCOPING & ROE     PHASE 2: HOST DISCOVERY       PHASE 3: ADVANCED PORT SCAN

(Legal, IP Math, CIA)      (ARP, ICMP, SYN, UDP Sweeps)  (RFC 793, Flags, IDLE Scan)

  │                                 │                                 │

  ├─────────────────────────────────┼─────────────────────────────────┤

  ↓                                 ↓                                 ↓

PHASE 4: ENUMERATION       PHASE 5: EVASION & PROBING    PHASE 6: EXPLOIT & PIVOTING

(SNMP, SMB, RPC, NFS)      (Fragmentation, Decoys, MTU)  (Metasploit, Double Pivot)

  │                                 │                                 │

  └─────────────────────────────────┴─────────────────────────────────┘

                                    ↓

                         PHASE 7: CLEANUP & REPORT

                         (PoE, CVSS, Remediation Roadmap)

---

## **1. Network Pentesting Fundamentals, Scoping & Legal Foundations**

### **A. Core Security Terminology (The Base Definitions)**

- **Threat:** Koi bhi entity, hacker ya event jo organization ke assets ko nuksan pahuncha sakta hai.
- **Vulnerability:** System, code, network ya configuration me aisi kamzori/loophole jise exploit kiya ja sake.
- **Risk:** Threat aur Vulnerability ka combination: Risk=Threat×Vulnerability×Asset Value\text{Risk} = \text{Threat} \times \text{Vulnerability} \times \text{Asset Value}Risk=Threat×Vulnerability×Asset Value
- **Exploit:** Ek software tool, script ya crafted packet jo vulnerability ka fayda utha kar unauthorized access dilata hai.
- **Attack:** Vulnerability ko exploit karne ka actual action jo **CIA Triad** (Confidentiality, Integrity, Availability) ko violate kare.
- **Low-Hanging Fruit:** Wo aasan vulnerabilities jo bina kisi deep exploitation ke mil jati hain (e.g., Default credentials, unpatched old software, open SMB shares).

---

### **B. Ethical Hacking vs Penetration Testing vs Vulnerability Assessment**

|Dimension|Vulnerability Assessment (VA)|Penetration Testing (PT)|Ethical Hacking|
|---|---|---|---|
|**Objective**|Network me known vulnerabilities ki list banana (Identify & Quantify)|Kamzoriyon ko actively exploit karke deep access lena (Proof of Concept)|Security posture ko overall improve karna (Broader scope)|
|**Tools Used**|Automated scanners (Nessus, OpenVAS, Qualys)|Manual exploitation + Scanners (Nmap, Metasploit, NetExec, Burp)|Complete offensive + defensive toolkit|
|**Intrusiveness**|Low (Non-intrusive, rarely crashes systems)|**High** (Active exploitation, service/system crash risk)|Varies based on domain|
|**Deliverable**|Automated scan report with severity scores|Detailed exploitation paths, proof, business impact report|Strategic security recommendations|

---

### **C. Types of Penetration Testing Approaches**

#### **1. By Information Level:**

- **Black Box:** Tester ke paas koi internal knowledge nahi hoti (External attacker perspective).
- **Grey Box:** Tester ke paas partial information hoti hai (e.g., specific user credentials, network range).
- **White Box:** Tester ke paas pura architecture diagram, source code, aur admin access hota hai.

#### **2. By Awareness & Visibility:**

- **Overt (White Hat Testing):** Organization ki IT/SOC team ko pehle se pata hota hai. Testing ke dauran impact minimize kiya jata hai aur IT staff test observe karta hai.
- **Covert (Black Hat / Red Team Testing):** Upper management ki permission hoti hai par **internal IT/SOC team ko bilkul khabar nahi hoti**. Iska main aim SOC team ke detection response time ko measure karna hota hai.
- **Blind Testing:** Tester ke paas koi info nahi hoti, sirf target name pata hota hai.
- **Double-Blind Testing:** Na tester ko internal system pata hai, aur na hi internal security staff ko test ke bare me pata hai.

#### **3. By Origin:**

- **External Pentest:** Internet se perimeter firewalls, VPN gateways, aur internet-facing IPs ko target karna.
- **Internal Pentest:** Perimeter ke andar baith kar (Insider threat ya compromised workstation simulation) segmentation aur lateral movement test karna.
    
    > 📌 **Compliance Mandate (PCI DSS v4.0.1 Req 11.4):** Payment data handle karne wali organizations ke liye internal aur external network pentesting regularly perform karna legally mandatory hai.
    

---

### **D. Scoping & Rules of Engagement (RoE) — Non-Negotiable Step**

Pentest shuru karne se pehle written approval (Get Out of Jail Free Card) zaroori hai:

1. **Scope Boundaries:** Kaunse IP ranges/CIDRs in-scope hain? Kaunse production servers **strictly out-of-scope** hain?
2. **Emergency Stop Conditions:** Agar koi core database crash ho jaye ya critical service down ho, toh immediate POC (Point of Contact) kaun hoga?
3. **Exploitation Limits:** Kya DoS testing allowed hai? Kya data exfiltration allowed hai?

---

## **2. Subnetting, IP Math & Target Discovery**

Jab client sirf ek single IP aur Subnet mask deta hai, toh tester ko pura IP range calculate karna hota hai.

### **A. Subnetting Math & Python Automation**

- IPv4 me **32 bits** hote hain (4 octets of 8 bits each).
- Subnet Mask network portion aur host portion ko alag karta hai.
    - `255.255.255.0` = Pehle 24 bits Network ke liye hain (`/24` CIDR) ➔ **256 IPs** total (254 usable hosts).

#### **🐍 Python CIDR & Range Calculator:**

python

import ipaddress

ip_input = input("Enter IP (e.g. 192.168.1.50): ")

subnet_mask_input = input("Enter Subnet Mask (e.g. 255.255.255.0): ")

# Convert to network object

network = ipaddress.IPv4Network(f"{ip_input}/{subnet_mask_input}", strict=False)

print(f"\n[+] Network Address: {network.network_address}")

print(f"[+] Broadcast Address: {network.broadcast_address}")

print(f"[+] CIDR Notation: {network.network_address}/{network.prefixlen}")

print(f"[+] Total Usable Hosts: {network.num_addresses - 2}")

---

### **B. Host Discovery Techniques (Network Sweeping)**

Aksar firewalls standard ICMP Echo (Ping) ko block kar dete hain. Isliye alag-alag discovery protocols use hote hain:

                          HOST DISCOVERY SPECTRUM

                                     │

   ┌──────────────────┬──────────────┴───────┬──────────────────┐

   ↓                  ↓                      ↓                  ↓

1. ARP Ping (LAN)  2. ICMP Echo Sweep   3. TCP SYN/ACK Ping  4. UDP Ping

(Unblockable LAN)  (Blocked by FWs)     (Port 80/443 bypass) (Port 40125)

|Technique|Nmap Command|Working Mechanism|Firewalls Bypass Ability|
|---|---|---|---|
|**ARP Ping**|`nmap -PR -sn 192.168.1.0/24`|Local LAN par ARP Request bhejta hai. Hardware MAC address reply aata hai.|**100% effective in LAN** (OS/Firewall ise block nahi kar sakta).|
|**ICMP Echo Ping**|`nmap -PE -sn 192.168.1.0/24`|Standard ICMP Type 8 request bhejta hai.|External firewalls aksar drop kar dete hain.|
|**ICMP Timestamp**|`nmap -PP -sn 192.168.1.0/24`|System clock query karta hai (ICMP Type 13).|Unblockable if only ICMP Type 8 is filtered.|
|**TCP SYN Ping**|`nmap -PS80,443 -sn 192.168.1.0/24`|Target ke port 80/443 par SYN bhejta hai.|**Bypasses firewalls** jo web traffic allow karte hain.|
|**TCP ACK Ping**|`nmap -PA80,3389 -sn 192.168.1.0/24`|Direct ACK packet bhejta hai. Stateless target RST bhejta hai (Host live!).|Stateless firewalls ko bypass karta hai.|
|**UDP Ping**|`nmap -PU53,161 -sn 192.168.1.0/24`|UDP packet bhejta hai. Agar ICMP Port Unreachable aaye toh host up hai.|TCP-only filtering firewalls ko bypass karta hai.|
|**No-Ping (Skip)**|`nmap -Pn 192.168.1.10`|Discovery skip karta hai, target ko directly online maan kar port scan karta hai.|Use jab target ICMP packets ko completely silently drop kar raha ho.|

#### **Fast Ping Sweep CLI Tools:**

- **`fping`:** `fping -a -g 192.168.1.0/24` (Sirf alive hosts print karega).
- **`nping`:** `nping --tcp -p 80,443 192.168.1.0/24` (Network packet generator tool).

---

## **3. Low-Level Transport Layer & TCP/IP Mechanics**

Network scanning ko master karne ke liye **TCP Header Flags** aur **3-Way Handshake** ki deeper understanding honi chahiye.

### **A. The 6 Core TCP Control Flags**

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|          Source Port          |       Destination Port        |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                        Sequence Number                        |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                    Acknowledgment Number                      |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

| Offset| Res.  |U|A|P|R|S|F|               Window              |

|       |       |R|C|S|S|Y|I|                                   |

|       |       |G|K|H|T|N|N|                                   |

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

1. **SYN (Synchronize):** Naya connection establish karne ke liye initial packet.
2. **ACK (Acknowledge):** Data ya packet milne ka confirmation.
3. **PSH (Push):** Receiving buffer ko bypass karke application ko directly data push karna.
4. **URG (Urgent):** Packet ke andar urgent data hai jise immediately process karna hai.
5. **FIN (Finish):** Graceful connection close request (Sender ne data bhejna band kar diya).
6. **RST (Reset):** Connection ko forcibly drop/terminate karna (Error ya closed port response).

---

### **B. TCP 3-Way Handshake Mechanics**

   ATTACKER / CLIENT                                  TARGET SERVER

          │                                                 │

          │ ─── 1. [SYN] (Seq = X) ───────────────────────► │ (Port Listening)

          │                                                 │

          │ ◄── 2. [SYN-ACK] (Seq = Y, Ack = X + 1) ─────── │ (Port Open!)

          │                                                 │

          │ ─── 3. [ACK] (Seq = X + 1, Ack = Y + 1) ──────► │ (Connection Established)

          │                                                 │

- **Closed Port Behavior:** Jab client band port par `SYN` bhejta hai, toh server reply me **`RST/ACK`** bhejta hai.

---

### **C. Packet Crafting with `hping3`**

`hping3` security testers ke liye custom packets banane ka sabse powerful CLI tool hai:

bash

# 1. Custom SYN Scan (Port 80)

hping3 -S 192.168.1.1 -p 80 -c 1

# 2. Custom ACK Scan (Firewall rules probe karne ke liye)

hping3 -A 192.168.1.1 -p 80 -c 1

# 3. Custom FIN Scan

hping3 -F 192.168.1.1 -p 80 -c 1

# 4. Custom Xmas Scan (FIN, PUSH, URG flags set)

hping3 -F -P -U 192.168.1.1 -p 80 -c 1

# 5. SYN Flood Testing (Stress testing firewalls)

hping3 --flood -S -p 80 --rand-source 192.168.1.1

---

## **4. Advanced Port Scanning Techniques & RFC 793 Anomalies**

### **A. Port Scanning Master Matrix**

|Scan Type|Nmap Flag|Root Required?|Handshake Completed?|Open Port Response|Closed Port Response|Firewall Detection Value|
|---|---|---|---|---|---|---|
|**TCP Connect**|`-sT`|❌ No|✅ Yes (Full)|`SYN-ACK` ➔ `ACK`|`RST/ACK`|High noise, logs me full connection dikhta hai.|
|**SYN (Stealth)**|`-sS`|✅ Yes|❌ No (Half-open)|`SYN-ACK` ➔ `RST`|`RST/ACK`|Fast, silent, application layer log nahi hota.|
|**NULL Scan**|`-sN`|✅ Yes|❌ No flags|**No Response**|`RST`|RFC 793 standard. Windows ignore karta hai (all RST).|
|**FIN Scan**|`-sF`|✅ Yes|❌ FIN only|**No Response**|`RST`|SYN-filtering firewalls ko bypass karta hai.|
|**Xmas Scan**|`-sX`|✅ Yes|❌ FIN+PSH+URG|**No Response**|`RST`|Lights lit up like Xmas tree! Bypasses dumb packet filters.|
|**Maimon Scan**|`-sM`|✅ Yes|❌ FIN+ACK|**No Response**|`RST`|BSD-derived systems ke firewalls ko probe karta hai.|
|**ACK Scan**|`-sA`|✅ Yes|❌ ACK only|`RST`|`RST`|**Stateful vs Stateless Firewall mapper**.|
|**Window Scan**|`-sW`|✅ Yes|❌ ACK only|`RST (Window > 0)`|`RST (Window = 0)`|Window size se open ports batata hai.|
|**UDP Scan**|`-sU`|✅ Yes|N/A (Connectionless)|Response / No Resp|`ICMP Port Unreachable`|Extremely slow, service timeout par depend karta hai.|
|**SCTP INIT**|`-sY`|✅ Yes|❌ Half-open|`INIT-ACK`|`ABORT`|Telecom / VoIP infrastructure profiling.|

---

### **B. Understanding Nmap's 6 Port States**

1. **Open:** Application connection accept kar rahi hai.
2. **Closed:** Port reachable hai par koi application listen nahi kar rahi (Server ne `RST` reply diya).
3. **Filtered:** Firewall/packet filter ne probe ko drop kar diya; Nmap ko koi response nahi mila.
4. **Unfiltered:** Port reachable hai lekin Nmap ye nahi bata sakta ki open hai ya closed (ACK scan me hota hai).
5. **Open|Filtered:** Jab open port aur filtered port dono koi response nahi dete (NULL, FIN, Xmas, UDP scans).
6. **Closed|Filtered:** Nmap closed aur filtered ke beech differentiate nahi kar pa raha.

---

### **C. The Blind IPID / IDLE Zombie Scan (`-sI`) Deep Dive**

> 🏆 **Goal:** Target network ko scan karna bina apna real IP reveal kiye, aur bina target par apna single direct packet bheje!

#### **Requirement:**

Ek aisi idle third-party machine (**Zombie**) chahiye jiska network traffic bilkul zero ho aur uska **IPID (IP Identification Number)** sequence strictly incremental ho (`+1, +2, +3...`).

                    IDLE SCAN WORKFLOW STEP-BY-STEP

[ STEP 1: PROBE ZOMBIE BASELINE ]

Attacker ────────► [SYN-ACK] ────────► Zombie

Attacker ◄──────── [RST (IPID = 31337)] ◄── Zombie

[ STEP 2: SPOOF SYN TO TARGET USING ZOMBIE'S IP ]

Attacker ───► [SYN (Source IP = Zombie IP)] ───► Target Port

                     ┌───────────────────────────┐

                     │ IF TARGET PORT IS OPEN:   │

                     │ Target ──► [SYN-ACK] ──► Zombie   │

                     │ Zombie ──► [RST (IPID=31338)] ──► Target │ (Zombie IPID increments!)

                     └───────────────────────────┘

                     ┌───────────────────────────┐

                     │ IF TARGET PORT IS CLOSED: │

                     │ Target ──► [RST] ──► Zombie       │

                     │ (Zombie ignores RST, IPID remains 31337) │

                     └───────────────────────────┘

[ STEP 3: PROBE ZOMBIE AGAIN ]

Attacker ────────► [SYN-ACK] ────────► Zombie

Attacker ◄──────── [RST (IPID = 31339)] ◄── Zombie

CONCLUSION:

- Agar final IPID = 31339 (Delta = +2) ➔ TARGET PORT OPEN!

- Agar final IPID = 31338 (Delta = +1) ➔ TARGET PORT CLOSED!

- **Command:**
    
    bash
    
    nmap -Pn -sI 192.168.1.50:80 192.168.1.100
    

---

### **D. Critical Ports Quick Reference**

|Port|Protocol|Default Service|Pentest Significance|
|---|---|---|---|
|**21**|TCP|FTP|Anonymous login, cleartext auth, vsftpd backdoors|
|**22**|TCP|SSH|Brute force, private key leaks, banner fingerprinting|
|**23**|TCP|Telnet|Unencrypted legacy remote shell|
|**25**|TCP|SMTP|User enumeration (`VRFY`, `EXPN`), open mail relay|
|**53**|TCP/UDP|DNS|DNS Zone Transfer (AXFR), DNS cache poisoning|
|**88**|TCP/UDP|Kerberos|AS-REP Roasting, Kerberoasting, Ticket attacks|
|**111**|TCP/UDP|Sun RPC / rpcbind|NFS share enumeration (`showmount -e`)|
|**123**|UDP|NTP|NTP amplification DDoS, clock offset reconnaissance|
|**137-139**|TCP/UDP|NetBIOS|NetBIOS name resolution, null session leaks|
|**161/162**|UDP|SNMP|Default `public`/`private` community strings, MIB walking|
|**389/636**|TCP/UDP|LDAP / LDAPS|Active Directory domain users & groups unauthenticated dump|
|**445**|TCP|SMB|EternalBlue (MS17-010), Null sessions, PSExec, Mimikatz|
|**1433**|TCP|MS-SQL|SQL injection, `xp_cmdshell` remote command execution|
|**1521**|TCP|Oracle DB|Default SIDs, TNS listener poisoning|
|**2049**|TCP/UDP|NFS|Misconfigured world-readable root mounts|
|**3306**|TCP|MySQL|Weak root password, database dumping|
|**3389**|TCP|RDP|BlueKeep (CVE-2019-0708), brute force, NLA status|
|**5985/5986**|TCP|WinRM (HTTP/S)|Remote PowerShell management, lateral movement|

---

## **5. OS & Service Fingerprinting & Vulnerability Analysis**

### **A. Active vs Passive OS Fingerprinting**

#### **1. Active Fingerprinting (`nmap -O`):**

Nmap target ko multiple crafted TCP/UDP packets bhejta hai aur target ke response ke 12 alag-alag features inspect karta hai:

- TCP Initial Sequence Number (ISN) predictability
- TCP Options order (MSS, Window Scale, SACK, Timestamp)
- Quirks on invalid flag responses
- Matches against **2,600+ known signatures** in `nmap-os-db`.

#### **2. Passive Fingerprinting (Sniffing TTL & Window Size):**

Target ko ek bhi packet send kiye bina, sirf aane wale packets ke IP TTL aur TCP Window Size dekh kar OS pata lagana (e.g., using `Wireshark` ya `p0f`):

|Operating System|Default IP TTL|Initial TCP Window Size|
|---|---|---|
|**Linux (Kernel 2.4 - 5.x)**|**64**|**5840 / 29200**|
|**Windows 7 / 10 / Server 2016+**|**128**|**8192 / 65535**|
|**Cisco Routers (IOS 12.x)**|**255**|**4128**|
|**FreeBSD / OpenBSD**|**64**|**65535**|

---

### **B. Service Version Probing (`nmap -sV`)**

- **Mechanism:** Port open milne par Nmap custom probes (HTTP GET, RPC requests, SMTP HELO) bhejta hai aur response banner ko `nmap-service-probes` database se match karta hai.
- **Intensity:** `--version-intensity <0-9>` (Default: 7. Higher = more probes, slower scan).

---

### **C. Automated Vulnerability Scanning Engines: Nessus vs OpenVAS**

|Feature|Tenable Nessus|Greenbone Vulnerability Management (OpenVAS)|
|---|---|---|
|**Core Architecture**|Nessus Engine + Plugins (Proprietary)|GVM Manager + OpenVAS Scanner Daemon (Open-Source)|
|**Scripting Engine**|**NASL** (Nessus Attack Scripting Language)|NASL fork maintained by Greenbone Feed|
|**Scan Types**|Credentialed & Uncredentialed Network Audits|Full and fast, System Discovery, Deep NVTs|
|**Deployment**|Standalone installer / Cloud-linked|Full Docker stack (PostgreSQL + GVMD + OSPD)|

> 🔑 **Credentialed vs Uncredentialed Scans:**
> 
> - **Uncredentialed:** Bahar se open ports aur response banners dekhta hai (Finds ~20% of vulnerabilities).
> - **Credentialed (Authenticated):** SSH ya SMB admin credentials use karke target ke andar login karta hai aur installed software, missing registry security patches aur local configurations audit karta hai (Finds **100% of internal patch vulnerabilities**).

---

## **6. Protocol-Specific Enumeration Deep Dive**

Jab specific ports open milte hain, tab deep enumeration execute ki jaati hai:

### **A. SNMP Enumeration (Port 161/162 UDP)**

Admins aksar SNMP configure karke bhool jaate hain, aur default community string **`public`** (Read-Only) ya **`private`** (Read-Write) reh jati hai.

bash

# 1. SNMP Brute-force Community Strings

onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt 192.168.1.10

# 2. Comprehensive System Enum with snmp-check

snmpcheck -t 192.168.1.10 -c public

# 3. Full MIB Tree Walk (Extract all processes, storage, network interfaces)

snmpwalk -c public -v 2c 192.168.1.10

- **High-Value OIDs:**
    - `1.3.6.1.2.1.25.4.2.1.2` ➔ Running Process Names
    - `1.3.6.1.2.1.25.6.3.1.2` ➔ Installed Software List
    - `1.3.6.1.4.1.77.1.2.25` ➔ Local User Accounts

---

### **B. SMB & NetBIOS Enumeration (Port 139/445 TCP)**

bash

# 1. Null Session & Share Check with Enum4linux

enum4linux -a 192.168.1.10

# 2. SMB Map (Check Read/Write permissions on shared folders)

smbmap -H 192.168.1.10 -u "guest" -p ""

# 3. Nmap SMB Vulnerability Scripts

nmap -p 445 --script smb-vuln-ms17-010,smb-enum-shares,smb-enum-users 192.168.1.10

---

### **C. RPC & NFS Enumeration (Port 111 / 2049)**

bash

# RPC Services List

rpcinfo -p 192.168.1.10

# Check Exposed NFS Mounts

showmount -e 192.168.1.10

# Mount remote folder locally without password

mkdir /mnt/target_nfs

mount -t nfs 192.168.1.10:/shared_data /mnt/target_nfs -o nolock

---

## **7. Firewall & IDS/IPS Evasion Techniques**

                         EVASION VECTOR MATRIX

                                   │

   ┌───────────────────────┬───────┴───────────────┬───────────────────────┐

   ↓                       ↓                       ↓                       ↓

1. Packet Fragmentation  2. Decoy IP Spoofing    3. Source Port Mod      4. Timing & Bad Checksums

(-f / --mtu 16)          (-D RND:10)             (--source-port 53)      (-T0/T1 / --badsum)

1. **Packet Fragmentation (`nmap -f` ya `--mtu 16`):**
    - TCP header ko multiple chote IP packets me tod deta hai taaki packet inspection systems signature match na kar sakein.
2. **Decoy Scanning (`nmap -D RND:10 <target>`):**
    - Target ko lagta hai ki 10 alag-alag random IP addresses use ek saath scan kar rahe hain. Attacker ka real IP decoys ke beech chup jata hai.
3. **Source Port Manipulation (`nmap --source-port 53`):**
    - DNS (53) ya HTTP (80) source port use karna. Bohot se puraane firewalls port 53 se aane wale traffic ko trusted internal DNS reply samajh kar allow kar dete hain.
4. **Bad Checksums (`nmap --badsum <target>`):**
    - Packets me deliberately invalid TCP/UDP checksum bhejna. Real hosts ise drop kar dete hain, lekin agar reply aa jaye toh iska matlab beech me koi stateless firewall ya proxy baithi hai.

---

## **8. Exploitation, Metasploit Integration & Lateral Movement**

### **A. Metasploit + Nmap Integration (`db_nmap`)**

Kali Linux me pentest activities ko track karne ke liye PostgreSQL database integrated hota hai:

bash

# Metasploit console shuru karein

msfconsole

# Naya isolated workspace banayein

msf > workspace -a NASA_Project

# Database-integrated Nmap scan chalayein

msf > db_nmap -A -sV 192.168.1.10

# Discovered targets aur services dekhein

msf > hosts

msf > services

# Vulnerability modules filter karein

msf > vulns

---

### **B. Live Case Study: OpenSSL Heartbleed (CVE-2014-0160) Exploitation**

- **Vulnerability:** OpenSSL ke TLS Heartbeat extension me bounds check missing tha. Attacker server se 64KB allocated memory data bina authentication ke dump kar sakta tha.
- **Metasploit Execution:**
    
    bash
    
    msf > use auxiliary/scanner/ssl/openssl_heartbleed
    
    msf auxiliary(openssl_heartbleed) > set RHOSTS 192.168.99.11
    
    msf auxiliary(openssl_heartbleed) > set RPORT 5001
    
    msf auxiliary(openssl_heartbleed) > set action DUMP
    
    msf auxiliary(openssl_heartbleed) > run
    
- **Impact:** Process memory se private SSL keys, session cookies aur user credentials plain text me exfiltrate ho gaye.

---

### **C. Searchsploit (Offline Exploit Database Mastery)**

bash

# Service & exact version se exploit dhoondhna

searchsploit apache mod_ssl 2.8.4

# Exploit code apne folder me copy karna

searchsploit -m 7618

# Exploit code ko inspect karna

searchsploit -x 7618.c

# Nmap XML file ko seedha searchsploit se scan karna

searchsploit --nmap scan_results.xml

---

### **D. Advanced Lateral Movement: Double Pivoting (CPENT AI Standard)**

Jab target machine direct accessible na ho, balki internal dual-homed machine ke peeche ho:

[ Attacker: 10.10.10.5 ] 

         │ (Compromised Machine 1 - Dual Homed)

         ▼

[ Pivot Host A: 10.10.10.20 & 192.168.1.1 ] 

         │ (Compromised Machine 2 - Dual Homed)

         ▼

[ Pivot Host B: 192.168.1.50 & 172.16.0.1 ] 

         │ (Deep Hidden Segment)

         ▼

[ Final Target: 172.16.0.100 ]

- **Pivoting Mechanism:**
    1. Meterpreter session par **AutoRoute** add karein: `run autoroute -s 192.168.1.0/24`
    2. SOCKS Proxy server start karein: `use auxiliary/server/socks_proxy`
    3. `/etc/proxychains4.conf` me proxy configure karein.
    4. Local system se `proxychains nmap -sT -Pn 172.16.0.100` chala kar hidden segment ko exploit karein!

---

### **E. Wireless Penetration Testing (NASA Study Guide Integration)**

- **WEP Cracking:**
    - RC4 Key Scheduling Algorithm ki kamzori par based hota hai (**FMS / KoreK / PTW attack**).
    - `airodump-ng` se ARP packets capture karke `aircrack-ng` kuch hi hazar IVs (Initialization Vectors) me WEP key crack kar deta hai.
- **WPA / WPA2 Handshake Cracking:**
    - **4-Way Handshake (EAPOL):** Pre-Shared Key (PSK) nikalne ke liye full 4 packets zaroori nahi hote; **Aircrack-ng sirf 2 packets (Packet 2 & 3 ya 3 & 4)** se bhi dictionary attack chala sakta hai.
- **WPS PIN Brute Force (Reaver):**
    - Wi-Fi Protected Setup (WPS) 8-digit PIN verification me pehle 4 digits aur aakhri 3 digits separately validate hote hain (Total search space sirf 104+103=11,00010^4 + 10^3 = 11,000104+103=11,000 attempts!).
    - `reaver -i wlan0mon -b [BSSID] -vv` ➔ 4 se 10 ghante ke andar plain text WPA/WPA2 passphrase recover ho jata hai.

---

## **9. Post-Engagement Cleanup & Professional Reporting**

### **A. Post-Engagement Cleanup (Clean Tracks)**

Testing khatam hone ke baad client network ko uski original state me restore karna professional standard hai:

1. **User Accounts:** Test ke dauran banaye gaye temporary user accounts (e.g., `A1SecurityAssessment_user`) delete ya deactivate karein.
2. **Artifacts & Shells:** Upload kiye gaye reverse shell scripts, web shells, binaries aur test files delete karein.
3. **Configurations:** Firewall ya registry me kiye gaye modifications ko revert karein.
4. **Log Review:** Client ke IT team ko bataiye ki test ke dauran kaunse logs generate hue taaki wo unhe investigate karke detection rules tune kar sakein.

---

### **B. CVSS v3.1 Scoring Calculator Cheat Sheet**

   BASE SCORE METRICS

   ├── Attack Vector (AV): Network [N: 0.85] | Adjacent [A: 0.62] | Local [L: 0.55]

   ├── Attack Complexity (AC): Low [L: 0.77] | High [H: 0.44]

   ├── Privileges Required (PR): None [N: 0.85] | Low [L: 0.62] | High [H: 0.27]

   ├── User Interaction (UI): None [N: 0.85] | Required [R: 0.62]

   ├── Scope (S): Unchanged [U] | Changed [C]

   └── Impact Metrics (C / I / A): None [0.0] | Low [0.22] | High [0.56]

- **Formula Rating:**
    - **0.0:** None
    - **0.1 – 3.9:** Low
    - **4.0 – 6.9:** Medium
    - **7.0 – 8.9:** High
    - **9.0 – 10.0:** **Critical** (Remote, unauthenticated, full compromise jaise SQLi/RCE).

---

### **C. Enterprise Pentest Report Structure**

1. **Title Page & Change Record:** Version history, authors, dates, NDA/Confidentiality status.
2. **Executive Management Summary:** Non-technical summary, total findings ka pie chart (Critical/High/Med/Low), key business risks.
3. **Scope & Methodology:** Tested IP ranges, user accounts, OWASP/PTES framework details.
4. **Detailed Technical Findings:**
    - Vulnerability Title & Severity (CVSS Vector String)
    - Affected Assets (Host & Port)
    - Technical Description & Root Cause
    - Step-by-Step Proof of Concept (PoC) with Screenshots & Code
    - Business Impact
    - Concrete Remediation Steps (Code snippets, config fixes)
5. **Remediation Roadmap:**
    - Immediate (Next 30 Days): Critical & High patches
    - Mid-Term (Next 90 Days): Architecture hardening & headers
    - Long-Term (Next 180 Days): Secure SDLC training & continuous attack surface monitoring