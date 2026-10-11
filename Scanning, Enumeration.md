# **🛡️ Day 04: Scanning, Enumeration & Network Fingerprinting Deep-Dive (The Ultimate Masterclass)**

> **Certification & Industry Alignment:** **CEH v13 (AI-Powered)**, **CPENT AI**, **OSCP**, **NIST SP 800-115**  
> **Golden Principle:**
> 
> - **Scanning** batata hai: _"Kaunsa system alive hai aur kaunse darwaze (ports) khule hain?"_
> - **Enumeration** batata hai: _"Darwaze ke andar kya chal raha hai, kaunse users hain, aur chabi (misconfiguration) kahan padi hai?"_
> - **Analysis** batata hai: _"In kamzoriyon ko jod kar target ko kaise compromise karein?"_

---

                       SCANNING & ENUMERATION LIFECYCLE

                                       │

  ┌────────────────────────────────────┼────────────────────────────────────┐

  ↓                                    ↓                                    ↓

1. HOST DISCOVERY            2. PORT & SERVICE SCANNING           3. PROTOCOL ENUMERATION

• ARP Ping (LAN Layer 2)     • TCP SYN / Connect / Inverse        • SMB / NetBIOS (445/139)

• ICMP Echo / Mask / Time    • UDP & SCTP Probing                 • SNMP (161) & MIB Walking

• TCP SYN/ACK (Layer 4)      • Nmap Engine & Masscan/RustScan     • LDAP, RPC, NFS, DNS, SMTP

  │                                    │                                    │

  └────────────────────────────────────┼────────────────────────────────────┘

                                       ↓

                           4. OS & STACK FINGERPRINTING

                           • Active (ISN, TCP Options, -O)

                           • Passive (p0f, TTL / TCP Window)

                                       ↓

                           5. FIREWALL & IDS/IPS EVASION

                           • Packet Fragmentation & MTU

                           • Decoy IPs, Source Port, Timing

                                       ↓

                           6. VULNERABILITY ANALYSIS (VA)

                           • Nessus / OpenVAS NASL Feeds

                           • CVE & NVD Correlation

---

## **1. Core Terminology & The Mental Model**

|Stage|Real-World Analogy|Technical Objective|Target Impact|
|---|---|---|---|
|**Scanning**|Ek colony me ghoom kar dekhna ki kaunse gharon me lights on hain aur kaunse darwaze khule hain.|Live hosts, open ports, aur active network services ko identify karna.|Surface-level interaction (Packets sent, but no deep query).|
|**Enumeration**|Khule darwaze par jakar andar poochhna: _"Ghar me kaun-kaun rehta hai, locker kahan hai, aur WiFi password kya hai?"_|Active services se deep data nikalna (Usernames, Shares, Groups, Routing tables, Banners).|**Aggressive & Interactive** (Direct queries to services).|
|**Fingerprinting**|Building ka structural map banana: _"Ye building kis saal bani thi aur iska cement kaunsa hai?"_|Exact Operating System, kernel version, software stack aur build version pehchanna.|Signature matching (RFC 793 quirks, TTL, HTTP headers).|
|**Vulnerability Analysis**|Pata lagana ki boundary wall me darar kahan hai.|Collected versions ko known CVEs aur misconfigurations se compare karna.|Database cross-referencing (NVD, Exploit-DB).|

---

## **2. Host Discovery (Network Sweeping at Layers 2, 3 & 4)**

Jab client enterprise subnet (`/16` ya `/24`) deta hai, toh scan speed badhane ke liye offline systems ko filter out karna zaroori hota hai.

                         HOST DISCOVERY PROTOCOLS

                                    │

     ┌──────────────────────────────┼──────────────────────────────┐

     ↓                              ↓                              ↓

LAYER 2 (Data Link)           LAYER 3 (Network)              LAYER 4 (Transport)

• ARP Ping (-PR)              • ICMP Echo (-PE)              • TCP SYN Ping (-PS)

• Bypasses all LAN firewalls  • ICMP Timestamp (-PP)         • TCP ACK Ping (-PA)

                              • ICMP Address Mask (-PM)      • UDP Ping (-PU)

### **A. Host Discovery Comparison Table**

|Probe Type|Nmap Switch|Working Mechanism|Response if Host is Alive|Firewall Bypass Strength|
|---|---|---|---|---|
|**ARP Ping**|`nmap -PR -sn`|Local network me ARP Request broadcast hoti hai.|**ARP Reply** (Target ka MAC address)|**Unstoppable on LAN** (OS firewall ARP block nahi kar sakta).|
|**ICMP Echo**|`nmap -PE -sn`|Standard Ping (ICMP Type 8) packet bhejta hai.|**ICMP Echo Reply** (Type 0)|Low (External edge routers/firewalls drop kar dete hain).|
|**ICMP Timestamp**|`nmap -PP -sn`|Remote machine ka system time query karta hai (Type 13).|**ICMP Timestamp Reply** (Type 14)|Medium (Agar admin ne sirf Type 8 block kiya ho).|
|**ICMP Mask**|`nmap -PM -sn`|Target ki Subnet mask query karta hai (Type 17).|**ICMP Address Mask Reply** (Type 18)|Medium (Internal network routing leaks).|
|**TCP SYN Ping**|`nmap -PS80,443 -sn`|Port 80/443 par SYN packet bhejta hai.|**SYN-ACK** (Open) ya **RST** (Closed)|**High** (Web-facing servers traffic allow karte hain).|
|**TCP ACK Ping**|`nmap -PA80,3389 -sn`|Port 80 par unsolicited ACK bhejta hai.|**RST Packet**|**High** (Stateless firewalls ise live connection samajhte hain).|
|**UDP Ping**|`nmap -PU53,161 -sn`|Port 40125 ya 53 par empty UDP packet bhejta hai.|**ICMP Port Unreachable**|Bypasses strict TCP-only firewalls.|
|**IP Protocol Ping**|`nmap -PO -sn`|Raw IP packets bhejta hai (ICMP=1, IGMP=2, IP-in-IP=4).|Protocol-specific response|Specialty routing device discovery.|

---

## **3. Advanced Port Scanning Mechanics & RFC 793 Quirks**

TCP protocol standard (**RFC 793**) ke rules ko leverage karke hackers stealth aur firewall discovery perform karte hain.

       RFC 793 RULE:

       • If a port is CLOSED: Any unexpected packet (without RST) must elicit a RST packet.

       • If a port is OPEN: Packets without SYN, ACK, or RST must be SILENTLY DROPPED.

### **A. The Master Port Scan Matrix**

|Scan Technique|Nmap Flag|Sent Flags|Open Port Action|Closed Port Action|Filtered Action|Core Benefit & Limitations|
|---|---|---|---|---|---|---|
|**TCP Connect**|`-sT`|`SYN`|Completes 3-way Handshake (`SYN-ACK` ➔ `ACK`)|`RST/ACK`|No response|❌ Non-root, very noisy, logged by application logs.|
|**SYN (Stealth)**|`-sS`|`SYN`|Half-open (`SYN-ACK` ➔ sends `RST` to abort)|`RST/ACK`|No response|✅ **Industry Standard**. Fast, stealthy, not logged by apps.|
|**NULL Scan**|`-sN`|_None (0)_|**No response (Drop)**|`RST`|No response / ICMP block|Bypasses naive firewalls. Fails on Windows (all return RST).|
|**FIN Scan**|`-sF`|`FIN`|**No response (Drop)**|`RST`|No response / ICMP block|Bypasses SYN-only packet filters. Fails on Windows.|
|**Xmas Scan**|`-sX`|`FIN+PSH+URG`|**No response (Drop)**|`RST`|No response / ICMP block|Lights up packet like a Christmas tree. Fails on Windows.|
|**Maimon Scan**|`-sM`|`FIN+ACK`|**No response (Drop)**|`RST`|No response / ICMP block|BSD-derived TCP/IP stacks ko probe karta hai.|
|**ACK Probe**|`-sA`|`ACK`|`RST` (Window > 0)|`RST` (Window = 0)|**No response**|**Stateful Firewall Mapper**: Batata hai port filtered hai ya nahi.|
|**Window Scan**|`-sW`|`ACK`|`RST (Non-Zero Window)`|`RST (Zero Window)`|No response|TCP Window size analyze karke open ports batata hai.|
|**UDP Scan**|`-sU`|_UDP Payload_|Application Data ya **No response**|`ICMP Type 3 Code 3 (Port Unreachable)`|ICMP unreachable errors|Extremely slow (OS rate-limits ICMP errors to 1/sec).|

---

### **B. Understanding Nmap's 6 Port States**

1. **Open:** Target port par service listening hai aur connect karne ke liye ready hai (`SYN-ACK` mila).
2. **Closed:** Target online hai, lekin us port par koi software nahi chal raha (`RST` reply mila).
3. **Filtered:** Firewall ya WAF ne probe ko drop kar diya; scanner ko koi response nahi mila.
4. **Unfiltered:** Port accessible hai, lekin open hai ya closed ye verify nahi ho saka (ACK scan result).
5. **Open|Filtered:** Scanner ye decide nahi kar pa raha ki port open hai (silent drop) ya firewall ne drop kiya (Filtered).
6. **Closed|Filtered:** Scanner closed aur filtered me farq nahi kar pa raha (IPID Idle scan error).

---

### **C. The Blind IDLE / Zombie Scan (`-sI`) Architecture**

> **Exam Favorite (CEH):** Ek bilkul silent scan jisme attacker target par **ek single packet bhi apne IP se nahi bhejta**.

                           IDLE (ZOMBIE) SCAN SEQUENCE

  [ ATTACKER ]                  [ ZOMBIE HOST ]                  [ TARGET HOST ]

       │                               │                                │

       │ ── 1. SYN-ACK to Zombie ────► │                                │

       │ ◄─ 2. RST (Records IPID = 100)│                                │

       │                               │                                │

       │ ── 3. Spoofed SYN (Src = Zombie IP) ─────────────────────────► │

       │                               │                                │

       │                               │ ◄── 4a. IF OPEN: SYN-ACK ───── │

       │                               │ ─── 4b. RST (IPID becomes 101)►│

       │                               │                                │

       │                               │ ◄── 4c. IF CLOSED: RST ─────── │

       │                               │     (Zombie drops RST; IPID stays 100)

       │                               │                                │

       │ ── 5. SYN-ACK to Zombie ────► │                                │

       │ ◄─ 6. RST (Check IPID) ────── │                                │

       │                               │                                │

  VERDICT:

  • Agar Zombie IPID = 102 (+2 jump) ➔ TARGET PORT IS OPEN!

  • Agar Zombie IPID = 101 (+1 jump) ➔ TARGET PORT IS CLOSED!

---

## **4. Modern Scanning Tools Comparison: Nmap vs Masscan vs RustScan**

Industry me modern red teams in teeno tools ko combine karke workflow banate hain:

[ STEP 1: RAW VELOCITY ]         [ STEP 2: HYBRID BRIDGE ]         [ STEP 3: SURGICAL INTELLIGENCE ]

       Masscan                          RustScan                                Nmap

(Custom user-space SYN,           (Rust async concurrency,              (Scripting Engine, Version

 scans internet in minutes)        hands ports directly to Nmap)         probes, OS quirks, CVE check)

|Feature|Nmap|Masscan|RustScan|
|---|---|---|---|
|**Speed**|Moderate (Standard OS kernel stack)|**Insane** (Custom user-space packet driver)|**Ultra-Fast** (Adaptive threading in Rust)|
|**Accuracy**|Highest (Very low false positives)|High (Only port discovery)|High|
|**Service Probing**|Full version detection (`-sV`)|None (Raw open/closed check)|Delegates directly to Nmap|
|**Scripting / CVE**|NSE Engine (600+ scripts)|None|Delegates directly to Nmap|
|**Use Case**|Deep targeted assessment (`/24`)|Internet-scale or `/16` network sweeps|CTFs & fast internal enterprise pentests|

#### **Best Practice Command Workflow:**

bash

# 1. Rustscan se 65,535 ports 10 second me scan karein aur Nmap ko pass karein:

rustscan -a 192.168.1.50 --ulimit 5000 -- -sV -sC -Pn -oA target_deep_scan

# 2. Large Class-B subnet par Masscan se open HTTP/HTTPS dhundhein:

masscan -p80,443,8080,8443 10.10.0.0/16 --rate 5000 -oG masscan_web.gnmap

---

## **5. OS & Service Fingerprinting (Active vs Passive)**

### **A. Passive OS Fingerprinting (Zero Packets Sent to Target)**

Wireshark ya `p0f` me target se aane wale normal traffic ke **TTL (Time to Live)** aur **TCP Window Size** ko inspect karke OS pehchana jata hai:

|Operating System Family|Default Initial TTL|Initial TCP Window Size|Typical TCP Flags Order|
|---|---|---|---|
|**Linux (Kernel 2.4 - 5.x / Android)**|**64**|**5840 / 29200**|`MSS, SACK, Timestamp, NOP, WScale`|
|**Windows (7, 10, 11, Server 2016-2022)**|**128**|**8192 / 65535**|`MSS, NOP, WScale, NOP, NOP, SACK`|
|**Cisco Routers / Network Appliances**|**255**|**4128**|Strict hardware defaults|
|**FreeBSD / OpenBSD / macOS**|**64**|**65535**|Berkeley sockets defaults|

> 📌 **Network Hop Calculation Rule:**  
> Agar target ka TTL Wireshark me `52` dikh raha hai:  
> Attacker ko pata hai nearest standard value `64` hai.  
> Hops=64−52=12 Intermediate Routers/Firewalls\text{Hops} = 64 - 52 = \mathbf{12\text{ Intermediate Routers/Firewalls}}Hops=64−52=12 Intermediate Routers/Firewalls.

---

### **B. Active OS Fingerprinting (`nmap -O`)**

Nmap target par 16 specific probes bhejta hai:

1. **T1 probe:** Sequence prediction check (ISN counter randomness).
2. **T2-T7 probes:** Invalid flag combinations (e.g., SYN with FIN, URG without ACK).
3. **U1 probe:** Closed UDP port probe (ICMP port unreachable reply structure).
4. Matches against **`nmap-os-db`** (2,600+ OS signatures).

---

## **6. Protocol-Specific Enumeration Masterclass**

Enumeration phase me raw port numbers ko **exploitable user accounts, shared files, aur internal configurations** me badla jata hai.

---

### **A. SMB & NetBIOS Enumeration (Ports 137, 138, 139, 445)**

Windows networks ka sabse exposed attack surface.

                          SMB ENUMERATION FLOW

                                   │

      ┌────────────────────────────┼────────────────────────────┐

      ↓                            ↓                            ↓

1. NULL SESSIONS             2. SHARE PERMISSIONS         3. RID CYCLING

(Empty user "" & pass "")    (Read/Write access on IPC$,  (Sid-to-User mapping:

                              Admin$, C$, Public shares)   500=Admin, 501=Guest)

#### **Essential Commands:**

bash

# 1. Modern Comprehensive SMB Enumerator

enum4linux-ng -A 192.168.1.10 -oA enum4linux_report

# 2. SMB Share Permissions & Content Listing

smbmap -H 192.168.1.10 -u "guest" -p ""

# 3. Interactive SMB Client connection

smbclient -L //192.168.1.10 -N          # List shares anonymously

smbclient //192.168.1.10/SharedFiles -N  # Connect to share without password

# 4. NetBIOS Name Table Enumeration

nbtscan -r 192.168.1.0/24

- **NetBIOS Name Suffixes (CEH Must-Know):**
    - `<00>`: Workstation Service (Computer Name / Domain Name)
    - `<20>`: File Server Service (File Sharing Enabled)
    - `<1B>`: Domain Master Browser
    - `<1D>`: Master Browser

---

### **B. SNMP Enumeration (Port 161 UDP)**

Simple Network Management Protocol — Network routers, switches, aur servers ka monitoring protocol.

#### **Core Concepts:**

- **Community String:** SNMP ka cleartext password.
    - `public` (Default Read-Only)
    - `private` (Default Read-Write)
- **MIB (Management Information Base):** Hierarchical structured database jisme system metrics store hote hain.
- **OID (Object Identifier):** MIB tree ke nodes ka numeric address.

#### **High-Value OIDs Table:**

|OID Path|Enumerated Information|
|---|---|
|`1.3.6.1.2.1.1.1`|**System Description** (OS Version, Hardware, Kernel, Hostname)|
|`1.3.6.1.2.1.25.4.2.1.2`|**Running Processes List** (Reveals antivirus, databases, internal software)|
|`1.3.6.1.2.1.25.6.3.1.2`|**Installed Software Packages** (Targeted local privilege escalation CVEs)|
|`1.3.6.1.4.1.77.1.2.25`|**User Accounts** (Domain & local Windows usernames)|
|`1.3.6.1.2.1.4.21`|**IP Routing Tables** (Internal network paths & DMZ gateways)|

#### **Practical Tools:**

bash

# 1. Fast Community String Brute-forcing

onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt 192.168.1.10

# 2. Automated Deep SNMP Audit

snmpcheck -t 192.168.1.10 -c public

# 3. Full Recursive MIB Walk

snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.25.4.2.1.2

---

### **C. LDAP & Active Directory Enumeration (Port 389 / 636)**

Lightweight Directory Access Protocol — Enterprise networks ka centralized identity provider.

bash

# 1. Anonymous LDAP Root DSE Query (Domain naming context extract karna)

ldapsearch -x -H ldap://192.168.1.10 -s base namingcontexts

# 2. Dump all Domain Users via unauthenticated bind

ldapsearch -x -H ldap://192.168.1.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# 3. Nmap LDAP Scripts

nmap -p 389 --script ldap-search,ldap-rootdse 192.168.1.10

---

### **D. NFS & RPC Enumeration (Port 111 / 2049)**

Network File System — Unix/Linux network file storage.

bash

# 1. Check RPC program registration

rpcinfo -p 192.168.1.10

# 2. Enumerate exported network directories

showmount -e 192.168.1.10

# 3. Unauthenticated Mount Exploitation

mkdir /tmp/nfs_loot

mount -t nfs 192.168.1.10:/var/backup /tmp/nfs_loot -o nolock

_(Agar mount me `no_root_squash` enabled ho, toh attacker local system se root privilege escalation execute kar sakta hai)._

---

### **E. SMTP Enumeration (Port 25)**

Mail transfer service jo user accounts verify karne ke liye use hoti hai.

bash

# Connect using Netcat

nc -vn 192.168.1.10 25

# SMTP User Verification Commands:

VRFY root          # 250 2.1.5 root@corp.local (User exists!)

VRFY fakeuser      # 550 5.1.1 User unknown

EXPN dev-team      # Expands mail distribution lists

---

## **7. Firewall & IDS/IPS Evasion Techniques**

┌─────────────────────────────────────────────────────────────────────────┐

│                      IDS vs IPS BEHAVIOR IN SCANS                       │

├────────────────────────────────────┬────────────────────────────────────┤

│  IDS (Intrusion Detection System)  │  IPS (Intrusion Prevention System) │

│  • Passive Listener (SPAN port)    │  • In-line Device (Gateway path)   │

│  • Alerts generate karta hai       │  • Packets drop / IP block karta hai│

│  • Detects abnormal port spikes    │  • Enforces dynamic rate limits    │

└────────────────────────────────────┴────────────────────────────────────┘

### **Advanced Nmap Evasion Arsenal:**

1. **Packet Fragmentation (`-f` ya `--mtu 16`):**
    - IP header ke baad TCP header ko 8 ya 16 bytes ke chunks me divide karta hai taaki deep packet inspection (DPI) signatures match na hon.
2. **Decoy Source Spoofing (`-D RND:10`):**
    - Real packet ke sath 10 fake random IPs ke packets mix karta hai. Target ke firewall logs me real IP decoys ke beech chhup jati hai.
3. **Source Port Masquerading (`--source-port 53`):**
    - Legacy firewalls DNS (53) ya NTP (123) ports se aane wale return packets ko allow kar dete hain.
4. **Scan Timing Throttling (`-T0` / `-T1`):**
    - `-T0` (Paranoid) har probe ke beech **5 minutes** ka gap deta hai. Threshold-based alert systems trip nahi hote.
5. **Host Order Randomization (`--randomize-hosts`):**
    - Subnet ko sequential scan karne ke bajaye random order me scan karta hai.
6. **Data Length Padding (`--data-length 25`):**
    - Default Nmap packets empty hote hain. Random payload bytes add karne se standard Nmap packet signature break ho jati hai.

---

## **8. Wireshark Packet Inspection Cheat Sheet**

Testing aur CTF labs ke dauran network traffic verify karne ke liye display filters:

text

# 1. Detect TCP SYN Scan (SYN sent, no ACK)

tcp.flags.syn == 1 && tcp.flags.ack == 0

# 2. Detect Xmas Scan (FIN + PUSH + URG flags enabled)

tcp.flags == 0x029

# 3. Detect NULL Scan (No flags enabled in TCP header)

tcp.flags == 0x000

# 4. Detect RST responses (Target telling port is closed)

tcp.flags.reset == 1

# 5. Filter all ICMP Port Unreachable packets (UDP closed ports)

icmp.type == 3 && icmp.code == 3

# 6. Capture plain SNMP Community Strings

snmp.community

---

## **9. Defensive Countermeasures (Hardening Blueprint)**

|Attack Vector|Defensive Action|Hardening Configuration|
|---|---|---|
|**Port Scanning**|Restrict perimeter exposure & drop probes|Stateful firewall rules (Default DROP instead of REJECT/RST).|
|**OS Fingerprinting**|Normalize TCP/IP stack signatures|Enable `tcp_timestamps = 0`, randomize IPIDs, suppress ICMP errors.|
|**SMB Leaks**|Block NetBIOS & restrict shares|Disable SMBv1, require SMB Signing, block ports 139/445 at perimeter.|
|**SNMP Enumeration**|Restrict OID tree visibility|Upgrade to **SNMPv3 (USM with SHA auth & AES encryption)**; remove `public`.|
|**Banner Grabbing**|Suppress software & version strings|Web server configuration: `ServerTokens Prod`, `ServerSignature Off`.|

---

## **10. The 30-Day Practical Mastery Roadmap**

WEEK 1: NETWORKING & PACKET FOUNDATIONS

[ ] Day 01-02: IPv4 Subnetting Math, CIDR, Octets & Python calculation scripts.

[ ] Day 03-04: TCP 3-Way Handshake & 6 Control Flags packet dissection in Wireshark.

[ ] Day 05-07: Layer 2 ARP Sweeps vs Layer 3 ICMP Sweeps vs Layer 4 TCP SYN discovery.

WEEK 2: SURGICAL PORT SCANNING

[ ] Day 08-10: Nmap Port States (Open, Closed, Filtered) & RFC 793 Inverse Scans (FIN, NULL, Xmas).

[ ] Day 11-12: The Blind IPID Zombie Scan (-sI) setup in an isolated VM lab.

[ ] Day 13-14: Masscan & RustScan benchmarking against full Class-B ranges.

WEEK 3: DEEP PROTOCOL ENUMERATION

[ ] Day 15-17: SMB & NetBIOS enumeration (enum4linux-ng, smbmap, share null sessions).

[ ] Day 18-20: SNMP MIB walking, OID parsing, and community string hunting.

[ ] Day 21-22: Active Directory LDAP unauthenticated dumps & NFS root mount exports.

WEEK 4: EVASION, ANALYSIS & REPORTING

[ ] Day 23-25: IDS/IPS Evasion (Packet fragmentation, decoys, MTU, source port overrides).

[ ] Day 26-28: Vulnerability scanning with OpenVAS/GVM & Nessus credentialed audits.

[ ] Day 29-30: Comprehensive Network Assessment Report drafting with CVSS v3.1 metrics.