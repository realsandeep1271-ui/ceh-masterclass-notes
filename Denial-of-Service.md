# **CEH v13 AI — Module 10: Denial-of-Service (DoS / DDoS)**

### **Advanced Protocol Engineering, Telemetry Diagnostics & Enterprise Mitigation Frameworks**

---

## **Master Architecture & Roadmap**

+------------------------------------------------------------------------------------------------------------------------+

|                                        MODULE 10: DoS / DDoS ENGINEERING ROADMAP                                       |

+------------------------------------------------------------------------------------------------------------------------+

|  [01] Mathematical Consumption Models --> Asymmetry Physics, Backlog Depletion Math, Amplification Multipliers        |

|  [02] L3/L4 Protocol Exploitation     --> TCP SYN Floods (RFC 793), Teardrop Integer Underflow, ICMP/UDP Broadcasts   |

|  [03] Volumetric Reflection Engines   --> DNS EDNS0, NTP Monlist (550x), SSDP, Memcached (50,000x), CLDAP Reflection   |

|  [04] Application-Layer (L7) Attacks  --> Slowloris Header Starvation, RUDY POST Injection, HTTP/2 Rapid Reset        |

|  [05] Tooling & Botnet Architectures  --> Hping3 CLI Flags, Trinoo/TFN2K Hierarchies, Mirai IoT Infection Engine       |

|  [06] Telemetry & Kernel Diagnostics  --> /proc/net/netstat, Socket Counter Analysis, CUSUM Anomaly Detection        |

|  [07] Stateless Kernel Mitigations    --> RFC 4987 SYN Cookies (24-3-5 Bit Allocation), Linux sysctl Tuning            |

|  [08] Edge Anti-Spoofing & Scrubbing  --> BCP 38 Ingress Filtering, uRPF (Strict vs Loose), Cisco TCP Intercept         |

|  [09] Upstream BGP & Anycast Defense  --> Destination/Source RTBH (Null0), BGP Anycast Global Scrubbing Centers       |

|  [10] Wireless 802.11 Layer DoS       --> Physical RF Jamming Models, Deauth / Disassociation (802.11w Protected Frames)|

+------------------------------------------------------------------------------------------------------------------------+

---

## **1. Curricular Taxonomy & Mathematical Consumption Models**

Denial-of-Service operations **CIA Triad** ke **Availability** attribute ko target karti hain (mapped to MITRE ATT&CK Tactic: _Impact_, Techniques: `T1498` Network DoS & `T1499` Endpoint DoS).

Traditional exploitation targets authentication ya memory corruption to gain execution privileges. In contrast, DoS operations **Asymmetric Consumption Models** par operate karti hain: **Attacker minimal computational/bandwidth overhead expend karta hai, jabki victim ke disproportionately large resources deplete ho jate hain.**

                                  +───────────────────────────────────+

                                  |    DoS / DDoS THREAT SPECTRUM     |

                                  +───────────────────────────────────+

                                                    │

             ┌──────────────────────────────────────┼──────────────────────────────────────┐

             ▼                                      ▼                                      ▼

   [ Volumetric (L3/L4) ]                 [ Protocol (L3/L4) ]                    [ Application (L7) ]

   - Metric: Bits/sec (bps)               - Metric: Packets/sec (pps)             - Metric: Requests/sec (rps)

   - Target: Pipe & Transit Links         - Target: Firewall/Kernel State Tables  - Target: Worker Threads & Database

   - Mechanism: UDP/NTP Amplification     - Mechanism: SYN Floods, Fragments      - Mechanism: Slowloris, RUDY, HTTP/2

### **1.1 Mathematical Model: Socket Backlog Depletion Rate**

Transport-layer state exhaustion attack (e.g., TCP SYN flood) me server har incoming SYN request ke liye kernel memory me ek **Transmission Control Block (TCB)** allocate karta hai aur socket state ko `SYN-RECEIVED` me shift kar deta hai.

Jab tak client final `ACK` nahi bhejta, server ka connection slot open rehta hai jab tak **Retransmission Timeout (TtimeoutT_{\text{timeout}}Ttimeout​)** expire na ho jaye (typically 75–120 seconds in default Linux kernels).

Connection backlog table ko completely saturate karne ke liye required spoofed packet arrival rate (λsaturate\lambda_{\text{saturate}}λsaturate​) ka mathematical formulation:

λsaturate=BTtimeout\lambda_{\text{saturate}} = \frac{B}{T_{\text{timeout}}}λsaturate​=Ttimeout​B​

- **BBB:** Socket Backlog Capacity (defined by `net.core.somaxconn` & application `listen(backlog)` parameter).
- **TtimeoutT_{\text{timeout}}Ttimeout​:** Cumulative half-open retention window (timeout duration).

Example: Agar B=1024 connections, and Ttimeout=100 seconds:\text{Example: Agar } B = 1024 \text{ connections, and } T_{\text{timeout}} = 100 \text{ seconds:}Example: Agar B=1024 connections, and Ttimeout​=100 seconds: λsaturate=1024100≈10.24 packets per second (pps)\lambda_{\text{saturate}} = \frac{1024}{100} \approx 10.24 \text{ packets per second (pps)}λsaturate​=1001024​≈10.24 packets per second (pps)

> **Critical Takeaway:** Ek attacker ko multi-gigabit bandwidth ki zaroorat nahi hai. Sirf **~11 packets per second** bhej kar 1,024-connection queue wale server ka port completely paralyze kiya ja sakta hai!

---

### **1.2 Mathematical Model: Volumetric Reflection & Amplification Physics**

Reflection attacks connectionless protocols (**UDP**) par rely karte hain kyunki UDP me three-way handshake ya sequence verification nahi hoti, jisse source IP spoofing possible hoti hai.

Amplification factor (α\alphaα) initial query aur returned response ke payload size ka ratio hota hai:

α=Payload SizeResponsePayload SizeRequest\alpha = \frac{\text{Payload Size}_{\text{Response}}}{\text{Payload Size}_{\text{Request}}}α=Payload SizeRequest​Payload SizeResponse​​

|Protocol Vector|Default Port|Transport|Vulnerable Command / Interface|Typical Amplification Factor (α\alphaα)|Technical Exploitation Mechanism|
|---|---|---|---|---|---|
|**DNS**|53|UDP|EDNS0 / `ANY` record queries|**28× to 54×**|Open recursive resolvers receive 50-byte queries and return multi-KB cryptographically signed DNSSEC responses.|
|**NTP**|123|UDP|`monlist` diagnostic command|**550×**|Ek 48-byte query par NTP daemon un last 600 clients ki IP list return karta hai jinhone synchronize kiya tha (spread over 100 packets).|
|**SSDP**|1900|UDP|`M-SEARCH` unicast probes|**30×**|UPnP-enabled consumer IoT routers large service discovery XML descriptions return karte hain.|
|**Memcached**|11211|UDP|Unauthenticated `get` dump|**10,000× to 50,000×**|Exposed caching instances single-byte requests par multi-megabyte cached key values return kar dete hain.|
|**CLDAP**|389|UDP|`RootDSE` search queries|**56× to 70×**|Misconfigured Active Directory Domain Controllers unauthenticated UDP search par extensive directory schemas return karte hain.|

Physical Consequence: 100 Mbps Upload Link×550(NTP monlist)=55 Gbps Transmitted Wave!\text{Physical Consequence: } 100\text{ Mbps Upload Link} \times 550 (\text{NTP monlist}) = \mathbf{55\text{ Gbps Transmitted Wave!}}Physical Consequence: 100 Mbps Upload Link×550(NTP monlist)=55 Gbps Transmitted Wave!

---

## **2. Layer 3 & Layer 4 Protocol Exploitation Mechanics**

### **2.1 TCP SYN Flooding (RFC 793 / RFC 4987)**

Standard TCP Three-Way Handshake:

1. `Client -> Server: SYN (Seq=X)`
2. `Server -> Client: SYN-ACK (Seq=Y, Ack=X+1)` →\rightarrow→ Server allocates TCB in memory (`SYN-RECV` state).
3. `Client -> Server: ACK (Seq=X+1, Ack=Y+1)` →\rightarrow→ Transition to `ESTABLISHED`.

Attacker (Spoofing 198.51.100.X)                   Victim Server (192.168.1.10)

            │                                                    │

            │─── [1] TCP SYN (Src: Spoofed, Dst: Port 80) ───────▶│ Allocates TCB slot

            │                                                    │ State: SYN-RECV

            │                                                    │ Starts Timer (100s)

            │                                                    │

Unroutable IP ◀── [2] TCP SYN-ACK (Sent to fake source IP) ──────│

 (Packet Lost)                                                   │

                                                                 │ *Waiting for final ACK...*

   [ NO FINAL ACK RETURNED ] ───────────────────────────────────▶│ Backlog Table Fills Up!

                                                                 │ Legitimate Clients DROPPED!

### **2.2 IP Packet Fragmentation Vulnerabilities**

IPv4 headers me packet fragmentation ke liye teen fields hoti hain: **Identification (16-bit)**, **Flags (3-bit)**, aur **Fragment Offset (13-bit)**.

       IPv4 Packet 1: Offset = 0,   Length = 1500 bytes (Range: 0 - 1499)

       IPv4 Packet 2: Offset = 600, Length = 1000 bytes (Range: 600 - 1599)

                               │

                               ▼

       [ Overlapping Offset Bug (Teardrop Exploit) ]

       Reassembly length calculation: Length = End_Offset - Start_Offset

       Unpatched OS integer underflow -> Buffer Overflow / Kernel Panic (BSOD)!

- **Teardrop Exploit:** Attacker deliberate overlapping fragment offsets bhejta hai. Kernel jab reassembly payload calculate karta hai, to internal variables me integer underflow generate hota hai, triggering system crash or kernel panic.
- **Ping of Death:** Multiple fragmented ICMP packets transmit kiye jate hain jinka combined reassembly size maximum IPv4 packet limit (**65,535 bytes**) ko exceed kar jata hai. Vulnerable network stacks me buffer overflow ho jata hai.

---

## **3. Application-Layer (Layer 7) Resource Starvation**

Layer 7 attacks perimeter stateful firewalls ko bypass kar dete hain kyunki ye **valid L4 TCP three-way handshake** complete karte hain. Target web server ka thread pool aur application memory exhaust hoti hai.

### **3.1 Slowloris (HTTP Header Starvation)**

Standard HTTP specifications ke mutabiq, request headers ke end me double CRLF hona mandatory hai: `\r\n\r\n`.

Victim Web Server (Apache prefork/worker - MaxRequestWorkers = 150)

     │

     ├── Socket 1: "GET / HTTP/1.1\r\nHost: target.com\r\n" ──▶ [Worker Thread 1 Busy]

     ├── Socket 2: "GET / HTTP/1.1\r\nHost: target.com\r\n" ──▶ [Worker Thread 2 Busy]

     │   ... (Opens 150 parallel sockets)

     └── Socket 150: ...                                   ──▶ [Worker Thread 150 Busy]

          │

          ▼

     Every 10-15 seconds (Before Timeout Expires):

     Attacker sends dummy keep-alive header: "X-Keep-Alive: 1\r\n"

     Server resets idle timer! Threads NEVER RELEASED!

     Legitimate users encounter "HTTP 504 Gateway Timeout" or connection refusal!

### **3.2 R-U-Dead-Yet? (RUDY — HTTP POST Chunk Injection)**

RUDY attack HTTP `POST` requests ko abuse karta hai:

1. Client ek legitimate `POST` request bhejta hai with large `Content-Length`:
    
    http
    
    POST /login.php HTTP/1.1
    
    Host: target.com
    
    Content-Type: application/x-www-form-urlencoded
    
    Content-Length: 1000000
    
2. Server 1 MB data receive karne ke liye internal process memory buffer reserve karta hai.
3. Attacker body bytes ko extremely slow rate par stream karta hai (e.g., **1 byte every 30–60 seconds**):
    
    ```
    a=1... (wait 40s) ...&b=2... (wait 40s) ...
    ```
    
4. Server process buffers open rakhta hai jab tak incoming data finish na ho, consuming all available file descriptors and application threads.

---

## **4. Assessment Tooling Ecosystem & Practical Stress Testing**

NOTE

All commands listed below are structured strictly for **Authorized Penetration Testing**, **Firewall Stress Auditing**, and **Lab Resilience Verification**.

+───────────────────+─────────────────────────────────────────────────────────────────────────────+

| Tool              | Target Layer & Protocol Mechanics                                           |

+───────────────────+─────────────────────────────────────────────────────────────────────────────+

| Hping3            | L3/L4: Custom TCP/UDP/ICMP raw packet injection, full source-spoofing engine.|

| Slowloris         | L7: Slow header persistence against thread-per-connection web daemons.      |

| GoldenEye / LOIC  | L7: GoldenEye uses Keep-Alive + No-Cache headers; LOIC does basic flooding. |

+───────────────────+─────────────────────────────────────────────────────────────────────────────+

### **4.1 `hping3` Execution Cheatsheet for Network Auditing**

bash

# 1. TCP SYN Flood with Randomized Source IP Addresses (Testing Connection Backlog)

# -S: SYN flag set | -p: Target port | --flood: Line-rate transmission | --rand-source: Spoof IPs

sudo hping3 -c 50000 -d 120 -S -w 64 -p 80 --flood --rand-source 192.168.1.50

# 2. TCP SYN Flood with Spoofed Subnet (Testing Ingress / Route-based Filtering)

sudo hping3 -S -p 443 -a 192.168.1.99 --flood 192.168.1.50

# 3. TCP RST Injection (Testing Active Session Teardown Resiliency)

sudo hping3 -R -p 80 --flood --rand-source 192.168.1.50

# 4. ICMP Ping Stress Test (Testing Interface Queue Dropping Thresholds)

sudo hping3 --icmp --flood --rand-source 192.168.1.50

# 5. UDP Flooding with Specific Payload Length

sudo hping3 --udp -p 53 --flood --rand-source -d 1024 192.168.1.50

### **4.2 Application-Layer Testing: Slowloris Execution**

bash

# Python Slowloris Tool Syntax (Auditing Web Concurrency Limits)

# -s: Number of sustained sockets | -p: Port | -v: Verbose mode

slowloris target-audit.local -p 80 -s 500 --sleeptime 15

---

## **5. Telemetry Acquisition, Kernel Signals & Change-Point Analytics**

Attack ke time server application unresponsive hone se pehle host kernel aur network interfaces alerts generate karte hain.

### **5.1 Host-Level Kernel Counters (`/proc/net/netstat`)**

bash

# Check current socket allocation and TCP connection states

ss -s

# Inspect live SYN flood kernel discard counters

cat /proc/net/netstat | awk -F' ' '{print $1,$2,$8,$9}' | column -t

# Or use netstat interface:

netstat -s | grep -i listen

|Kernel Metric|Host Interface / File|Baseline State|Alert Indicator|Operational Root Cause|
|---|---|---|---|---|
|**`SYN_RECV` Sockets**|`ss -n state syn-recv`|< 5% of active sockets|> 50% of socket allocations|Active TCP SYN flood targeting local ports; connection queue saturation.|
|**`SyncookiesSent`**|`/proc/net/netstat`|0|Rapid positive increment|Backlog table completely full (`somaxconn` exceeded); kernel fell back to stateless SYN cookies.|
|**`SyncookiesFailed`**|`/proc/net/netstat`|0|Sustained elevation|Invalid final ACK packets ya forged acknowledgments attempting to bypass cookie verification.|
|**`TcpExtListenOverflows`**|`/proc/net/netstat`|0|Sustained elevation|Operating system accept queue full; legitimate incoming connections are actively dropped!|
|**`TcpExtListenDrops`**|`/proc/net/netstat`|0|Any positive increment|Packets dropped due to memory limits, buffer starvation, or unhandled socket queues.|

---

### **5.2 Mathematical Signal Processing: Cumulative Sum (CUSUM) Algorithm**

Static threshold alert systems slow-and-low attacks miss kar dete hain. **CUSUM (Cumulative Sum)** sequential change-point algorithm statistical deviations ko accumulate karta hai:

Sn=max⁡(0,Sn−1+(Xn−μ0−k))S_n = \max\left(0, S_{n-1} + (X_n - \mu_0 - k)\right)Sn​=max(0,Sn−1​+(Xn​−μ0​−k))

- XnX_nXn​: Observed packet arrival rate at interval nnn.
- μ0\mu_0μ0​: Historical baseline mean packet rate.
- kkk: Acceptable slack/drift factor.
- SnS_nSn​: Cumulative sum counter. Jab Sn≥hS_n \ge hSn​≥h (threshold alert limit), tab automated mitigation activate hoti hai!

Traffic Rate

     │

     │                                            * ALERT TRIGGERED (Sn >= h) *

     │                                           ▲

     │                                   ▲      /

     │                            ▲     /

     │                     ▲     /

Baseline (μ0) ───────▲────/

     │              /

     └─────────────┴────────────────────────────► Time (Intervals)

                   Attack Begins (Subtle Ramp-up Detected via CUSUM!)

---

## **6. Stateless Protocol Defense: RFC 4987 SYN Cookies**

Jab standard socket backlog table saturate ho jati hai, standard OS naye connections drop karna shuru kar deta hai. **RFC 4987 SYN Cookies** kernel ko **stateless mode** me operate karne ki permission dete hain: **Server initial SYN receive hone par TCB memory me bilkul allocate nahi karta!**

Server connection state ko 32-bit TCP Initial Sequence Number (ISN) ke andar cryptographically encode karke `SYN-ACK` reply bhejta hai.

       32-Bit Server Initial Sequence Number (ISN) Bit Allocation:

       +───────────────────────────────────+───────────+───────────────────────+

       |       Bits 31 .. 27 (5 Bits)      | 26 .. 24  | 23 .. 0 (24 Bits)     |

       |───────────────────────────────────|───────────|───────────────────────|

       |          Timestamp Window         |  MSS Table|   Cryptographic Hash  |

       |  (Cyclic 64-second counter)       |   Index   |  HMAC-K(Src,Dst,Ports)|

       +───────────────────────────────────+───────────+───────────────────────+

### **6.1 Handshake Verification Logic**

1. **Outgoing SYN-ACK:** Server client ko sequence number bhejta hai: ISNserver\text{ISN}_{\text{server}}ISNserver​. Memory usage: **0 Bytes**.
2. **Incoming Final ACK:** Legitimate client jab ACK bhejta hai, uska Acknowledgment number hota hai: Ack=ISNserver+1\text{Ack} = \text{ISN}_{\text{server}} + 1Ack=ISNserver​+1.
3. **Stateless Recomputation:**
    - Server receives ACK, subtracts 1: ISN=Ack−1\text{ISN} = \text{Ack} - 1ISN=Ack−1.
    - Recalculates cryptographic hash using local secret key KKK and connection 4-tuple (`SrcIP`, `DstIP`, `SrcPort`, `DstPort`).
    - Verifies timestamp freshness.
    - Agar hash match hota hai, **sirf tab** kernel memory allocate karta hai aur socket transition `ESTABLISHED` ho jata hai!

### **6.2 Linux Kernel Hardening (`/etc/sysctl.conf`)**

Production Linux servers ko TCP exhaustion attacks se protect karne ke liye configurations:

ini

# /etc/sysctl.conf - Enterprise TCP/IP Hardening Template

# 1. Enable Cryptographic SYN Cookies (RFC 4987)

net.ipv4.tcp_syncookies = 1

# 2. Increase Half-Open Connection Backlog Table Size (Default is often 128-512)

net.ipv4.tcp_max_syn_backlog = 4096

# 3. Increase Core Maximum Socket System Backlog Limit

net.core.somaxconn = 4096

# 4. Reduce SYN-ACK Retransmissions to drop dead half-open connections faster (Default: 5)

net.ipv4.tcp_synack_retries = 2

# 5. Reduce SYN Retransmissions for outgoing handshakes

net.ipv4.tcp_syn_retries = 2

# 6. Enable TCP Timestamps (Required for SYN Cookies to negotiate TCP Window Scaling & SACK)

net.ipv4.tcp_timestamps = 1

bash

# Apply sysctl parameters immediately without reboot

sudo sysctl -p

---

## **7. Edge Anti-Spoofing & Traffic Scrubbing Mechanics**

### **7.1 BCP 38 (RFC 2827) Ingress Filtering**

**Best Current Practice 38** mandates that network providers verify that packets entering the internet carry valid source IP addresses belonging to the customer's allocated CIDR block. Jo packets unassigned ya forged IP use karte hain, unhe edge border router par hi drop kiya jata hai.

### **7.2 Unicast Reverse Path Forwarding (uRPF)**

Routers apne hardware **Forwarding Information Base (FIB)** ka use karke source IP address authenticity check karte hain:

[ Incoming Packet ] ──▶ Look up Source IP in FIB Routing Table

                                │

       ┌────────────────────────┴────────────────────────┐

       ▼                                                 ▼

[ uRPF Strict Mode ]                            [ uRPF Loose Mode ]

- Check 1: Does a valid route exist?            - Check 1: Does a valid route exist?

- Check 2: Did it arrive on the exact           - (Does NOT care which interface received it)

           interface used to reach that IP?     - Purpose: Stops unroutable bogons while

- Purpose: Zero tolerance for spoofing.                   tolerating Asymmetric Routing!

- Limitation: Drops asymmetric routing!

#### **Cisco IOS uRPF Configuration:**

cisco

! Configure Strict Mode uRPF on Enterprise Edge Interface

interface GigabitEthernet0/1

 description Inbound Internet Link

 ip verify unicast source reachable-via rx

 exit

! Configure Loose Mode uRPF (For Multi-homed Asymmetric Links)

interface GigabitEthernet0/2

 description Multi-Homed Upstream Transit

 ip verify unicast source reachable-via any

 exit

---

### **7.3 Cisco TCP Intercept Architecture**

Cisco edge routers par TCP connection starvation prevent karne ke do operational modes hote hain:

                    +─────────────────────────────────────────+

                    |        Cisco TCP Intercept Engine       |

                    +─────────────────────────────────────────+

                                         │

            ┌────────────────────────────┴────────────────────────────┐

            ▼                                                         ▼

   [ Intercept Mode (Active) ]                               [ Watch Mode (Passive) ]

   - Router intercepts incoming SYN.                         - Permits SYN to pass directly to server.

   - Router completes 3-way handshake with client.           - Tracks connection state in local table.

   - Only forwards valid connection to real server!          - If no ACK in 30s, router injects TCP RST

   - Incomplete spoofed SYNs NEVER touch the server!           to clear server backlog automatically!

#### **Cisco IOS Configuration Commands:**

cisco

! Define Access List identifying servers to protect

ip access-list extended ACL-PROTECT-HTTP

 permit tcp any host 192.168.1.50 eq 80

 permit tcp any host 192.168.1.50 eq 443

 exit

! Enable TCP Intercept in Active Intercept Mode

ip tcp intercept list ACL-PROTECT-HTTP

ip tcp intercept mode intercept

! Set Aggressive Connection Thresholds (Switches to fast-purge mode under attack)

ip tcp intercept max-incomplete low 900 high 1100

ip tcp intercept one-minute low 800 high 1000

ip tcp intercept connection-timeout 3600

ip tcp intercept watch-timeout 15

---

## **8. Upstream Cloud Scrubbing & Routing Diversion**

Jab volumetric attack local physical link capacity (e.g., 10 Gbps flood over a 1 Gbps fiber link) ko exceed kar jata hai, tab on-premise appliances useless ho jati hain. Mitigation **Upstream ISP / Cloud Provider** network me execute karni padti hai.

Attacker Botnet (Multi-Terabit Wave) ─────────▶ [ ISP Upstream Core ]

                                                        │

                      ┌─────────────────────────────────┴─────────────────────────────────┐

                      ▼                                                                   ▼

       [ Remotely Triggered Black Hole ]                                  [ BGP Anycast Cloud Scrubbing ]

       - BGP /32 advertised with community 65535:666                      - BGP announces same IP prefix from 300+ PoPs!

       - Next-Hop set to 192.0.2.1 -> Discards at Null0!                  - Attack traffic split geographically across world!

       - Transit pipe SAVED; Victim service offline.                      - Dirty traffic cleaned; Clean traffic forwarded.

### **8.1 Remotely Triggered Black Hole (RTBH) Routing**

1. **Destination RTBH:** Edge router par jab link congestion detect hoti hai, router internal BGP (iBGP) ke through attack target ka host address (`/32`) announce karta hai with community `65535:666`. Upstream ISP routers is prefix ka next-hop unroutable `Null0` interface par point kar dete hain. Traffic ISP edge par discard ho jata hai, saving other network services from saturation.
2. **Source RTBH:** Known attacking bot IP addresses ko BGP ke through upstream announce kiya jata hai to drop specific hostile traffic sources without taking down the victim host.

---

## **9. Blue Team Intrusion Detection Rules (Snort / Suricata)**

Network taps aur border sensors par anomalous floods identify karne ke liye high-performance IDS rules:

snort

# 1. Detect Inbound TCP SYN Flood Attack (High Rate of SYN Packets Without Handshake)

alert tcp any any -> $HOME_NET any (msg:"DOS-ATTACK Inbound Potential TCP SYN Flood Detected"; flags:S; threshold:type threshold, track by_dst, count 200, seconds 1; classtype:denial-of-service; sid:3001001; rev:1;)

# 2. Detect NTP Monlist Amplification Traffic (UDP Port 123 Diagnostic Response Abuse)

alert udp any 123 -> $HOME_NET any (msg:"DOS-ATTACK NTP Monlist Inbound Amplification Stream"; content:"|17 00 03 2a|"; depth:4; threshold:type both, track by_dst, count 50, seconds 2; classtype:attempted-dos; sid:3001002; rev:1;)

# 3. Detect Slowloris Incomplete Header Streams (Repeated Slow Header Probes)

alert tcp any any -> $HTTP_SERVERS 80 (msg:"DOS-ATTACK Slowloris Suspicious Persistent Connection"; flow:to_server,established; content:"X-"; depth:2; threshold:type both, track by_src, count 25, seconds 5; classtype:denial-of-service; sid:3001003; rev:1;)

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
|**10**|**Denial-of-Service (DoS / DDoS)**|**COMPLETED**|
|**11**|Session Hijacking & Token Manipulation|⏳ _Next in Queue_|
|**12**|Evading IDS, Firewalls, and Honeypots|⏳ _Pending_|
|**13**|Hacking Web Servers|⏳ _Pending_|
|**14**|Hacking Web Applications|⏳ _Pending_|
|**15**|SQL Injection|⏳ _Pending_|
|**16**|Hacking Wireless Networks|⏳ _Pending_|
|**17**|Hacking Mobile Platforms|⏳ _Pending_|
|**18**|IoT & OT Hacking|⏳ _Pending_|
|**19**|Cloud Computing Security|⏳ _Pending_|
|**20**|Cryptography & PKI|⏳ _Pending_|