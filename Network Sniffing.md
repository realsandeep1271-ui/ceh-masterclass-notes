# **Module 08: Network Sniffing & Deep Wire Forensics**

### **Practical Masterclass & Red/Blue Team Field Manual**

---

## **Master Architecture & Roadmap**

+--------------------------------------------------------------------------------------------------+

|                                    MODULE 08 EXECUTION ROADMAP                                   |

+--------------------------------------------------------------------------------------------------+

|  [01] Packet Capture Internals    --> Linux Kernel, PF_PACKET, NAPI, Promiscuous Driver IOCTL   |

|  [02] tcpdump Engine & BPF        --> Advanced Flags, Bitmask Math, Raw Byte Offsets            |

|  [03] Wireshark & tshark Forensics--> TCP 3-Way Handshake State, TLS 1.3 Streams, CLI Extraction|

|  [04] Layer 2 Attack Mechanics    --> CAM Flooding, ARP Poisoning, Rogue DHCP DORA Hijack        |

|  [05] Hardware Taps & Physical L1 --> Copper LAN Taps, 70/30 Fiber Splitters, Bypass Relays     |

|  [06] PCAP vs PCAPNG Forensics    --> SHB, IDB, EPB, DSB (TLS Key Embedding), NRB Internals     |

|  [07] Sniffer Detection Mechanics --> NDIS Bugs, Bogus MAC ICMP Probes, PTR Leaks, Latency Shifts|

|  [08] Python Scapy Engineering   --> Packet Parsing, Live ARP Poison Detector, OS Fingerprint   |

|  [09] Blue Team Hardening Matrix  --> Cisco Port-Security, DHCP Snooping, DAI, IPSG, Snort Rules|

+--------------------------------------------------------------------------------------------------+

---

## **1. Packet Capture Mechanics & Low-Level Linux Internals**

### **1.1 The Linux Kernel Packet Path**

Standard network communication works via the OS network stack where the Network Interface Card (NIC) filters frames matching its own MAC address, broadcast (`FF:FF:FF:FF:FF:FF`), or registered multicast addresses. Unmatched frames are dropped at the hardware ASIC/PHY layer before ever reaching CPU/RAM.

       [ Wire / Ethernet Frame ]

                  │

                  ▼

       [ NIC Hardware / PHY ]

       (Hardware MAC Filter)

                  │

        Passes matching frames

        (Or ALL frames if IFF_PROMISC set)

                  │

                  ▼

       [ Ring Buffer (DMA) ]

                  │

                  ▼

       [ Linux Kernel (NAPI Poll) ]

                  │

                  ├───────────────────────────────┐

                  ▼                               ▼

       [ Packet Socket: PF_PACKET ]     [ Normal IP Stack ]

       (Attached BPF Filter Engine)     (netfilter/iptables)

                  │                               │

                  ▼                               ▼

       [ User-space App (tcpdump/pcap) ]   [ TCP/UDP -> Apps ]

### **1.2 Promiscuous Mode vs. Monitor Mode (RFMON)**

- **Promiscuous Mode (Wired / Ethernet):** NIC ko instruct karta hai ki hardware address filter disable kar de. Sabhi frames (chahe destination MAC kuch bhi ho) ring buffer aur kernel ko forward hoti hain. Switch par agar port isolated nahi hai ya CAM flooded hai, to host ko traffic dikhta hai.
- **Monitor Mode / RFMON (Wireless / 802.11):** Wireless card ko Access Point ke sath associate hue bina raw 802.11 beacon, probe, request, aur data frames capture karne deta hai (including 802.11 radio headers).

### **1.3 C Socket Implementation: Low-Level Sniffer Engine**

Linux me raw packet sniffing ke liye `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` use hota hai. Promiscuous mode set karne ke liye `ioctl` call ke through `SIOCSIFFLAGS` par `IFF_PROMISC` flag apply kiya jata hai:

c

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <net/if.h>

#include <netinet/in.h>

#include <linux/if_packet.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

int main(int argc, char *argv[]) {

    if (argc < 2) {

        printf("Usage: %s <interface_name>\n", argv[0]);

        return 1;

    }

    const char *iface = argv[1];

    // 1. Create Raw Packet Socket (Captures all L2 Ethernet frames)

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0) {

        perror("Socket creation failed");

        return 1;

    }

    // 2. Put Interface into Promiscuous Mode via ioctl

    struct ifreq ifr;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock_raw, SIOCGIFFLAGS, &ifr) < 0) {

        perror("Failed to retrieve interface flags");

        close(sock_raw);

        return 1;

    }

    ifr.ifr_flags |= IFF_PROMISC; // Set promiscuous bit

    if (ioctl(sock_raw, SIOCSIFFLAGS, &ifr) < 0) {

        perror("Failed to set IFF_PROMISC");

        close(sock_raw);

        return 1;

    }

    printf("[+] Interface %s set to PROMISCUOUS mode successfully.\n", iface);

    // 3. Receive Loop

    unsigned char buffer[65536];

    while (1) {

        ssize_t data_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);

        if (data_size < 0) {

            perror("Recvfrom error");

            break;

        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        printf("\n[Captured Frame] Length: %zd bytes\n", data_size);

        printf("  Source MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n",

               eth->h_source[0], eth->h_source[1], eth->h_source[2],

               eth->h_source[3], eth->h_source[4], eth->h_source[5]);

        printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",

               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],

               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

        printf("  EtherType      : 0x%04X\n", ntohs(eth->h_proto));

    }

    close(sock_raw);

    return 0;

}

---

## **2. `tcpdump` Swiss-Army Knife & BPF Architecture**

### **2.1 Essential Production CLI Flags**

| Flag          | Parameter / Value | Meaning & Performance Impact                                                                                           |
| ------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `-i`          | `eth0` / `any`    | Interface bind karta hai (`any` use karne par OS cooked mode `LINUX_SLL` use hota hai, L2 MACs strip ho jate hain).    |
| `-nn`         | N/A               | **Crucial:** IP aur Port numbers ko DNS/service names me resolve hone se rokta hai. Packet dropping prevent karta hai. |
| `-s`          | `0` (or `65535`)  | Snaplen set karta hai. `0` full frame capture karta hai without truncation.                                            |
| `-v` / `-vvv` | N/A               | Verbosity level badhata hai (IP ID, TTL, TOS, Options display karta hai).                                              |
| `-w`          | `trace.pcap`      | Raw packets direct disk me binary format me stream karta hai (bypasses terminal rendering overhead).                   |
| `-C`          | `<size_in_MB>`    | File size limit define karta hai. Hit hone par naya file banata hai (Rotating buffers).                                |
| `-W`          | `<file_count>`    | Ring buffer slot count set karta hai (e.g., `-C 100 -W 10` = max 1 GB disk space).                                     |
| `-G`          | `<seconds>`       | Time-based rotation (e.g., `-G 3600` = har ghante naya capture file).                                                  |
| `-e`          | N/A               | L2 Ethernet headers (Source MAC, Dest MAC, 802.1Q VLAN IDs) print karta hai.                                           |
| `-XX`         | N/A               | Hex aur ASCII me complete packet payload dump karta hai including                                                      |
|               |                   |                                                                                                                        |
### **2.2 `tcpdump` Parameter Table (Completion)**

|Flag|Parameter / Value|Meaning & Performance Impact|
|---|---|---|
|`-i`|`eth0` / `any`|Interface bind karta hai (`any` use karne par OS cooked mode `LINUX_SLL` use hota hai, L2 MACs strip ho jate hain).|
|`-nn`|N/A|**Crucial:** IP aur Port numbers ko DNS/service names me resolve hone se rokta hai (packet loss prevent karta hai).|
|`-s`|`0` (or `65535`)|Snaplen set karta hai. `0` full frame capture karta hai without truncation.|
|`-v` / `-vvv`|N/A|Verbosity level badhata hai (IP ID, TTL, TOS, Options display karta hai).|
|`-w`|`capture.pcap`|Binary PCAP format me direct file me write karta hai (terminal display overhead zero).|
|`-C`|`<size_in_MB>`|File size limit define karta hai. Hit hone par naya file banata hai (Rotating buffers).|
|`-W`|`<file_count>`|Ring buffer slot count set karta hai (e.g., `-C 100 -W 10` = max 1 GB disk space).|
|`-G`|`<seconds>`|Time-based rotation (e.g., `-G 3600` = har ghante naya capture file).|
|`-e`|N/A|L2 Ethernet headers (Source MAC, Dest MAC, 802.1Q VLAN IDs) print karta hai.|
|`-XX`|N/A|Hex aur ASCII me packet data display karta hai including Ethernet L2 headers.|
|`-A`|N/A|Packet data ko pure ASCII text me print karta hai (HTTP GET/POST, cleartext passwords dekhne ke liye).|
|`-r`|`file.pcap`|Saved PCAP capture file ko offline read aur inspect karta hai.|
|`-q`|N/A|Quiet mode: Output ko minimal rakhta hai (Protocol, source, destination, port details only).|
|`-l`|N/A|Line-buffered mode: Output ko line-by-line flush karta hai (grep/awk piping ke liye mandatory).|

---

### **2.3 Berkeley Packet Filter (BPF) Engine & Bitmask Math**

BPF Linux kernel space me run hota hai, jisse un-matched packets user space me transfer hone se pehle hi drop ho jate hain. BPF CPU registers par raw byte offset manipulation perform karta hai.

       Ethernet Header (14B)            IPv4 Header (20B min)           TCP Header (20B min)

+───────────────────────────────+───────────────────────────────+───────────────────────────────+

| [0..5] Dest MAC               | [0] Version & IHL             | [0..1] Source Port            |

| [6..11] Src MAC               | [1] DSCP / ECN                | [2..3] Destination Port       |

| [12..13] EtherType            | [2..3] Total Length           | [4..7] Sequence Number        |

|                               | [4..5] Identification         | [8..11] Acknowledgment Number |

|  * 0x0800 = IPv4              | [6..7] Flags & Fragment Off   | [12] Data Offset (Header Len) |

|  * 0x0806 = ARP               | [8] Time to Live (TTL)        | [13] TCP Control Flags (8-bit)|

|  * 0x86DD = IPv6              | [9] Protocol (6=TCP, 17=UDP)  | [14..15] Window Size          |

|                               | [10..11] Header Checksum      | [16..17] Checksum             |

|                               | [12..15] Source IP            | [18..19] Urgent Pointer       |

|                               | [16..19] Destination IP       |                               |

+───────────────────────────────+───────────────────────────────+───────────────────────────────+

                                                                             │

                                              ┌──────────────────────────────┴───────────────┐

                                              │ Bit 7: CWR | Bit 6: ECE | Bit 5: URG         │

                                              │ Bit 4: ACK | Bit 3: PSH | Bit 2: RST         │

                                              │ Bit 1: SYN | Bit 0: FIN                      │

                                              └──────────────────────────────────────────────┘

#### **TCP Flags Bitmask Cheatsheet:**

- **FIN:** `0x01` (Bit 0)
- **SYN:** `0x02` (Bit 1)
- **RST:** `0x04` (Bit 2)
- **PSH:** `0x08` (Bit 3)
- **ACK:** `0x10` (Bit 4)
- **URG:** `0x20` (Bit 5)

#### **High-Value BPF Filter Commands:**

bash

# 1. Capture SYN-only packets (Initial Connection Requests / SYN Scans)

# tcp[13] is the TCP flags byte. (tcp[13] & 0x02 != 0) AND (tcp[13] & 0x10 == 0)

tcpdump -nn -i eth0 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'

# 2. Capture TCP Reset (RST) Packets (Connection teardowns / Port closed responses)

tcpdump -nn -i eth0 'tcp[tcpflags] & (tcp-rst) != 0'

# 3. Capture TCP SYN-ACK Responses (Successful handshake reply from server)

tcpdump -nn -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# 4. Filter by TTL (Detecting Traceroutes or Hop manipulation)

# ip[8] is the TTL field byte in IPv4 Header

tcpdump -nn -i eth0 'ip[8] < 5'

# 5. Filter Jumbo Frames / Oversized Packets (MTU > 1500 bytes)

# ip[2:2] reads 2 bytes starting at offset 2 (Total Length field)

tcpdump -nn -i eth0 'ip[2:2] > 1500'

# 6. Filter Specific ICMP Types (ICMP Echo Request: Type 8; icmp[0] == 8)

tcpdump -nn -i eth0 'icmp[0] == 8'

# 7. Enterprise Production 24/7 Rolling Capture (100MB files, 20 rotations)

tcpdump -nn -i eth0 -s 0 -C 100 -W 20 -w /var/log/traffic_analysis.pcap

---

## **3. Wireshark & `tshark` Deep Protocol Forensics**

### **3.1 Dissecting the TCP 3-Way Handshake & Connection States**

Client (192.168.1.50:49152)                     Server (192.168.1.10:443)

            │                                                │

            │─── [1] TCP SYN (Seq=0, Len=0, MSS=1460, WS=64) ───▶ State: SYN_SENT

            │                                                │

            │◀── [2] TCP SYN-ACK (Seq=0, Ack=1, MSS=1460) ───│ State: SYN_RECEIVED

            │                                                │

State: ESTAB │─── [3] TCP ACK (Seq=1, Ack=1, Len=0) ───────────▶ State: ESTABLISHED

#### **Wire Anomalies to Detect:**

1. **TCP Retransmissions / Fast Retransmissions:** Network packet loss ya duplex mismatch indicate karta hai.
2. **TCP ZeroWindow:** Receiving host ka OS socket buffer full ho chuka hai; application layer hang ho rahi hai.
3. **TCP Reset (RST) with sequence jump:** Active connection termination ya inline Firewall/IDS (e.g., Palo Alto / Fortinet) TCP reset injection.

### **3.2 TLS 1.2 vs TLS 1.3 Handshake Inspection**

- **TLS 1.2:** 2-RTT Handshake. ClientHello aur ServerHello cleartext hote hain. Server Certificate, Cipher Suites aur Key Exchange parameters (`ServerKeyExchange`) wire par unencrypted pass hote hain.
- **TLS 1.3:** 1-RTT Handshake. ClientHello ke andar hi Diffie-Hellman key share bhej diya jata hai (`key_share` extension). Server Certificate aur Server Extensions completely encrypted hote hain. Cleartext me sirf **SNI (Server Name Indication)** dikhta hai.

### **3.3 `tshark` Command-Line Forensics & Automated Extraction**

GUI ke bina automated scripts me analysis ke liye `tshark` use hota hai:

bash

# 1. Extract All HTTP Hostnames and Request URIs

tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# 2. Extract TLS Server Name Indication (SNI) - Domains accessed over HTTPS

tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# 3. Decrypt TLS 1.3 Traffic using Pre-Master Secret Keylog File

# (Client ne SSLKEYLOGFILE=/tmp/keys.log set karke run kiya ho)

tshark -r capture.pcap -o "tls.keylog_file:/tmp/keys.log" -Y "http2 || http" -T fields -e ip.src -e http2.header.value

# 4. Detect DNS Tunneling / Exfiltration (High length subdomains)

tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name | awk '{ if (length($2) > 40) print $0 }'

---

## **4. Layer 2 Protocol Mechanics & Security Auditing**

### **4.1 Switch CAM (Content Addressable Memory) Table Mechanics**

Switch apne L2 forwarding decision ke liye CAM table maintain karta hai: `[MAC Address <--> Physical Port <--> VLAN]`.

                    +─────────────────────────────────+

                    |       Switch CAM Table          |

                    |─────────────────────────────────|

                    | Port Fa0/1 <--> 00:0C:29:AA:BB:CC|

                    | Port Fa0/2 <--> 00:0C:29:11:22:33|

                    +─────────────────────────────────+

                                     │

      [ CAM Table Exhaustion (Thousands of Random MACs Generated) ]

                                     ▼

                    +─────────────────────────────────+

                    | CAM Table Full (Memory Exhaust) |

                    | Action: "Fail-Open" / Fallback   |

                    | Packets Flooded to ALL Ports    |

                    +─────────────────────────────────+

- **CAM Flooding Test:** Network stress-testing tool `macof` (dnet suite) random MAC aur IP addresses generate karke switch memory saturate karta hai. Jab table full ho jati hai, switch "Hub Mode" (Fail-Open) me fallback ho jata hai aur unmapped unicast packets sabhi ports par broadcast kar deta hai.

bash

# Security Audit Command (Authorized Lab Environment Only)

macof -i eth0 -n 10000

### **4.2 ARP Protocol Mechanics & Cache Verification**

ARP protocol stateless hota hai aur request/reply verify nahi karta:

1. Target machine ko gratuitous ARP bhej kar bataya jata hai ki Gateway ka IP ab testing machine ke MAC se associated hai.
2. IP forwarding (`sysctl -w net.ipv4.ip_forward=1`) enable karke traffic inspect kiya jata hai aur transparently forward kiya jata hai.

bash

# Enable IP Forwarding on Linux Gateway/Auditor

sudo sysctl -w net.ipv4.ip_forward=1

# Layer 2 Protocol Audit using Bettercap

bettercap -iface eth0

# Inside bettercap console:

net.probe on

net.show

set arp.spoof.targets 192.168.1.105

set arp.spoof.internal true

arp.spoof on

### **4.3 Rogue DHCP & Starvation Protocol Inspection**

- **DHCP DORA Process:** `Discover` (Broadcast) -> `Offer` (Unicast/Broadcast) -> `Request` (Broadcast) -> `Acknowledge` (Unicast).
- **Starvation Test:** Attacker randomized MAC addresses se DHCP Discover bhej kar pool ke sabhi IP addresses exhaust kar deta hai. Uske baad Rogue DHCP server run karke clients ko custom Default Gateway aur malicious DNS address distribute karta hai.

---

## **5. Hardware Taps & Physical Layer Forensics**

Jab switch par SPAN/RSPAN port mirror configure nahi kiya ja sakta ya network device configuration access restricted hota hai, physical hardware taps use kiye jate hain.

       Host A ───────────────► [ Passive Inline Tap ] ───────────────► Host B

                                      │        │

                                      ▼        ▼

                                  Monitor A  Monitor B

                                   (TX A)     (TX B)

### **5.1 Copper Inline Taps vs. Fiber Optic Taps**

|Tap Type|Physical Mechanism|Split Ratio / Power|Insertion Loss & Link Impact|
|---|---|---|---|
|**Passive Fiber Tap**|Fused Biconical Taper (FBT) ya Planar Lightwave Circuit (PLC) glass splitters.|**70/30** (70% light line par rehti hai, 30% monitor port par divert hoti hai) ya **50/50**.|Insertion loss (1.5 dB se 3.7 dB). Zero power required. Link down nahi hota agar power chali jaye.|
|**Active Copper Tap**|Inline active micro-controller jo electrical signals replicate karta hai.|Requires External DC Power.|Power loss par **Bypass Relays** activate hote hain jo mechanical relay click karke copper line restore karte hain (100ms link drop).|
|**Throwing Star LAN Tap**|Passive copper capacitive tap (Tx/Rx pairs split).|100% Passive (No external power).|**Gigabit Constraint:** 1000BASE-T (Gigabit) par kaam nahi karta kyunki Gigabit me sabhi 4 pairs bidirectional signaling aur echo cancellation use karte hain. Link ko 100BASE-TX (100 Mbps) par downgrade hona padta hai.|

---

## **6. Capture File Forensics: PCAP vs. PCAPNG**

### **6.1 Traditional PCAP Format (Libpcap)**

- **Global Header (24 Bytes):** Magic Number (`0xa1b2c3d4` for microsecond resolution, `0xa1b23c4d` for nanosecond resolution), Version (2.4), Snaplen, Data Link Type (e.g., Ethernet = 1).
- **Packet Header (16 Bytes):** Timestamp seconds, Timestamp microseconds, Captured Packet Length, Original Packet Length.
- **Limitations:** Sirf ek interface capture kar sakta hai, koi hardware/OS metadata nahi, and packet comments ya decryption keys natively embed nahi ho sakti.

### **6.2 PCAP Next Generation (PCAPNG) Architecture**

PCAPNG modular **Block Structure** use karta hai:

+───────────────────────────────────────────────────────────────────────────+

|               Section Header Block (SHB) [Type: 0x0A0D0D0A]               |

|            Byte-order Magic, OS, Hardware, User Application ID            |

+───────────────────────────────────────────────────────────────────────────+

                                      │

                                      ▼

+───────────────────────────────────────────────────────────────────────────+

|            Interface Description Block (IDB) [Type: 0x00000001]           |

|            Interface Name (eth0), LinkType, Speed, IPv4/IPv6, MTU         |

+───────────────────────────────────────────────────────────────────────────+

                                      │

                                      ▼

+───────────────────────────────────────────────────────────────────────────+

|              Enhanced Packet Block (EPB) [Type: 0x00000006]               |

|            Timestamp (64-bit ns), Captured Len, Packet Data, Hashes       |

+───────────────────────────────────────────────────────────────────────────+

                                      │

                                      ▼

+───────────────────────────────────────────────────────────────────────────+

|           Decryption Secrets Block (DSB) [Type: 0x0000000A]               |

|     Embeds TLS Session Secrets (SSLKEYLOGFILE) directly inside capture!   |

+───────────────────────────────────────────────────────────────────────────+

                                      │

                                      ▼

+───────────────────────────────────────────────────────────────────────────+

|              Name Resolution Block (NRB) [Type: 0x00000004]               |

|            Resolved IPv4/IPv6 to DNS Hostname Mappings Table              |

+───────────────────────────────────────────────────────────────────────────+

> **Key Forensics Insight:** PCAPNG ka **DSB (Decryption Secrets Block)** sabse powerful feature hai. DFIR investigators Wireshark capture file ke andar hi TLS keys bind kar dete hain, jisse investigation team ko alag se secret key files share nahi karni padti.

---

## **7. Promiscuous Mode & Sniffer Detection Mechanics**

Network par agar koi node silently sniffer / promiscuous mode me operate kar raha hai, to usko detect karne ke 4 main methods hote hain:

[ Auditor / IDS ] ─────────────────────────────────────────────► [ Target Host ]

                 Probe: ICMP Echo Request

                 * Dest IP  : 192.168.1.50 (Target IP)

                 * Dest MAC : 00:00:00:00:00:01 (Fake / Bogus MAC)

                                                                        │

                                   ┌────────────────────────────────────┴───────────────────────────┐

                                   ▼                                                                 ▼

                         [ Normal Host (Non-Promisc) ]                                     [ Promiscuous Sniffer ]

                         NIC Hardware drops frame.                                         NIC Hardware filter OFF.

                         Kernel never sees it.                                             Frame passed to OS Kernel.

                         RESULT: [ SILENCE ]                                               Kernel sees Dest IP == My IP.

                                                                                           Sends ICMP Echo Reply!

                                                                                           RESULT: [ EXPOSED! ]

### **7.1 Bogus MAC Address ICMP / ARP Probe**

1. **NIC Address Filtering:** Ek standard NIC hardware layer par check karta hai: `Dest MAC == My MAC` ya `Dest MAC == Broadcast`. Agar match nahi hota, packet immediately drop ho jata hai.
2. **Promiscuous Mode State:** NIC hardware filter bypass ho jata hai. Frame OS network stack (Kernel) tak pahunchti hai.
3. **Kernel Verification:** Kernel sirf Layer 3 (IP Header) verify karta hai: `Dest IP == My IP`. Agar IP match hoti hai, to OS ICMP Echo Reply send kar deta hai — jisse confirm ho jata hai ki target machine promiscuous mode me hai.

### **7.2 Detection Tooling & Commands**

bash

# Nmap Sniffer Detection NSE Script

# Tests multiple OS-specific broadcast bitmask implementation bugs

sudo nmap -sP --script sniffer-detect 192.168.1.0/24

# Passive Decoy DNS Leak Test:

# Agar attacker sniffer me auto-name-resolution enable rakhta hai, to

# fake internal hosts ko traffic bhejne par attacker ka host instantly

# un IP addresses ke liye reverse DNS (PTR query) trigger karega.

---

## **8. Python Network Forensics Suite with Scapy**

Scapy packet generation, decoding, sniffing aur security auditing ke liye standard framework hai.

### **8.1 Custom Real-Time ARP Poisoning & Spoofing Detector**

Niche diya gaya script network par traffic passively sniff karta hai. Agar ek hi IP ke liye do alag MAC addresses claim kiye jate hain, to script instant security alert trigger karta hai:

python

#!/usr/bin/env python3

"""

Enterprise ARP Cache Poisoning Detector

Passively inspects ARP replies and alerts on MAC-IP association anomalies.

"""

from scapy.all import sniff, ARP

import sys

# In-memory IP to MAC mapping table

ip_mac_table = {}

def process_arp_packet(packet):

    # Check if packet is an ARP packet and is an ARP Reply (op=2)

    if packet.haslayer(ARP) and packet[ARP].op == 2:

        source_ip = packet[ARP].psrc

        source_mac = packet[ARP].hwsrc

        # Check if IP already seen in baseline

        if source_ip in ip_mac_table:

            known_mac = ip_mac_table[source_ip]

            if known_mac.lower() != source_mac.lower():

                print(f"\n[!] CRITICAL ALERT: ARP SPOOFING DETECTED!")

                print(f"    Target IP     : {source_ip}")

                print(f"    Legitimate MAC: {known_mac}")

                print(f"    Attacking MAC : {source_mac}")

                print(f"    Action        : Potential MITM In Progress!\n")

        else:

            # Register new baseline host

            ip_mac_table[source_ip] = source_mac

            print(f"[*] Learned Host Baseline: {source_ip} -> {source_mac}")

def main():

    iface = "eth0" if len(sys.argv) < 2 else sys.argv[1]

    print(f"[*] Starting Passive ARP Spoofing Monitor on {iface}...")

    try:

        sniff(iface=iface, filter="arp", prn=process_arp_packet, store=0)

    except KeyboardInterrupt:

        print("\n[*] Monitoring stopped by user.")

if __name__ == "__main__":

    main()

---

## **9. Enterprise Hardening & Blue Team Detection Matrix**

Switch-level L2 attacks ko prevent karne ke liye Cisco IOS aur enterprise switches par specific security configurations apply kiye jate hain:

               [ Client ] ──────────────► [ Cisco Catalyst Switch ] ──────────────► [ DHCP Server ]

                                                  │

       ┌──────────────────────────────────────────┼────────────────────────────────────────┐

       ▼                                          ▼                                        ▼

[ Port Security ]                         [ DHCP Snooping ]                       [ Dynamic ARP Insp. ]

* Limits MACs per port                    * Untrusted ports: Blocks DHCPOFFER     * Validates ARP against

* Drops excess/unknown MACs               * Builds Binding Table                  * DHCP Snooping Table

### **9.1 Cisco IOS Layer 2 Hardening Commands**

cisco

! ==========================================

! 1. PORT SECURITY (Mitigates CAM Flooding)

! ==========================================

interface FastEthernet0/1

 switchport mode access

 switchport port-security

 ! Maximum allowable MAC addresses on this physical port

 switchport port-security maximum 2

 ! Learns valid connected MAC automatically and saves to running-config

 switchport port-security mac-address sticky

 ! Violation action: shutdown port immediately upon unauthorized MAC detection

 switchport port-security violation shutdown

 exit

! ==========================================

! 2. DHCP SNOOPING (Mitigates Rogue DHCP)

! ==========================================

! Globally enable DHCP Snooping

ip dhcp snooping

! Enable DHCP snooping on user VLAN

ip dhcp snooping vlan 10

! Set Uplink port to Authorized DHCP Server as TRUSTED

interface GigabitEthernet0/1

 ip dhcp snooping trust

 exit

! Rate limit DHCP discovery packets on untrusted access ports to prevent starvation

interface FastEthernet0/1

 ip dhcp snooping limit rate 15

 exit

! ==========================================

! 3. DYNAMIC ARP INSPECTION (DAI - Mitigates ARP Spoofing)

! ==========================================

! Inspect ARP packets against DHCP Snooping Binding Table

ip arp inspection vlan 10

! Validate both Source MAC, Destination MAC, and IP inside ARP payload

ip arp inspection validate src-mac dst-mac ip

interface GigabitEthernet0/1

 ip arp inspection trust

 exit

! ==========================================

! 4. IP SOURCE GUARD (IPSG - Prevents IP Spoofing)

! ==========================================

interface FastEthernet0/1

 ip verify source mac-check

 exit

### **9.2 Snort / Suricata Intrusion Detection Signatures**

snort

# Rule 1: Detect Rapid ARP Request Storm (Network Scanning / ARP Sweeps)

alert arp any any -> any any (msg:"ET SCAN Suspicious High-Rate ARP Request Storm"; threshold:type both, track by_src, count 50, seconds 2; sid:2001001; rev:1;)

# Rule 2: Detect Excessive TCP SYN Packets without ACK (SYN Flood / Discovery)

alert tcp any any -> any any (flags:S; msg:"NETWORK ATTACK Inbound TCP SYN Flood Detected"; threshold:type threshold, track by_dst, count 100, seconds 1; sid:2001002; rev:1;)

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
|**08**|**Sniffing & Deep Wire Forensics**|**COMPLETED**|
|**09**|Social Engineering & Phishing Infrastructure|⏳ _Next in Queue_|
|**10**|Denial-of-Service (DoS / DDoS)|⏳ _Pending_|
|**11**|Session Hijacking|⏳ _Pending_|
|**12**|Evading IDS, Firewalls, and Honeypots|⏳ _Pending_|
|**13**|Hacking Web Servers|⏳ _Pending_|
|**14**|Hacking Web Applications|⏳ _Pending_|
|**15**|SQL Injection|⏳ _Pending_|
|**16**|Hacking Wireless Networks|⏳ _Pending_|
|**17**|Hacking Mobile Platforms|⏳ _Pending_|
|**18**|IoT & OT Hacking|⏳ _Pending_|
|**19**|Cloud Computing Security|⏳ _Pending_|
|**20**|Cryptography & PKI|⏳ _Pending_|