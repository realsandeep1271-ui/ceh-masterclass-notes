# **Day 02: Footprinting & Reconnaissance — The Masterclass Notes**

> **Level:** Beginner ➔ Advanced Practical (CEH & Bug Bounty Aligned)  
> **Core Rule:** _"Attacker ko system me ghusne ke liye 1 rasta chahiye, lekin Defender ko har ek rasta pata hona chahiye. Wo rasta hum Recon phase me dhoondhte hain."_

---

## **1. Footprinting, Recon, Scanning & Enumeration me farq kya hai?**

Aksar log in terms me confuse hote hain. Iska clear mental model:

[ FOOTPRINTING ]  ──►  [ SCANNING ]  ──►  [ ENUMERATION ]  ──►  [ EXPLOITATION ]

 (Info Gathering)       (Port/Live IP)      (Deep Probing)        (Attack Phase)

1. **Footprinting (Data Collection):** Target ke bare me maximum information collect karna (Domain, IP blocks, employee emails, tech-stack) bina attack kiye.
2. **Reconnaissance (The Whole Phase):** Ye broader term hai jisme Passive + Active information gathering dono aati hain.
3. **Scanning (Host & Port Discovery):** Live systems, open ports, aur firewalls ki status pata karna (e.g., Nmap).
4. **Enumeration (Resource Deep-Dive):** Specific service ke andar jakar users, shares, tables, banners nikalna (e.g., SMB shares check karna, RPC users nikalna).

---

## **2. Passive vs Active Reconnaissance**

| Dimension             | Passive Reconnaissance                              | Active Reconnaissance                                  |     |
| --------------------- | --------------------------------------------------- | ------------------------------------------------------ | --- |
| **Target se Contact** | ❌ Koi direct connection nahi                        | ✅ Direct packets / traffic target ko bheje jate hain   |     |
| **Detection Risk**    | **Zero (0%)** — Logs me detect nahi hota            | **High** — Firewalls, IDS/IPS, WAFs me IP log hoti hai |     |
| **Legal Risk**        | Legal (Public OSINT data use hota hai)              | Authorization / Scope permission zaroori hai           |     |
| **Data Sources**      | Google, Shodan, WHOIS, DNS Caches, LinkedIn, crt.sh | Nmap, Netcat, Nessus, Gobuster, Live DNS queries       |     |
| **Examples**          | Job postings dekhna, DNSdumpster, Hunter.io         | Port scan (`-p-`), Ping sweep (`-sP`), Banner grabbing |     |

---

## **3. The 5 Core Recon Domains & Practical Techniques**

                         RECONNAISSANCE ARSENAL

                                    │

  ┌───────────────┬─────────────────┼─────────────────┬───────────────┐

  ↓               ↓                 ↓                 ↓               ↓

Search Engines  DNS & Domains     Network & ASN     Web Tech-Stack   People & OSINT

(Google/Shodan) (dig / nslookup) (WHOIS/Traceroute) (Wappalyzer/p0f) (Hunter / Maltego)

---

### **Domain 1: Search Engine Intelligence & Google Dorking (GHDB)**

Search engines internet ka bohot sa sensitive data index kar lete hain jo public nahi hona chahiye tha.

#### **📌 High-Impact Google Dorks Cheatsheet:**

- **Exposed Environment & Password Files:**
    
    text
    
    site:target.com filetype:env "DB_PASSWORD"
    
    site:target.com filetype:sql "dump" | "INSERT INTO"
    
- **Directory Indexing (Open Buckets / Directories):**
    
    text
    
    site:target.com intitle:"index of /" "parent directory"
    
    site:target.com intitle:"index of /" backup | admin | config
    
- **Hidden Login Portals & Dashboards:**
    
    text
    
    site:target.com inurl:admin | inurl:login | inurl:dashboard
    
- **Leaked Documents / Internal Docs:**
    
    text
    
    site:target.com ext:pdf | ext:xlsx | ext:docx "confidential" | "internal use only"
    

#### **🌐 Specialized Search Engines (No Interaction Needed):**

- **Shodan / Censys:** Internet se connected har IP, server, webcam, router aur open port ka scanner.
    - Search: `VNC` ➔ Exposed remote desktop bina password ke.
    - Search: `webcamxp` ➔ Live unsecured surveillance camera streams.
    - Filter: `org:"Target Corp" port:"8080"` ➔ Target ke hidden web portals.
- **FOFA / ZoomEye / GreyNoise:** Internet-wide assets mapping.

---

### **Domain 2: Domain & DNS Footprinting**

DNS records target ki sari public boundary, mail servers aur third-party services ko expose karte hain.

#### **📌 DNS Record Types Summary:**

- **A Record:** Domain ➔ IPv4 Address (Direct Server IP).
- **AAAA Record:** Domain ➔ IPv6 Address (Kai baar IPv6 par firewall bypass ho jata hai).
- **CNAME Record:** Alias domain (Agar third-party AWS S3 / Heroku / Zendesk pe point kare aur wo expire ho jaye ➔ **Subdomain Takeover**).
- **MX Record:** Mail Servers (Pata chalta hai target Proofpoint, Mimecast, ya GSuite use kar raha hai).
- **TXT Record:** SPF, DKIM, DMARC policies. Cloud vendors (AWS SES, Google, MS Office) verify karne ke liye secrets yahan daalte hain.
- **NS Record:** Authoritative Name Servers.

#### **⚡ DNS Zone Transfer (AXFR) — Critical Misconfiguration:**

Agar DNS server misconfigured ho, toh wo pura ka pura internal DNS database ek command me leak kar deta hai:

bash

dig axfr @ns1.target.com target.com

_(Defense: Server me `allow-transfer { none; };` configure hona chahiye)._

#### **🛠️ Subdomain Discovery:**

- **Passive:** Certificate Transparency logs (`crt.sh`), AlienVault OTX, Sublist3r, Assetfinder.
- **Active:** Brute-force using wordlists (`gobuster dns -d target.com -w subdomains.txt` ya `ffuf`).

---

### **Domain 3: Network & ASN Footprinting**

Target ke pure IP ranges aur server ownership ka pata lagana.

- **WHOIS:** Domain registration, expiry, owner name, aur registrar info.
    
    bash
    
    whois target.com
    
- **ASN (Autonomous System Number):** Ek organization ki saari IP address ranges (CIDR blocks):
    
    bash
    
    whois -h whois.radb.net -- '-i origin AS12345'
    
- **Traceroute Analysis:** Target tak pahunchne wale saare routers aur intermediate firewall hops ko track karta hai:
    
    bash
    
    traceroute -T -p 443 target.com
    

---

### **Domain 4: Web Application & Tech-Stack Fingerprinting**

Target kis server (Nginx/Apache), backend (Node/PHP/Java), aur CMS (WordPress/Drupal) par chal raha hai:

- **Banner Grabbing (HTTP Headers):**
    
    bash
    
    curl -I https://target.com
    
    Look for: `Server`, `X-Powered-By`, `Set-Cookie` (jaise `PHPSESSID` = PHP, `JSESSIONID` = Java).
- **Passive OS Fingerprinting (`p0f`):**
    
    bash
    
    p0f -i eth0
    
    - Bina packets send kiye, aane wale traffic ke TCP window size, SYN packet, aur TTL se OS aur uptime bata deta hai:
- **Extensions:** Wappalyzer, BuiltWith (Browser me directly tech-stack dikhata hai).
- **Metadata Extraction (Exiftool / FOCA):**
    
    bash
    
    exiftool annual_report.pdf
    
    - Target ke public PDF/Excel download karke unka author, local computer path, aur software version nikalna:

---

### **Domain 5: People, Social Media & Email OSINT**

Hacking ka sabse kamzor hissa: **Humans**.

- **LinkedIn Recon:** Employee names, job designations (DevOps, Cloud Engineer) dekh kar tech-stack ka pata lagana (e.g., job me manga hai "Kubernetes, AWS, MongoDB" ➔ confirm ho gaya target ye use karta hai).
- **Email Pattern Discovery:**
    - Tools: **Hunter.io**, **Phonebook.cz**, **theHarvester**.
    - Pattern pehchanna: `first.last@company.com` ya `initial.last@company.com`.
- **Credential Leaks:** Dehashed, HaveIBeenPwned se check karna ki purane breaches me target ke employee passwords leak to nahi hue.

---

## **4. Hands-On Practical Commands & Tools Guide**

### **💻 Nmap Mastery (Discovery & Port Scanning)**

#### **1. Host Discovery Scans:**

|Goal|Command|Kyu aur Kaise use karein?|
|---|---|---|
|**Ping Scan (Subnet)**|`nmap -sP 192.168.0.0/24`|ICMP Echo request bhejta hai; live hosts identify karta hai.|
|**No-Port Ping Scan**|`nmap -sn 192.168.0.0/24`|Sirf host up/down batata hai, port scan skip karke speed badhata hai.|
|**ARP Scan (Local Network)**|`nmap -PR 192.168.0.0/24`|Local LAN me firewall bypass karta hai (Firewall ARP block nahi kar sakta).|
|**TCP SYN Ping**|`nmap -sn -PS80 192.168.0.0/24`|Port 80 par SYN bhej kar live hosts dhoondhta hai jab ICMP ping blocked ho.|
|**Traceroute Map**|`nmap --traceroute 192.168.0.0/24`|Host ke live hone ke sath-sath network hops bhi dikhata hai.|

#### **2. Port Scanning Techniques:**

| Goal                    | Command                           | Details                                             |
| ----------------------- | --------------------------------- | --------------------------------------------------- |
| **Single Port**         | `nmap -p 80 192.168.0.2`          | Specific port scan karta hai.                       |
| **Port Range**          | `nmap -p 1-100 192.168.0.1`       | 1 se 100 tak ke ports check karta hai.              |
| **Fast Scan (Top 100)** | `nmap -F 192.168.0.1`             | Sabse popular 100 ports scan karta hai.             |
| **Top N Ports**         | `nmap --top-ports 10 192.168.0.1` | Top 10 most used ports ko scan karta hai.           |
| **All 65,535 Ports**    | `nmap -p- 192.168.0.1`            | Har ek port check karta hai (Slow but thorough).    |
| **TCP Connect Scan**    | `nmap -sT 192.168.0.1`            | Pura 3-way handshake banata hai (No root required). |
| **UDP Port Scan**       | `nmap -sU -p 53,123 192.168.0.1`  | DNS (53), NTP (123) jaise UDP ports scan karta hai. |

#### **3. Understanding Port States in Nmap:**

- **Open:** Service listening hai aur connection accept kar rahi hai.
- **Closed:** Packet receive hua, par koi service port pe chal nahi rahi (RST response mila).
- **Filtered:** Firewall/WAF ne packet block ya drop kar diya; Nmap ko response nahi mila.
- **Unfiltered:** Port accessible hai par open hai ya closed, ye clear nahi (ACK scan me hota hai).

#### **4. OS & Version Detection:**

bash

# Operating System Detection

nmap -O 192.168.0.1

# Aggressive OS Guessing

nmap -O --osscan-guess 192.168.0.1

# Service & Version Detection

nmap -sV 192.168.0.1

# Aggressive Scan (OS + Services + Scripts + Traceroute)

nmap -A 192.168.0.1

---

### **🌐 CLI DNS Querying with `nslookup`**

bash

# Basic Domain to IP resolution

nslookup target.com

# Specific DNS Server se query karna

nslookup target.com 8.8.8.8

# A Record Query (IPv4)

nslookup -type=A target.com

# MX Records (Mail Servers)

nslookup -query=MX target.com

# NS Records (Nameservers)

nslookup -type=ns target.com

# SOA Record (Start of Authority / Admin email)

nslookup -type=soa target.com

# All Available Records (ANY query)

nslookup -query=any target.com

# Debug mode (TTL aur Cache expiration dekhne ke liye)

nslookup -type=A -debug target.com

---

### **🕵️ OSINT Tools Syntax & Walkthrough**

#### **1. theHarvester (CLI OSINT Powerhouse):**

bash

# Google se 500 emails & subdomains collect karna

theHarvester -d target.com -l 500 -b google

# Bing search engine use karke

theHarvester -d target.com -b bing

# Saare sources ek saath scan karna

theHarvester -d target.com -b all

#### **2. Maltego CE (Graph-Based Intelligence):**

- **Use Case:** Complex relationships (Domain ➔ MX ➔ IP ➔ Server Technologies ➔ People) ko visually graph ke form me link karna.
- **Key Transforms in Lab:**
    1. Drag **Domain Entity** ➔ Enter `target.com`.
    2. Right-click ➔ `To DNS Name - MX (mail server)`.
    3. Right-click Domain ➔ `To Website [Quick lookup]`.
    4. Right-click Website ➔ `To IP Address [DNS]`.
    5. Right-click Website ➔ `To Server Technologies [Using BuiltWith]`.
    6. Machine ➔ **Footprint L1/L2** (Full automated graph mapping).

---

## **5. Countermeasures & Defense Blueprint (CEH Exam Must-Know)**

Footprinting ko 100% stop nahi kiya ja sakta, lekin impact minimize kiya ja sakta hai:

1. **DNS Protection:**
    - Secondary nameservers par **AXFR (Zone Transfer)** disable karein (`allow-transfer { none; };`).
    - **Split-Horizon DNS:** Internal IP ranges ke liye alag private DNS aur external ke liye alag public DNS use karein.
    - **DNSSEC** enable karein taaki cache poisoning roki ja sake.
2. **WHOIS Privacy:**
    - Domain registration me Privacy Protection (WhoisGuard) enable karein taaki admin ka personal email aur phone number mask rahe.
3. **Information Disclosure Suppression:**
    - Web servers se banners disable karein (`ServerTokens Prod` in Apache, `expose_php = Off` in PHP).
    - Unnecessary headers remove karein (`X-Powered-By`).
    - Public documents se metadata strip karein.
4. **Search Engine Control:**
    - Robots.txt me sensitive admin paths expose na karein.
    - Non-public staging/dev pages par `X-Robots-Tag: noindex, nofollow` lagayein.
5. **EASM (External Attack Surface Management):**
    - Apni organization ko regular Shodan aur Certificate Transparency logs par monitor karein taaki shadow IT aur bhooli hui test machines pakdi ja sakein.

---

## **6. Hacker's Recon Workflow (Day 2 Action Checklist)**

[ STEP 1: PASSIVE OSINT ]

├── Google Dorks (Configs, Admin Portals, Leaked DBs)

├── Shodan / Censys (Open ports, IoT, exposed dashboards)

├── WHOIS & ASN Lookup (IP Range CIDR Blocks identify karna)

└── theHarvester / Hunter.io (Employee list & email format)

[ STEP 2: DNS & ASSET ENUMERATION ]

├── Subdomain Discovery (crt.sh + Assetfinder + Amass)

├── DNS Records Inspection (A, AAAA, CNAME, MX, TXT)

└── Test for Zone Transfer (dig axfr @ns1.target.com)

[ STEP 3: ACTIVE NETWORK PROBING (Scope Permitted) ]

├── Host Discovery: Ping / ARP scan (nmap -sn / -PR)

├── Port Scanning: Top ports / Full scan (nmap -F ya -p-)

├── Service & OS Fingerprint (nmap -sV -O)

└── Passive Fingerprint via Traffic (p0f)

[ STEP 4: ATTACK SURFACE BLUEPRINT ]

└── Target ka complete map tayyar: Kis IP par kaunsi service, 

    kaunsa version aur kaunse vulnerable endpoints open hain!
