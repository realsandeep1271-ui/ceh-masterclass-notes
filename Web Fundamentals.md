# **🛡️ Day 01: Web Fundamentals for Bug Bounty**

> **Level:** Beginner → Practical Foundation  
> **Core Objective:** Kisi bhi web app ko inspect karna, client-server communication samajhna, aur ye pehchanna ki vulnerabilities kahan paida hoti hain.

---



### **🔑 3 Major Skills Needed**

          ┌───────────────────────────┐

          │     BUG BOUNTY SUCCESS    │

          └─────────────┬─────────────┘

      ┌─────────────────┼─────────────────┐

      ↓                 ↓                 ↓

Technical Skills   Recon Skills     Reporting Skills

(Bugs dhundna)    (Assets khojna)   (Impact explain karna)

---

## **2. The Hacker's Golden Mindset 🧠**

> ❌ **Beginner Mindset:** _"Is parameter me main kaunsa XSS ya SQLi payload daalu?"_  
> ✅ **Pro Hacker Mindset:** _"Ye application internally kaise kaam kar rahi hai, aur iska trust model kahan break hota hai?"_

### **Core Security Principle:**

```
[ Untrusted Input ] ──► [ Application Logic ] ──► [ TRUST BOUNDARY ] ──► [ Output / Execution ]
```

> **Aapka main kaam:** Yeh pata lagana ki **kahan untrusted user input trust boundary ko cross karta hai** bina proper validation ya sanitization ke.

---

## **3. How Websites Work (Architecture & Components)**

Jab browser me URL open hota hai:

┌──────────────┐     HTTP/HTTPS Request     ┌────────────────────────┐      SQL / NoSQL      ┌──────────────┐

│   Browser    │ ────────────────────────►  │   Web Server / App     │  ──────────────────►  │   Database   │

│   (Client)   │ ◄────────────────────────  │ (Node/PHP/Python/Go)   │  ◄──────────────────  │ (MySQL/Mongo)│

└──────────────┘     HTTP/HTTPS Response    └───────────┬────────────┘                       └──────────────┘

                                                        │

                                                        ▼

                                             External Services / APIs

                                             (Stripe, AWS S3, OAuth)

### **Attack Surface by Component:**

1. **Frontend (Client-side):** DOM XSS, Sensitive Data Leaks in JS, HTML Injection, Client-side validation bypass.
2. **API Layer:** Broken Object Level Authorization (BOLA/IDOR), Broken Authentication, Mass Assignment.
3. **Backend Logic:** Business Logic Errors, Race Conditions, Server-Side Request Forgery (SSRF).
4. **Database:** SQL Injection, NoSQL Injection.
5. **Cloud / Infrastructure:** Subdomain takeover, S3 bucket misconfigurations, CORS misconfigurations.

---

## **4. URL Anatomy & Bug Bounty Importance**

Example URL: `https://example.com:443/products?id=10#reviews`

https://       example.com       :443        /products        ?id=10             #reviews

   │                │              │             │               │                  │

Scheme            Host           Port          Path         Query String         Fragment

(Protocol)      (Domain)       (Default)    (Endpoint)    (User Input / Target)  (Client-side)

### **🎯 Bug Bounty Value:**

- **Query Parameters (`?id=10`, `?redirect=...`, `?user=...`)**: Yeh backend database ya logic ko directly input bhejte hain. Bug bounty me 80% input tampering yahi se start hoti hai (SQLi, IDOR, SSRF, XSS).
- **Fragment (`#reviews`)**: Server ko nahi bheja jata; browser handle karta hai. Lekin agar JavaScript isse `location.hash` se padhkar render kare toh **DOM XSS** ho sakta hai.

---

## **5. DNS Fundamentals & Recon Records**

DNS ka kaam humans ke domain names ko machine IP address me convert karna hai.

### **📌 Critical DNS Records for Bug Bounty:**

|Record Type|Purpose|Bug Bounty Relevance|
|---|---|---|
|**A**|Domain ➔ IPv4 address|Origin IP discovery (Cloudflare/WAF bypass)|
|**AAAA**|Domain ➔ IPv6 address|Kabhi-kabhi IPv6 pe WAF rules apply nahi hote|
|**CNAME**|Alias to another domain|**Subdomain Takeover** (Agar third-party service delete ho gayi ho)|
|**MX**|Mail Server|Email spoofing (SPF/DMARC analysis)|
|**TXT**|Text information|Secret keys, verification codes, internal details leak|
|**NS**|Authoritative Nameservers|DNS zone transfer (AXFR misconfigurations)|

### **🌐 Subdomain Attack Surface:**

Subdomains targets ke attack surface ko expand karte hain:

                      target.com

                          │

  ┌───────────────┬───────┴───────┬───────────────┐

  ↓               ↓               ↓               ↓

admin.target.com dev.target.com api.target.com staging.target.com

(Admin Panels)   (Old/Buggy)    (Auth Bypasses)  (Testing Environment)

> **Pro Tip:** Main domain (`target.com`) bohot secure hota hai, lekin `dev`, `staging`, ya `test` subdomains par security checks aksar disabled hote hain.

---

## **6. HTTP Protocol — Methods & Status Codes**

HTTP stateless protocol hai. Har request independent hoti hai.

### **HTTP Methods (Mental Model):**

- **GET** ➔ READ (Data read karna, safe maana jata hai)
- **POST** ➔ CREATE (Naya resource create karna, jaise `/login`, `/register`)
- **PUT** ➔ UPDATE / OVERWRITE (Pura resource update karna)
- **PATCH** ➔ MODIFY (Kuch specific fields update karna)
- **DELETE** ➔ REMOVE (Resource delete karna)
- **OPTIONS** ➔ Enquire (CORS preflight checks, supported methods janna)

### **HTTP Status Codes:**

- **2xx (Success):** `200 OK`, `201 Created`
- **3xx (Redirection):** `301 Moved Permanently`, `302 Found / Temp Redirect` (Open Redirect bugs yahan check hote hain)
- **4xx (Client Error):**
    - `400 Bad Request`
    - `401 Unauthorized` (Authentication missing hai - Login required)
    - `403 Forbidden` (Aap pehchane gaye hain, lekin permission nahi hai)
    - `404 Not Found`
    - `405 Method Not Allowed`
- **5xx (Server Error):** `500 Internal Server Error` (Input handling break hui hai - SQLi/RCE/Logic flaw ka hint!), `503 Service Unavailable`.

### **🔍 Bug Bounty Perspective on `403 Forbidden`:**

Jab aapko `403 Forbidden` mile, toh sirf bypass tool mat chalao, pehle samjho:

1. _Kya ye authentication ki wajah se hai?_ (User token vs Admin token)
2. _Kya HTTP Method badalne se bypass hota hai?_ (`GET /admin` ➔ 403, lekin `POST /admin` ➔ 200)
3. _Kya custom headers exist karte hain?_ (`X-Original-URL`, `X-Forwarded-For: 127.0.0.1`)

---

## **7. HTTP Headers & Cookies**

### **Important Headers:**

- **`Host:`** Target server batata hai. (Check for _Host Header Injection / Password Reset Poisoning_).
- **`User-Agent:`** Browser/client identity. (Check for _Blind SQLi / Blind XSS in admin logs_).
- **`Authorization:`** Bearer token / JWT token (API security).
- **`Referer:`** Kis page se request aayi. (Check for _Token leakage in referer_).
- **`Content-Type:`** Payload format (`application/json`, `application/x-www-form-urlencoded`).

### **Cookies & Security Flags:**

HTTP stateless hai, isliye session maintain karne ke liye cookies use hoti hain.

http

Set-Cookie: session=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/

1. **`Secure`**: Cookie sirf HTTPS (encrypted) connection par hi transfer hogi.
2. **`HttpOnly`**: JavaScript (`document.cookie`) is cookie ko access **nahi** kar sakti. (XSS hone ke baad bhi session token chori nahi ho sakta!).
3. **`SameSite`**:
    - `Strict`: Third-party sites se cookie kabhi nahi jayegi (Best against CSRF).
    - `Lax`: Top-level GET navigation par jayegi.
    - `None`: Har request me jayegi (Needs `Secure`).

---

## **8. Frontend Security & DevTools Mastery**

### **DevTools (`F12`) Tabs for Hackers:**

- **Network Tab:** Real API endpoints, hidden parameters, authentication headers dekhne ke liye sabse important tab.
- **Application Tab:** Cookies, Local Storage (aksar JWT tokens yahan store hote hain), Session Storage.
- **Sources Tab:** Frontend JavaScript files, API routes, hardcoded keys.
- **Console Tab:** DOM-based functions test karne ke liye.
- **Elements Tab:** Rendered live DOM tree inspect karna.

### **Sensitive Data Exposure in Frontend:**

> **Golden Rule:** Jo code client (browser) ke paas aa gaya, wo private nahi hai!

Frontend JS/HTML me hamesha check karein:

- Developer comments: `<!-- TODO: remove test credentials admin:admin123 -->`
- Hardcoded API keys (Firebase keys, Stripe secret keys by mistake, AWS access keys).
- Hidden endpoints/routes: `/api/v1/internal/export-users`.
- Disabled buttons: Frontend pe button `disabled` hota hai, lekin backend endpoint call karne par kaam kar jata hai.

---

## **9. Day 1 Exercises & Scenarios Solved 💡**

### **Practical Exercise (Build the Request)**

- Target: `https://example.com/products?id=10`
    - **Scheme:** `https`
    - **Host:** `example.com`
    - **Path:** `/products`
    - **Query:** `id=10`

### **Scenario 1:**

> **Scenario:** Request: `GET /api/user?id=1001`. Aap login hain as: `User ID: 1000`.  
> **Vulnerability Class:** **IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level Authorization)**.  
> **Investigation:** Agar `id=1001` karne par doosre user ka private data (email, phone, address) mil jata hai bina authorization check ke, toh yeh high-severity IDOR hai.

### **Scenario 2:**

> **Scenario:** Request: `POST /api/profile` with `{"name": "Ali"}`.  
> **Investigation:**
> 
> 1. **Mass Assignment / Parameter Tampering:** Request me extra fields add karke dekhein (jaise `{"name": "Ali", "role": "admin", "is_admin": true}`).
> 2. **Stored XSS:** Name field me XSS payload daal kar dekhein ki profile page par kaise render hota hai.

### **Scenario 3:**

> **Scenario:** HTML me comment mila: `<!-- Temporary admin login -->`.  
> **Action:** Page source me us comment ke aas-paas ke JS functions, hidden links ya forms ko inspect karein; directory brute-forcing me `/admin-login`, `/temp-login`, `/admin_temp` try karein.

---

## **10. Bug Hunter's Daily Checklist (The Sequence)**

Jab bhi naya target mile, is order ko follow karein:

```
MAP ──► UNDERSTAND ──► INTERACT ──► TEST ──► VALIDATE ──► REPORT
```

1. **MAP:** App me kya-kya features hain? (Login, Signup, Profile, Search, Payment, File Upload).
2. **UNDERSTAND:** Requests aur responses ko DevTools / Burp Suite me observe karo.
3. **INTERACT:** Normal user ki tarah features chalao.
4. **TEST:** Parameters change karo, roles change karo (User A vs User B).
5. **VALIDATE:** Confirm karo ki impact genuine hai (not a false positive).
6. **REPORT:** Clear reproduction steps ke sath report likho.