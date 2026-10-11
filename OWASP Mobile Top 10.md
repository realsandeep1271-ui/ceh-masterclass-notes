#  & Penetration Testing Masterclass (Android & iOS)**

### **_OWASP Mobile Top 10 (2024–2026) • Drozer IPC Auditing • iOS Architecture & Modern Escalation Vectors_**

---

## **🏛️ PART 1: OWASP Mobile Top 10 (2024–2026 Enterprise Edition)**

Mobile applications client-side presentation layer aur complex backend microservices ke beech ek gateway hote hain. Modern mobile threats client storage, Inter-Process Communication (IPC), runtime execution, aur transport layer par target karte hain.

       ┌────────────────────────────────────────────────────────┐

       │              Mobile Attack Surface Boundary            │

       └───────────────────────────┬────────────────────────────┘

                                   │

      ┌────────────────────────────┼────────────────────────────┐

      ▼                            ▼                            ▼

[ Client-Side Storage ]    [ IPC / Platform API ]     [ Transport & Network ]

  • SharedPreferences        • Exported Activities      • Cleartext HTTP

  • SQLite Databases         • Broadcast Receivers      • Missing Cert Pinning

  • Keystore / Keychain      • Content Providers        • TLS Downgrade

---

### **M1: Improper Platform Usage**

Platform features (jaise Android Intents, Permissions, iOS Keychain accessibility flags) ko improperly ya bina security control ke implement karna.

- **Real-World Impact:** App components globally broadcast ho jate hain, jisse unprivileged malicious applications device par chalte hue sensitive broadcasted data capture kar lete hain.
- **Vulnerable Pattern (Android Broadcast):**
    
    java
    
    // Broadcasts sensitive data globally to all installed apps on device
    
    Intent intent = new Intent("com.corp.app.LOCATION_UPDATE");
    
    intent.putExtra("coordinates", "28.6139,77.2090");
    
    sendBroadcast(intent); // Insecure: No permission barrier!
    
- **Remediation Blueprint:**
    
    java
    
    // Secure: Use LocalBroadcastManager or explicit Component Intent
    
    Intent intent = new Intent(context, LocationReceiver.class);
    
    intent.putExtra("coordinates", "28.6139,77.2090");
    
    context.sendBroadcast(intent, "com.corp.app.PRIVATE_PERMISSION");
    
- **Audit Rule:** `AndroidManifest.xml` me check karo ki components ke andar `android:exported="false"` explicitly defined ho, jab tak ki component ko externally expose karna intended na ho.

---

### **M2: Insecure Data Storage**

Unencrypted credentials, session tokens, personal data (PII), ya database caches ko device filesystem par plain text me store karna.

- **High-Risk Locations:**
    - Android: `/data/data/<package_name>/shared_prefs/`, `/data/data/<package_name>/databases/`, Cache folders.
    - iOS: Documents directory, Library/Caches, unencrypted SQLite `.db` files.
- **Vulnerable Pattern:**
    
    java
    
    // Plaintext SharedPreferences
    
    SharedPreferences prefs = getSharedPreferences("UserSession", MODE_PRIVATE);
    
    prefs.edit().putString("auth_token", rawToken).apply();
    
- **Remediation Blueprint (EncryptedSharedPreferences with Android Keystore):**
    
    java
    
    MasterKey masterKey = new MasterKey.Builder(context)
    
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    
        .build();
    
    SharedPreferences securePrefs = EncryptedSharedPreferences.create(
    
        context,
    
        "secure_session_prefs",
    
        masterKey,
    
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    
    );
    

---

### **M3: Insecure Communication**

Unencrypted HTTP channels, TLS fallback vulnerabilities, ya missing SSL Certificate Pinning.

- **Attack Vector:** Man-in-the-Middle (AiTM/MITM) proxies unpinned TLS sessions ko terminate karke sensitive API tokens read kar lete hain.
- **Remediation Blueprint (`network_security_config.xml`):**
    
    xml
    
    <?xml version="1.0" encoding="utf-8"?>
    
    <network-security-config>
    
        <!-- Block all cleartext HTTP traffic -->
    
        <base-config cleartextTrafficPermitted="false">
    
            <trust-anchors>
    
                <certificates src="system" />
    
            </trust-anchors>
    
        </base-config>
    
        <!-- Enforce Certificate Pinning for Production Domain -->
    
        <domain-config>
    
            <domain includeSubdomains="true">api.corp-enterprise.com</domain>
    
            <pin-set expiration="2027-01-01">
    
                <!-- Primary Certificate SHA-256 Pin -->
    
                <pin digest="SHA-256">k20D3B1RQLtBlqd...=</pin>
    
                <!-- Backup Pin -->
    
                <pin digest="SHA-256">0Z55RUuaMmEuMW...=</pin>
    
            </pin-set>
    
        </domain-config>
    
    </network-security-config>
    

---

### **M4: Insecure Authentication & Authorization (M4 & M6)**

Biometric checks ko client-side bypassable banana, weak local PIN validation, ya missing server-side role-based access control (RBAC).

- **Common Flaw:** App developer biometric prompt return code (`onAuthenticationSucceeded`) par rely karta hai bina cryptographic signature authenticate kiye. Attacker runtime instrumentation (Frida) se function hook karke `true` return kara deta hai.
- **Defense in Depth:** Biometric authentication successful hone par **Android Keystore** me stored private key unlock honi chahiye, jo server par challenge sign karke bheje. Server verification fail hone par access grant nahi hona chahiye.

---

### **M5: Insufficient Cryptography**

Weak ciphers (DES, RC4, MD5, SHA1), insecure pseudo-random generators, ya codebase me hardcoded symmetric encryption keys.

- **Audit Discovery Command:**
    
    bash
    
    # Search decompiled source code for embedded keys or weak hashes
    
    grep -rnE "(AES|SecretKeySpec|DES|MD5|PRIVATE_KEY|API_SECRET)" ./jadx_output/sources/
    
- **Remediation:** Hardware-backed storage (**Android Keystore Provider** / **iOS Secure Enclave**) use karo, jahan cryptographic operations direct secure enclave hardware me execute hote hain aur raw private key memory me leak nahi hoti.

---

### **M7: Client Code Quality & Memory Safety**

Buffer overflows, format string vulnerabilities, aur native C/C++ libraries (`JNI` / `NDK`) ke andar improper pointer handling.

- **Audit Practice:** Native `.so` files ko inspect karo compile-time protections ke liye:
    
    bash
    
    # Check native binary protections (RELRO, Stack Canary, NX, PIE)
    
    checksec --file=libnative-bridge.so
    

---

### **M8 & M9: Code Tampering & Reverse Engineering**

App binary ko decompile karke, logic patch (Smali editing) karke re-sign karna, aur third-party stores ya modified devices par distribute karna.

- **Anti-Tampering Architecture:**
    1. **Google Play Integrity API / Apple DeviceCheck:** Cryptographically verify karta hai ki binary genuine store se install hui hai ya modified hai.
    2. **Obfuscation (R8 / ProGuard):** Classes, method names, aur variable signatures ko non-reversible strings me flatten karna.

---

## **🛠️ PART 2: Android Inter-Process Communication (IPC) & Drozer Auditing**

Drozer security testing framework hai jo running Android device/emulator me ek unprivileged rogue application ban kar app ke exposed attack surface ko probe karta hai.

[ Kali Linux Machine ]

       │  (Port 31415 via ADB forward)

       ▼

[ Android Emulator / Device ]

       │

       ├──> [ Drozer Agent APK ] (Listens on 127.0.0.1:31415)

       │         │

       │         ▼ (Invokes IPC: Binder, Intents, Content Resolvers)

       │

       └──> [ Target App (e.g., InsecureBankv2) ]

                 ├── Exported Activities (Direct invocation bypasses Auth)

                 ├── Content Providers (SQL Injection / Data Exposure)

                 └── Broadcast Receivers (Malicious trigger injection)

---

### **2.1 Drozer Lab Architecture & Bridge Configuration**

bash

# 1. Verify ADB connection with target emulator

adb devices -l

# 2. Install Drozer Agent APK on target emulator

adb install drozer-agent.apk

# 3. Setup TCP port forwarding from workstation to emulator

adb forward tcp:31415 tcp:31415

# 4. Connect to Drozer interactive console from host machine

drozer console connect

---

### **2.2 Drozer Component Enumeration Commands**

Target application: `com.android.insecurebankv2`

#### **1. Attack Surface Assessment:**

text

dz> run app.package.attacksurface com.android.insecurebankv2

[*] Attack Surface:

  5 activities exported

  1 broadcast receivers exported

  1 content providers exported

  0 services exported

_Agar koi component exported hai aur `permission=null` hai, toh koi bhi local app us component ko execute kar sakti hai._

#### **2. Exported Activities Enumeration & Authentication Bypass:**

text

dz> run app.activity.info -a com.android.insecurebankv2

### **2.2 Android Component Security & IPC Auditing (Continuation)**

Android application framework char main building blocks (Components) par bana hota hai:

1. **Activities** (UI Screens)
2. **Broadcast Receivers** (Event Listeners)
3. **Content Providers** (Data abstraction & sharing)
4. **Services** (Background processing)

Jab koi component `AndroidManifest.xml` me `android:exported="true"` declare hota hai bina proper permission restrictions ke, tab device par maujood koi bhi unprivileged application us component se directly interact kar sakti hai.

---

#### **1. Exported Activities & Broken Access Control**

- **Vulnerability Concept:** Agar sensitive screens (jaise `DashboardActivity`, `PostLoginActivity`, ya `AdminPanelActivity`) exported hon, toh third-party applications bina user credentials verify kiye unhe seedhe launch kar sakti hain.
- **Audit Command (Drozer Syntax):**
    
    text
    
    # Exported activities ki details aur permission requirements list karna
    
    run app.activity.info -a com.android.insecurebankv2
    
- **Analysis:** Agar output me kisi activity ka status `Permission: null` dikhta hai, iska matlab hai ki koi bhi app `Intent` bhej kar us screen ko foreground me call kar sakti hai.
- **Architecture Fix (Secure Manifest):**
    
    xml
    
    <!-- Internal activities must strictly set exported to false -->
    
    <activity 
    
        android:name=".PostLoginActivity" 
    
        android:exported="false" />
    
    _Rule:_ Agar activity ko deep-linking ya external app launch ke liye expose karna zaroori ho, toh hamesha custom signature-level permission enforce karein:
    
    xml
    
    <permission 
    
        android:name="com.corp.app.CUSTOM_SIGNATURE_PERM" 
    
        android:protectionLevel="signature" />
    

---

#### **2. Content Providers & Data Leakage Analysis**

Content Providers applications ko centralized storage (SQLite databases, files) tak access provide karte hain.

- **Vulnerability Concept:** Agar Content Provider exported ho, toh unprivileged applications `content://` URI schemas ke through internal databases ko read ya manipulate kar sakti hain. Agar query handling me parameter concatenation ho, toh client-side SQL Injection create ho sakta hai.
- **Audit Inspection:**
    
    text
    
    # Exported content providers aur unke URI schemes identify karna
    
    run app.provider.info -a com.android.insecurebankv2
    
- **Defensive Code Pattern (Preventing SQLi in Content Providers):** Concat strings ki jagah hamesha `SQLiteQueryBuilder` ya parameterized queries use karein:
    
    java
    
    // Insecure: Raw String Concatenation
    
    db.rawQuery("SELECT * FROM accounts WHERE user = '" + selection + "'", null);
    
    // Secure: Parameterized Prepared Statements
    
    String[] selectionArgs = new String[]{ selection };
    
    db.query("accounts", projection, "user = ?", selectionArgs, null, null, sortOrder);
    
- **Permission Hardening:**
    
    xml
    
    <!-- Restrict read/write permissions at the provider level -->
    
    <provider
    
        android:name=".AccountProvider"
    
        android:authorities="com.corp.app.provider"
    
        android:exported="false"
    
        android:readPermission="com.corp.app.READ_DATA"
    
        android:writePermission="com.corp.app.WRITE_DATA" />
    

---

#### **3. Broadcast Receivers & Intent Sniffing**

- **Vulnerability Concept:** System events ya custom application broadcasts ko receive karne ke liye use hote hain. Agar broad implicit intents use kiye jayein, toh malicious background apps un broadcasts ko intercept karke unme contain hone wala data read kar sakti hain.
- **Audit Inspection:**
    
    text
    
    # Check exported broadcast receivers
    
    run app.broadcast.info -a com.android.insecurebankv2
    
- **Remediation Pattern:** Explicit intents use karein ya system-level `LocalBroadcastManager` implement karein:
    
    java
    
    // Enforcing strict package-level isolation
    
    Intent explicitIntent = new Intent(context, SecureReceiver.class);
    
    explicitIntent.setPackage("com.corp.secureapp");
    
    context.sendBroadcast(explicitIntent);
    

---

## **🍏 PART 3: iOS Security Architecture & Modern Vulnerabilities**

iOS security architecture fundamentally hardware-enforced isolation, code signing, aur sandboxing par operate karti hai.

       ┌────────────────────────────────────────────────────────┐

       │                iOS Security Layers                     │

       ├────────────────────────────────────────────────────────┤

       │ 1. Hardware: Secure Enclave Processor (SEP)            │

       │ 2. Boot Chain: Secure Boot & Cryptographic Signature   │

       │ 3. Kernel: XNU Kernel, MAC Framework, Sandboxing       │

       │ 4. OS Controls: TCC (Transparency, Consent & Control)   │

       │ 5. Code Signing: AMFI & CoreTrust Validation           │

       └────────────────────────────────────────────────────────┘

---

### **3.1 iOS Sandboxing & Entitlements Deep-Dive**

- **Container Directory:** Har iOS app ek isolated directory structure (`/var/mobile/Containers/Data/Application/<UUID>`) ke andar execute hoti hai. Ek app doosri app ke documents ya memory ko directly read nahi kar sakti.
- **Entitlements:** Entitlements key-value pairs hote hain jo application signature me embedded hote hain. Ye system-level capabilities grant karte hain (e.g., Apple Pay, Push Notifications, Network Extensions, HealthKit).
    - _Public Entitlements:_ Standard developers configure kar sakte hain.
    - _Private Entitlements:_ Strictly Apple internal apps aur system daemons ke liye reserve hote hain.

---

### **3.2 Key iOS Vulnerability Classes (Case Studies & Concepts)**

#### **1. CoreTrust & AMFI Architecture (Context: CVE-2022-26766 / CVE-2021-30937)**

- **Architecture Concept:** Apple Mobile File Integrity (`AMFI`) aur `CoreTrust` verify karte hain ki binary valid certificate dwara signed hai aur uske entitlements authorized hain.
- **Flaw Mechanics:** Memory parsing aur signature verification flaws ke chalte malicious binaries invalid/arbitrary signatures ke sath validate ho jati thin bina App Store approval ke.
- **Mitigation:** Apple ne iOS 16.6.1/17.0+ me kernel signature parsing logic aur CoreTrust cryptographic checks ko redesign kiya.

#### **2. MacDirtyCow & Memory CoW Races (CVE-2022-46689)**

- **Architecture Concept:** XNU Kernel ka Virtual Memory subsystem Copy-on-Write (`COW`) mechanism use karta hai shared memory pages handle karne ke liye.
- **Flaw Mechanics:** Read-only system files ko modify karne ke liye memory cache race condition trigger hoti thi jisse disk par bina write permission ke in-memory cached page overwrite ho jata tha (temporary duration ke liye).
- **Impacted Components:** `TCC.db` (Transparency, Consent, and Control database) overwrite hone se unauthorized camera, microphone, ya photo library access permissions grant ho sakti thin.
- **Mitigation:** Proper page locking mechanisms aur strict unmapping checks kernel memory manager me add kiye gaye.

---

## **🛡️ PART 4: Enterprise Mobile App Vetting Framework (Static & Dynamic Analysis)**

Enterprises me corporate devices par sideloaded ya third-party apps deploy karne se pehle ek structured vetting process follow kiya jata hai.

                     [ Input: APK / IPA Binary ]

                                  │

         ┌────────────────────────┴────────────────────────┐

         ▼                                                 ▼

[ Static Application Testing (SAST) ]    [ Dynamic Application Testing (DAST) ]

  • Decompilation (JADX / MobSF)           • Network proxying (Burp Suite)

  • Hardcoded Secrets & API Keys           • Runtime Memory Inspection (Frida)

  • Permission Analysis (Least Privilege)  • Filesystem modification tracking

  • AndroidManifest / Info.plist audit     • Sandboxed execution in emulator

---

### **4.1 Automated Static Analysis with MobSF (Mobile Security Framework)**

MobSF ek automated tool hai jo Android (APK/AAB) aur iOS (IPA) binaries ko audit karta hai.

bash

# Running MobSF using Docker

docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest

# Key Inspection Points in Report:

# 1. Manifest Analysis: Exported components, dangerous permissions.

# 2. Hardcoded Secrets: High-entropy strings, AWS tokens, API keys.

# 3. Code Quality: Insecure random generators, weak crypto functions.

---

### **4.2 Security Checklist for Pentesters & Developers (MASVS Baseline)**

|Category|Control Area|Verification Step|
|---|---|---|
|**Storage**|Data at Rest|Device filesystem inspect karein (`adb shell run-as <pkg> ls -la`), ensure karein tokens unencrypted na hon.|
|**Network**|Data in Transit|Burp Suite se proxy karke check karein ki SSL Pinning properly fail-closed behave kar rahi hai.|
|**Auth**|Biometrics|Verify karein ki authentication token client-side flag se validate nahi ho raha, balki Keystore cryptographic keys use ho rahi hain.|
|**IPC**|Component Exposure|Sabhi activities, services, aur providers me `android:exported="false"` audit karein.|
|**Platform**|Root / Jailbreak Detection|Check karein ki app rooted/tampered environments detect karke gracefully terminate hoti hai.|

---

## **🗺️ Master Certification Roadmap Progress**

| Mod #  | Module Title                                                       | Status                 |
| ------ | ------------------------------------------------------------------ | ---------------------- |
| 01–12  | Modules 01 to 12 (Core Network, System & Perimeter Security)       | ✅ Complete             |
| 13     | Hacking Web Servers                                                | ✅ Complete             |
| **14** | **Hacking Web Applications (OWASP Top 10, Web APIs, Logic Flaws)** | ⏳ **CURRENT TARGET**   |
| 15     | SQL Injection (Advanced Syntax & Blind Vectors)                    | ⏸️ Pending             |
| 16     | Hacking Wireless Networks                                          | ⏸️ Pending             |
| **17** | **Hacking Mobile Platforms (Android & iOS)**                       | ✅ **Documented Above** |
| 18     | IoT and OT Hacking                                                 | ⏸️ Pending             |
| 19     | Cloud Computing                                                    | ⏸️ Pending             |
| 20     | Cryptography                                                       | ⏸️ Pending             |