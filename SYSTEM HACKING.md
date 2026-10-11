# **MODULE 06: SYSTEM HACKING (MASTERCLASS STUDY NOTES)**

> **Track:** CEH v13 AI Official | NIST SP 800-115 | MITRE ATT&CK Matrix  
> **Topic:** Gaining Access, Privilege Escalation, Maintaining Access & Clearing Tracks  
> **Language:** Comprehensive Hinglish (Deep Technical Concepts + Auditing Commands + Enterprise Defense)

---

## **📑 TABLE OF CONTENTS**

1. [System Hacking Architecture & 4-Stage Lifecycle](#1-system-hacking-architecture--4-stage-lifecycle)
2. [Stage 1: Gaining Access & Password Mechanics](#2-stage-1-gaining-access--password-mechanics)
    - _Windows SAM, SYSTEM Hive, NTDS.dit & LSASS Memory_
    - _Linux `/etc/passwd` aur `/etc/shadow` Structure_
    - _LM, NTLM, NetNTLMv2 & Pass-the-Hash (PtH) Concept_
    - _Password Auditing & Cracking Mechanics (Hashcat & JtR Modes)_
    - _LLMNR / NBT-NS Poisoning Mechanics (Responder)_
3. [Stage 2: Privilege Escalation (PrivEsc) Deep Dive](#3-stage-2-privilege-escalation-privesc-deep-dive)
    - _Windows: Unquoted Service Path Vulnerability Mechanics_
    - _Windows: Token Impersonation (`SeImpersonatePrivilege`)_
    - _Windows: DLL Search Order Hijacking & AlwaysInstallElevated_
    - _Linux: SUID / SGID Binaries & Execution Path Abuse_
    - _Linux: Sudoers Configuration Flaws (`sudo -l`)_
    - _Linux: File Permission Misconfigurations (`/etc/passwd`, `/etc/shadow`)_
    - _Linux: POSIX Capabilities & Insecure Cron Jobs_
4. [Stage 3: Maintaining Access & Persistence](#4-stage-3-maintaining-access--persistence)
    - _Windows Persistence: Registry Run Keys, Scheduled Tasks, Hidden Accounts_
    - _Linux Persistence: SSH Keys, Crontabs, Systemd Services_
    - _Rootkit Architecture (User, Kernel, Hypervisor, Bootloader)_
    - _Steganography Mechanics: LSB Insertion & Whitespace_
5. [Stage 4: Clearing Tracks & Anti-Forensics](#5-stage-4-clearing-tracks--anti-forensics)
    - _Windows Event Log Structure & Critical Event IDs_
    - _Linux Log Auditing (`/var/log/`) & Shell History Controls_
    - _Timestomping & Artifact Elimination Concepts_
6. [Enterprise Countermeasures, Hardening & CEH Exam Flashcards](#6-enterprise-countermeasures-hardening--ceh-exam-flashcards)

---

## **1. System Hacking Architecture & 4-Stage Lifecycle**

Reconnaissance (Module 2), Scanning (Module 3), Enumeration (Module 4), aur Vulnerability Analysis (Module 5) ke baad **System Hacking** wo stage hai jahan target system ke andar entry li jaati hai aur full control establish kiya jaata hai.

                     CEH HACKING METHODOLOGY (CHM)

  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐     ┌────────────────┐

  │ Footprinting  │ ──► │   Scanning    │ ──► │  Enumeration  │ ──► │ Vulnerability  │

  │ (Module 02)   │     │ (Module 03)   │     │ (Module 04)   │     │ Analysis (M05) │

  └───────────────┘     └───────────────┘     └───────────────┘     └───────┬────────┘

                                                                            │

  ┌─────────────────────────────────────────────────────────────────────────┘

  │

  ▼

 ══════════════════════════════════════════════════════════════════════════════════

                   MODULE 06: SYSTEM HACKING (4 CORE PHASES)

 ══════════════════════════════════════════════════════════════════════════════════

  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐

  │ 1. GAINING       │───►│ 2. ESCALATING    │───►│ 3. MAINTAINING   │───►│ 4. CLEARING      │

  │    ACCESS        │    │    PRIVILEGES    │    │    ACCESS        │    │    TRACKS        │

  ├──────────────────┤    ├──────────────────┤    ├──────────────────┤    ├──────────────────┤

  │ • Credential     │    │ • Vertical       │    │ • Persistence    │    │ • Event Log      │

  │   Attacks        │    │   PrivEsc        │    │   (Reg/Cron)     │    │   Analysis       │

  │ • Authentication │    │ • Horizontal     │    │ • Backdoors &    │    │ • Forensic       │

  │   Flaws          │    │   PrivEsc        │    │   Rootkits       │    │   Timestamps     │

  │ • Network Auth   │    │ • OS Config Flaws│    │ • Steganography  │    │ • History &      │

  │   Interception   │    │ • Token Abuse    │    │ • Covert Links   │    │   Cache Wiping   │

  └──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘

---

## **2. Stage 1: Gaining Access & Password Mechanics**

### **2.1 Operating System Credential Storage**

#### **A. Windows Architecture**

Windows plaintext passwords disk par store nahi karta:

1. **Local SAM (Security Account Manager):**
    - Path: `C:\Windows\System32\config\SAM`
    - Ye file OS boot hone ke baad kernel dwara locked hoti hai (direct copy nahi ho sakti).
    - Isme local accounts ke NTLM hashes store hote hain, jo `SYSTEM` hive key se encrypt hote hain.
2. **Active Directory Database:**
    - Path: `C:\Windows\NTDS\NTDS.dit`
    - Domain Controllers par pure domain ke users, groups aur hashes store karta hai.
3. **LSASS Process (`lsass.exe`):**
    - Local Security Authority Subsystem Service RAM me chal rahi hoti hai.
    - User login ke baad uske Kerberos tickets, NTLM hashes aur authentication tokens memory me active rehte hain.

#### **B. Linux Architecture**

Linux credentials do primary files me divide hote hain:

1. `/etc/passwd`: **World-readable (`-rw-r--r--`)**. Isme har user ka username, UID, GID, home directory aur shell hota hai.
    
    text
    
    root:x:0:0:root:/root:/bin/bash
    
          │
    
          └── 'x' represent karta hai ki actual hash /etc/shadow me hai
    
2. `/etc/shadow`: **Restricted (`-rw-r-----` ya `-r--------`, only root readable)**. Isme salted hash aur password aging parameters hote hain:
    
    text
    
    root:$6$kG9pXyZ...$v8ZqW...:19700:0:99999:7:::
    
          │  │
    
          │  └── Salt aur Hashed Output
    
          └── Hash Type Identifier:
    
              $1$ = MD5
    
              $2a$ / $2y$ = Blowfish (bcrypt)
    
              $5$ = SHA-256
    
              $6$ = SHA-512 (Standard modern Linux)
    
              $y$ = Yescrypt (Debian/Ubuntu modern default)
    

---

### **2.2 Hash Types & Authentication Protocols**

|Format|Algorithm|Characteristics & Security Posture|
|---|---|---|
|**LM Hash**|DES|Legacy (Win 2000/XP). Passwords ko do 7-character blocks me divide karta hai, uppercase me convert karta hai. Max length 14 chars. Rainbow tables se instantly breakable.|
|**NTLM Hash**|MD4|Password ka UTF-16LE encoding par MD4 hash. Isme **koi Salt nahi hota**. Is wajah se ye **Pass-the-Hash (PtH)** attack ke prati vulnerable hota hai.|
|**NetNTLMv1/v2**|HMAC-MD5|Network challenge-response authentication protocol. Isko direct Pass-the-Hash me use nahi kiya ja sakta; isko offline crack karna padta hai ya SMB Relay me use kiya ja sakta hai.|

#### **Pass-the-Hash (PtH) Concept**

Windows SMB/RPC protocols me authentication ke dauran plaintext password verify nahi hota, balki NTLM hash challenge solve karne ke liye kaafi hota hai. Agar auditor ke paas NTLM hash ho:

bash

# Example syntax using Impacket suite for administrative testing:

impacket-psexec -hashes <LM_HASH>:<NTLM_HASH> Administrator@<TARGET_IP>

---

### **2.3 Network Credential Interception: LLMNR / NBT-NS Poisoning**

Jab koi Windows client kisi server ya share ko access karne ki koshish karta hai (e.g., `\\InternalShare`) aur DNS request fail ho jaati hai, tab Windows subnet par broadcast query bhejta hai:

- **LLMNR (Link-Local Multicast Name Resolution):** UDP Port 5355
- **NBT-NS (NetBIOS Name Service):** UDP Port 137

   Victim Client                         Auditing Machine (Responder)

         │                                            │

         ├─── Broadcast: "Who is \\FileServer?" ─────►│

         │    (LLMNR / NBT-NS Broadcast)              │

         │                                            │

         │◄── Spoofed Reply: "I am \\FileServer!" ────┤

         │                                            │

         ├─── Sends NetNTLMv2 Challenge-Response ────►│ (Captures hash for

         │                                            │  offline auditing)

Auditors is weakness ko verify karne ke liye **Responder** tool use karte hain:

bash

# Interface bind aur passive listening

sudo responder -I eth0 -dwv

---

### **2.4 Password Auditing & Cracking Mechanics**

                       OFFLINE PASSWORD AUDITING TYPES

                                      │

     ┌──────────────────┬─────────────┴─────────────┬──────────────────┐

     ▼                  ▼                           ▼                  ▼

  DICTIONARY          HYBRID                      MASK            RAINBOW TABLE

(Wordlist exact    (Word + Numbers/            (Specific pattern  (Pre-computed

 matches)           Rules: Admin -> Adm1n!)     e.g., ?u?l?l?d?d)  chain lookup)

#### **Hashcat Modes & Essential Reference**

Hashcat GPU cores (CUDA / OpenCL) par mathematical parallel processing karta hai:

|Mode Flag (`-m`)|Algorithm / Target|Common Use Case|
|---|---|---|
|`-m 1000`|NTLM|Windows local SAM / Active Directory|
|`-m 5600`|NetNTLMv2|Network authentication captures|
|`-m 1800`|sha512crypt (`$6$`)|Modern Linux `/etc/shadow`|
|`-m 22000`|WPA/WPA2/WPA3 PBKDF2|Wireless handshakes & PMKID|

bash

# 1. Straight Dictionary Attack (-a 0)

hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# 2. Rule-Based Mutation Attack (-r)

hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 3. Mask Attack (-a 3) - Example: Capital + 4 lowercase + 2 digits

hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d

#### **John the Ripper (JtR) Architecture**

bash

# Linux shadow aur passwd file combine karna

sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Wordlist mode me execute karna

john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# Successfully cracked passwords check karna

john --show unshadowed.txt

---

## **3. Stage 2: Privilege Escalation (PrivEsc) Deep Dive**

Privilege escalation do types ka hota hai:

- **Horizontal PrivEsc:** Same level ke doosre user ka access lena (e.g., User A se User B).
- **Vertical PrivEsc:** Low-privilege account se Administrative / System / Root access lena.

---

### **3.1 Windows PrivEsc 1: Unquoted Service Path**

#### **Flaw Mechanism**

Windows jab kisi service executable path ko execute karta hai, agar path me spaces hon aur wo double quotes (`"`) ke andar enclose na ho, to operating system har space ko argument separator maankar files dhoondhta hai:

Configured Path: C:\Program Files\Network Monitor\Service Engine\engine.exe

Windows Execution Search Order:

1. C:\Program.exe

2. C:\Program Files\Network.exe

3. C:\Program Files\Network Monitor\Service.exe

4. C:\Program Files\Network Monitor\Service Engine\engine.exe

Agar kisi low-privilege user ke paas `C:\Program Files\Network Monitor\` folder me **Write Permission** hai, to wo wahan `Service.exe` place kar sakta hai. Jab service restart hogi, to Windows `Service.exe` ko `LocalSystem` privileges ke saath execute karega.

#### **Auditing & Verification Commands**

cmd

:: 1. Unquoted paths dhoondhna jo System32 me na hon:

wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /v /i "system32" | findstr /v \"

:: 2. Service permissions aur start account check karna:

sc qc <ServiceName>

:: 3. Directory write access check karna (Sysinternals AccessChk):

accesschk.exe /accepteula -uwdq "C:\Program Files\Network Monitor"

:: Agar output me "RW BUILTIN\Users" dikhe -> Directory Writable hai!

---

### **3.2 Windows PrivEsc 2: Token Impersonation (Potato Class Attacks)**

Service accounts (jaise IIS Application Pools ya SQL Server) ke paas aam taur par restricted Windows privileges hote hain, lekin unme **`SeImpersonatePrivilege`** ya **`SeAssignPrimaryTokenPrivilege`** enabled hota hai:

cmd

whoami /priv

# Privilege Name                Description                               State

# SeImpersonatePrivilege        Impersonate a client after authentication Enabled

- **Core Mechanism:** Local system par COM/RPC services ko induce kiya jaata hai attacker dwara controlled pipe par connect hone ke liye. Jab `NT AUTHORITY\SYSTEM` connect karta hai, to system us security token ko impersonate karke elevated context me process create kar leta hai (e.g., GodPotato, JuicyPotatoNG).

---

### **3.3 Linux PrivEsc Deep Dive**

                             LINUX PRIVESC VECTORS

                                       │

     ┌────────────────────┬────────────┴────────────┬────────────────────┐

     ▼                    ▼                         ▼                    ▼

  SUDOERS FLAWS       SUID BINARIES            FILE PERMISSIONS       CAPABILITIES

 (`sudo -l` rules,   (GTFOBins execution     (Writable /etc/passwd  (cap_setuid on

  NOPASSWD binaries)  with preserved eUID)   or readable /shadow)    interpreters)

#### **A. Insecure Sudoers (`sudo -l`)**

Jab system administrator kisi binary ko bina password ke sudo rights de deta hai:

bash

sudo -l

# User may run the following commands on host:

# (ALL : ALL) NOPASSWD: /usr/bin/find

GTFOBins standard ke according, `find` directly shell invoke kar sakta hai:

bash

sudo find . -exec /bin/sh \; -quit

#### **B. SUID / SGID Binaries (`chmod u+s`)**

SUID bit set hone par binary file owner (`root`) ke privileges ke saath run hoti hai:

bash

# System me SUID binaries locate karna

find / -perm -4000 -type f 2>/dev/null

# Example: Agar python3 par SUID set ho:

/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

#### **C. Insecure `/etc/passwd` Permissions**

Agar `/etc/passwd` world-writable ho (`-rw-rw-rw-`):

bash

# Password hash generate karna

openssl passwd -1 -salt admin pass123

# Root-level entry add karna (UID 0, GID 0)

echo 'auditroot:$1$admin$5b8...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Direct switch to new root user:

su auditroot

---

## **4. Stage 3: Maintaining Access & Persistence**

Persistence ka objective hota hai ki system reboot hone ya user logout hone ke baad bhi management channel break na ho.

                           PERSISTENCE MECHANISMS

                                     │

         ┌───────────────────────────┴───────────────────────────┐

         ▼                                                       ▼

      WINDOWS                                                  LINUX

  • Registry Run Keys                                     • User / System Crontabs

    `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`    `/etc/crontab`

  • Scheduled Tasks (`schtasks`)                          • SSH Authorized Keys

  • Service Installation (`sc create`)                      `~/.ssh/authorized_keys`

  • WMI Event Subscriptions                               • Systemd Unit Services

---

### **4.1 Rootkits: Deep Invisibility Architecture**

Rootkit ka primary purpose malware ko execute karna nahi, balki malicious presence ko OS se **chhipana (hide karna)** hota hai.

  ┌────────────────────────────────────────────────────────────────────────┐

  │                           ROOTKIT TAXONOMY                             │

  ├──────────────────┬─────────────────────────────────────────────────────┤

  │ Level / Type     │ Hooking Mechanism & Technical Operation             │

  ├──────────────────┼─────────────────────────────────────────────────────┤

  │ User-Mode        │ DLL injection / API hooking. Windows APIs jaise     │

  │ (Ring 3)         │ `EnumProcesses` aur `FindFirstFile` ko hook karke   │

  │                  │ process aur file list se malicious entries filter   │

  │                  │ kar deta hai.                                       │

  ├──────────────────┼─────────────────────────────────────────────────────┤

  │ Kernel-Mode      │ Ring 0 drivers. SSDT (System Service Descriptor     │

  │ (Ring 0)         │ Table) ya Direct Kernel Object Manipulation (DKOM)  │

  │                  │ se process list unlink kar deta hai.                │

  ├──────────────────┼─────────────────────────────────────────────────────┤

  │ Hypervisor       │ Hardware virtualization (Intel VT-x / AMD-V) use    │

  │ (Type-0)         │ karke OS ko ek virtual machine ke andar run karta   │

  │                  │ hai (Blue Pill architecture).                       │

  ├──────────────────┼─────────────────────────────────────────────────────┤

  │ Bootloader /     │ MBR ya UEFI firmware level par baithta hai. OS load │

  │ Firmware         │ hone se pehle activate hota hai (e.g., BlackLotus). │

  └──────────────────┴─────────────────────────────────────────────────────┘

---

### **4.2 Steganography Mechanics**

Data hiding techniques security monitoring ko bypass karne ke liye use ki jaati hain:

1. **LSB (Least Significant Bit) Insertion:**
    
    bash
    
    # Steghide tool usage
    
    steghide embed -cf cover.jpg -ef payload.txt -p SecretKey
    
    steghide extract -sf cover.jpg -p SecretKey
    
    - 24-bit image me har pixel ke RGB components ke last bit ko secretly alter kiya jaata hai. Human eye is difference ko detect nahi kar sakti.
2. **Whitespace Steganography (Snow):**
    - Text file ke lines ke end me invisible spaces aur tabs append karke message encode kiya jaata hai.

---

## **5. Stage 4: Clearing Tracks & Anti-Forensics**

Investigation ya Incident Response ke dauran forensic analysts log timeline create karte hain. Anti-forensics ka matlab hota hai in artifacts ko disrupt karna.

### **5.1 Critical Windows Event IDs (Blue Team Audit Matrix)**

|Event ID|Log Name|Description & Security Significance|
|---|---|---|
|**1102**|Security|Audit Log was cleared (`wevtutil` ya manual event wipe detect karta hai).|
|**4624**|Security|Successful Account Logon (Logon Type 2=Interactive, 3=Network, 10=RDP).|
|**4625**|Security|Failed Account Logon (Brute-force detection).|
|**4672**|Security|Special privileges assigned to new logon (Admin / SYSTEM elevation).|
|**7045**|System|A new service was installed in the system (Persistence / PrivEsc marker).|

cmd

:: Windows native log clearing verification (Admin context)

wevtutil cl Security

wevtutil cl System

wevtutil cl Application

### **5.2 Anti-Forensics Concepts: Timestomping & History**

- **MAC Timestamps:** Modified, Accessed, Created timestamps.
- **Timestomping:** File ke metadata timestamps ko modify karke legacy system binaries (jaise `kernel32.dll`) ke barabar kar dena taaki timeline analysis me malicious file recent na dikhe.
- **Linux History Controls:**
    
    bash
    
    # Session history disable karna
    
    unset HISTFILE
    
    export HISTSIZE=0
    

---

## **6. Enterprise Countermeasures, Hardening & CEH Exam Flashcards**

### **6.1 Defense-in-Depth Matrix**

       ┌────────────────────────────────────────────────────────┐

       │             IDENTITY & ACCESS HARDENING                │

       │  • LAPS (Local Administrator Password Solution)        │

       │  • MFA (FIDO2 / Hardware Security Keys)                │

       │  • Disable LLMNR/NBT-NS via GPO                        │

       └───────────────────────────┬────────────────────────────┘

                                   │

                                   ▼

       ┌────────────────────────────────────────────────────────┐

       │             ENDPOINT & OS RUNTIME DEFENSE              │

       │  • Windows Credential Guard (Isolated LSASS)           │

       │  • UEFI Secure Boot & Driver Signature Enforcement    │

       │  • AppLocker / Software Restriction Policies           │

       │  • Quotes around all Service Binary Paths              │

       └───────────────────────────┬────────────────────────────┘

                                   │

                                   ▼

       ┌────────────────────────────────────────────────────────┐

       │             CENTRALIZED LOG MONITORING                 │

       │  • WORM (Write-Once-Read-Many) Remote SIEM Logging     │

       │  • Alert on Event ID 1102 (Log Clearing)               │

       │  • Auditd real-time kernel syscall tracing             │

       └────────────────────────────────────────────────────────┘

---

### **6.2 High-Yield CEH v13 Exam Flashcards**

|Exam Concept|Key Fact to Remember|
|---|---|
|**SAM Database Location**|`C:\Windows\System32\config\SAM` (Protected by OS kernel while online).|
|**LM Hash Weakness**|14-char limit, uppercase conversion, splits password into two 7-byte DES blocks.|
|**NTLM Pass-the-Hash**|NTLM hashes me Salt nahi hota; challenge authentication me direct use ho sakta hai.|
|**NetNTLMv2 Nature**|Challenge-response string; cannot be passed directly via PtH; must be cracked or relayed.|
|**Mimikatz Utility**|Extracts plaintext passwords, Kerberos tickets, and hashes directly from `lsass.exe` RAM.|
|**Potato Exploits**|Windows service accounts ke `SeImpersonatePrivilege` ko abuse karke SYSTEM token hijack karte hain.|
|**Unquoted Service Path**|Spaces in executable path + missing quotes + folder write permission = LocalSystem escalation.|
|**GTFOBins**|Unix binaries ka catalog jo sudo, SUID, ya capabilities ke through misconfigure hone par shell escape provide karte hain.|
|**Event ID 1102**|Security log cleared event. Enterprise SOC me instantly critical alert trigger karta hai.|
|**Covert Channel**|Data transfer protocol jo standard monitoring channels ke through unauthorized information leak karta hai (e.g., DNS/ICMP tunneling).|

---

