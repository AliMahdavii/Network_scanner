# Network Scanner

A multithreaded network scanner built with Python for discovering active hosts, scanning TCP ports, identifying common services, and collecting basic HTTP and TLS information.

---

## Features

- Local network discovery
- Active host detection using ICMP ping
- Hostname resolution
- MAC address discovery using ARP
- TCP port scanning
- Multithreaded scanning with `ThreadPoolExecutor`
- Common service identification
- Banner grabbing
- HTTP response inspection
- HTTPS / TLS inspection
- TLS certificate information
- Modular OOP architecture
- Clean terminal output

---

## 🛠️ Technologies

- Python 3.11+
- `socket`
- `ipaddress`
- `subprocess`
- `ssl`
- `concurrent.futures`
- Object-Oriented Programming
- TCP/IP networking

No external Python packages are required.

---

## 🏗️ Project Structure

```text
Network_scanner/
│
├── main.py
├── network_scanner.py
│
├── network_info.py
├── host_scanner.py
├── port_scanner.py
│
├── service_detector.py
├── banner_grabber.py
├── http_scanner.py
├── tls_scanner.py
│
├── models.py
├── formatter.py
├── parsers.py
│
├── README.md
└── .gitignore

```

🚀 Getting Started
Prerequisites
Python 3.11 or newer
Git
Windows

This project currently targets Windows because some network discovery features rely on Windows commands such as ping and arp.

No external Python packages are required.

Installation

Clone the repository:

git clone https://github.com/AliMahdavii/Network_scanner.git

Enter the project directory:

cd Network_scanner

Run the scanner:

python main.py

---

## 📊 Example Output

```text
=================================================================
                            NETWORK SCANNER
=================================================================

Local IP:  10.196.129.54
Network:  10.196.129.0/24
Netmask:  255.255.255.0
Broadcast:  10.196.129.255

Scanning...

Start port: 1
End port: 1000

Scanning ports...

IP ADDRESS        HOSTNAME             MAC ADDRESS
-----------------------------------------------------------------
10.196.129.54      DESKTOP-N8DCA3C       Unknown
10.196.129.104     Unknown               ba-1b-b2-88-c9-87
10.196.129.209     Unknown               d6-ab-d7-4e-0b-20
                   135    Unknown | Unknown Unknown
                          Server: Unknown
                          Content-Type: Unknown
                   139    NetBIOS | Unknown Unknown
                          Server: Unknown
                          Content-Type: Unknown
                   445    SMB | Unknown Unknown
                          Server: Unknown
                          Content-Type: Unknown
                   902    Unknown | VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t,
                          Server: Unknown
                          Content-Type: Unknown
                   912    Unknown | VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , ,
                          Server: Unknown
                          Content-Type: Unknown
                   53     DNS | Unknown Unknown
                          Server: Unknown
                          Content-Type: Unknown

-----------------------------------------------------------------
3 hosts found
=================================================================

```

Output may vary depending on the local network, active devices, available services, and selected port range.

---

## ⚙️ How It Works

The scanner follows a series of steps to discover and analyze devices on the local network.

### 1. Network Detection

The scanner determines the local IPv4 address and calculates the corresponding `/24` network.

```text
Local IP
   ↓
Network Address
   ↓
Netmask
   ↓
Broadcast Address

Host Discovery

The scanner checks each host in the network using ICMP ping to determine which devices are online.

Network
   ↓
Scan all hosts
   ↓
ICMP Ping
   ↓
Online Hosts
Host Information

For each active host, the scanner attempts to collect:

IP address
Hostname
MAC address

Hostname information is obtained using reverse DNS lookup, while MAC addresses are retrieved from the local ARP table.

Port Scanning

The scanner asks the user for a TCP port range and checks each port using TCP connections.

Multiple ports are scanned concurrently using ThreadPoolExecutor.

Host
  ↓
Port Range
  ↓
TCP Connection Attempts
  ↓
Open Ports

Service Detection

Open ports are mapped to commonly known services based on their port numbers.

Examples:

22   → SSH
53   → DNS
80   → HTTP
443  → HTTPS
445  → SMB
3389 → RDP

Banner and Protocol Inspection

Depending on the detected service, the scanner performs additional inspection.

Open Port
    │
    ├── HTTP
    │      ↓
    │   HTTP Response
    │
    ├── HTTPS
    │      ↓
    │   TLS Information
    │      ↓
    │   Certificate
    │
    └── Other Services
           ↓
       Banner Grabbing

For HTTP services, the scanner attempts to retrieve information such as:

HTTP status code
Server
Content-Type

For HTTPS services, it collects information such as:

TLS version
Cipher suite
Certificate subject
Certificate issuer
Certificate validity period
Subject Alternative Names (SAN)
Result Formatting

Finally, the collected information is passed to the formatter and displayed in the terminal in a structured format.



---

```text
┌──────────────────┐
│ Network Detection│
└────────┬─────────┘
         ↓
┌──────────────────┐
│  Host Discovery  │
└────────┬─────────┘
         ↓
┌──────────────────┐
│  Host Information│
└────────┬─────────┘
         ↓
┌──────────────────┐
│  Port Scanning   │
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Service Detection│
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Protocol Analysis│
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Result Formatting│
└──────────────────┘

