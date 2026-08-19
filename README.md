# 🔎 Network Scanner

A lightweight multithreaded network scanner built with Python for discovering active hosts, scanning TCP ports, identifying common services, and collecting basic HTTP and TLS information.

The project was built from scratch to gain practical experience with **network programming, TCP/IP, sockets, multithreading, service detection, HTTP/TLS, and Object-Oriented Programming**.

---

## 📌 Overview

Network Scanner discovers active devices on the local network and performs TCP port scanning on them.

For discovered open ports, the scanner attempts to identify the associated service and collect additional information where possible.

The scanning pipeline is:

```text
Local Network
      │
      ▼
Host Discovery
      │
      ▼
Active Hosts
      │
      ├── Hostname
      └── MAC Address
      │
      ▼
TCP Port Scanning
      │
      ▼
Service Detection
      │
      ├── Banner Grabbing
      ├── HTTP Inspection
      └── TLS Inspection
      │
      ▼
Formatted Results
```
✨ Features
🌐 Network Discovery
Automatically detects the local IPv4 address
Calculates the local /24 network
Determines:
Network address
Netmask
Broadcast address
🖥️ Host Discovery
Scans hosts inside the local network
Uses ICMP ping to identify active hosts
Resolves hostnames when possible
🔗 MAC Address Discovery
Reads the local ARP table
Associates discovered IP addresses with MAC addresses
Displays MAC addresses for available hosts
🚪 TCP Port Scanning
User-defined port range
TCP connection-based scanning
Configurable timeout
Multithreaded scanning using ThreadPoolExecutor
🔍 Service Detection

The scanner recognizes common services based on their ports, including:

Port	Service
21	FTP
22	SSH
23	Telnet
25	SMTP
53	DNS
80	HTTP
110	POP3
139	NetBIOS
443	HTTPS
445	SMB
3389	RDP
8080	HTTP

Unknown ports are also reported.

📦 Banner Grabbing

The scanner attempts to communicate with open ports and collect available banner information.

🌍 HTTP Inspection

For HTTP services, the scanner sends an HTTP request and extracts information such as:

HTTP status code
HTTP status
Server
Content-Type

Example:

```text
8080   HTTP | 200 OK
       Server: SimpleHTTP/0.6 Python/3.11.9
```

🔐 TLS / HTTPS Inspection

For HTTPS services, the scanner establishes a TLS connection and collects:

TLS version
Cipher suite
Certificate
Certificate subject
Certificate issuer
Certificate validity period
Subject Alternative Names (SAN)

Example:
```text
TLS Version: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256

Subject: github.com
Issuer: Sectigo Public Server Authentication CA DV E36

Valid From: Jul 3 00:00:00 2026 GMT
Valid Until: Sep 30 23:59:59 2026 GMT

SAN: github.com, www.github.com
```

🛠️ Technologies

The project is built entirely with Python's standard library.

Language
Python 3.11+
Standard Library
socket
ipaddress
subprocess
ssl
concurrent.futures
Concepts
TCP/IP networking
IPv4 addressing
TCP sockets
Port scanning
ICMP ping
ARP
DNS / hostname resolution
HTTP
HTTPS
TLS
SSL certificates
Multithreading
Object-Oriented Programming
Modular architecture

No external Python packages are required.

🏗️ Project Architecture

The project was initially developed as a single Python file and later refactored into a modular Object-Oriented architecture.

The current architecture separates network discovery, host scanning, port scanning, service detection, result formatting, and data models.

```text
Network Scanner
│
├── Network Information
│
├── Host Scanner
│   ├── Ping
│   ├── Hostname Resolution
│   └── ARP
│
├── Port Scanner
│   ├── Port Validation
│   ├── TCP Connection
│   └── Multithreading
│
├── Service Detector
│   ├── Service Identification
│   ├── Banner Grabbing
│   ├── HTTP Detection
│   └── TLS Detection
│
├── Host Model
│
└── Result Formatter

```

📂 Project Structure

```text
Network_scanner/
│
├── main.py
│
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
├── LICENSE
└── .gitignore

```

The exact file structure may change as the project evolves.

🚀 Installation
Requirements
Python 3.11 or newer
Windows environment

The project currently uses Windows-specific commands such as:

```text
ping
arp

```

Clone the Repository

```
git clone <repository-url>
```
Move into the project directory:

```
cd Network_scanner
```

▶️ Usage

Run the scanner with:
```
python main.py
```

The scanner first detects the local network.


Example:

```text
=================================================================
                            NETWORK SCANNER
=================================================================

Local IP:  10.196.129.54
Network:  10.196.129.0/24
Netmask:  255.255.255.0
Broadcast: 10.196.129.255

Scanning...
```
The program then asks for the port range:
```
Start port: 1
End port: 1000


Scanning ports...
```


📊 Example Output
A typical scan may produce output similar to:

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

When an HTTP service is detected:
```
8080   HTTP | 200 OK
       Server: SimpleHTTP/0.6 Python/3.11.9
       Content-Type: Unknown
```
When a TLS service is detected:
```
443    HTTPS | TLS: TLSv1.3
       Cipher: TLS_AES_128_GCM_SHA256
       Subject: github.com
       Issuer: Sectigo Public Server Authentication CA DV E36
       Valid From: Jul 3 00:00:00 2026 GMT
       Valid Until: Sep 30 23:59:59 2026 GMT
       SAN: github.com, www.github.com
```

⚡ Multithreading

Network scanning can involve a large number of socket connections.

Scanning every host and port sequentially would be unnecessarily slow.

The project therefore uses Python's:
```
ThreadPoolExecutor
```
For example:
```
with ThreadPoolExecutor(max_workers=20) as executor:
    ...
```
This allows multiple network operations to be performed concurrently.

The same approach is used during host discovery and port scanning.


🧠 How Port Scanning Works

For every target port, the scanner creates a TCP socket and attempts to establish a connection.

Conceptually:

```text
Target IP
    │
    ├── Port 22  ──► TCP connection
    │
    ├── Port 80  ──► TCP connection
    │
    ├── Port 443 ──► TCP connection
    │
    └── Port 8080 ─► TCP connection
```

If the connection succeeds, the port is considered open.

If the connection fails or times out, the port is considered closed or unreachable.


🔎 Service Detection

After discovering open ports, the scanner attempts to determine which service is associated with each port.

For example:
```
22   → SSH
53   → DNS
80   → HTTP
443  → HTTPS
445  → SMB
```
This information is based primarily on commonly assigned port numbers.

Therefore, the detected service should not be considered definitive.

A service can run on a non-standard port.

🌍 HTTP Detection

When the detected service is HTTP, the scanner opens a TCP connection and sends an HTTP request.

Example request:
```
HEAD / HTTP/1.0
Host: target
Connection: close
```
The response is then parsed to extract useful information.

For example:
```
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.9
Content-Type: text/html
```

🔐 TLS Detection

For HTTPS services, the scanner creates a TLS connection using Python's ssl module.

The scanner can inspect:
```
TLS Version
Cipher Suite
Certificate
Certificate Subject
Certificate Issuer
Validity Period
Subject Alternative Names
```
Example:
```
TLS Version: TLSv1.3
Cipher: TLS_AES_128_GCM_SHA256
Subject: github.com
Issuer: Sectigo Public Server Authentication CA DV E36
```
This provides a basic view of the TLS configuration exposed by the target.


🧩 Object-Oriented Design

The project was initially implemented as a procedural Python script.

As the project grew, the codebase was refactored into an Object-Oriented architecture.

The main components include classes responsible for:

NetworkInfo

Responsible for collecting information about the local network.

Local IP
Network
Netmask
Broadcast
HostScanner

Responsible for discovering active hosts.

Ping
Hostname
ARP
PortScanner

Responsible for:

Port validation
TCP scanning
Multithreaded scanning
ServiceDetector

Responsible for identifying services and selecting the appropriate scanner.

TLSScanner

Responsible for TLS connections and certificate inspection.
BannerGrabber

Responsible for collecting service banners.

Host

Represents a discovered host and stores its scan results.

This separation makes the project easier to understand, maintain, and extend.


📚 What I Learned

This project was built as a practical way to understand networking rather than simply learning the theory.

Throughout the development process, I worked with:

```text
Python
   │
   ├── Sockets
   │
   ├── IPv4 / Subnets
   │
   ├── TCP
   │
   ├── ICMP
   │
   ├── ARP
   │
   ├── DNS / Hostnames
   │
   ├── HTTP
   │
   ├── HTTPS
   │
   ├── TLS / SSL
   │
   ├── Multithreading
   │
   └── OOP
```

The project also helped me understand how different layers of networking interact in a real application.

🎯 Project Goals

The main goal of this project was not to build a production-grade scanner.

Instead, the goal was to learn by building.

The project helped me move from:

"I know what a TCP socket is."

to:

"I can actually use sockets to discover
and inspect services on a network."
🚧 Future Ideas

The current version is considered complete.

Possible future improvements include:

UDP scanning
Better service fingerprinting
More protocol-specific scanners
OS fingerprinting
JSON output
CSV reports
HTML reports
Command-line arguments
Configurable timeout
Configurable thread count
Improved IPv6 support
More advanced HTTP analysis

These features are intentionally left outside the current scope.

⭐ Final Note

This project started as a simple Python network scanner and gradually evolved into a modular application involving sockets, concurrency, service detection, HTTP/TLS analysis, and Object-Oriented Programming.

