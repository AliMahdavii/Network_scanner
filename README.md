# Network Scanner

A multithreaded network scanner built with Python for discovering active hosts, scanning TCP ports, identifying common services, and collecting basic HTTP and TLS information.

---

##  Features

-  Local network discovery
-  Active host detection using ICMP ping
-  Hostname resolution
-  MAC address discovery using ARP
-  TCP port scanning
-  Multithreaded scanning with `ThreadPoolExecutor`
-  Common service identification
-  Banner grabbing
-  HTTP response inspection
-  HTTPS / TLS inspection
-  TLS certificate information
-  Modular OOP architecture
-  Clean terminal output

---

## 🛠️ Technologies

- Python 3
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
