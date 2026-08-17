import socket
import ipaddress
import subprocess
import ssl

from concurrent.futures import ThreadPoolExecutor

# Network

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.connect(("8.8.8.8", 80))

local_ip = sock.getsockname()[0]

sock.close()


network = ipaddress.ip_network(local_ip + "/24", strict=False)

# Ping


def ping(ip):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", str(ip)],
        stdout=subprocess.DEVNULL
    )

    return result.returncode == 0


# Hostname
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"


# ARP Table
def get_arp_table():
    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True
    )

    lines = result.stdout.splitlines()

    arp_table = {}

    for line in lines:

        line = line.strip()
        parts = line.split()

        if len(parts) >= 3 and parts[2] in ["dynamic", "static"]:

            ip = parts[0]
            mac = parts[1]

            arp_table[ip] = mac

    return arp_table


# Host scanner

online_hosts = []


def scan_host(ip):

    if ping(ip):

        hostname = get_hostname(ip)

        online_hosts.append({
            "ip": str(ip),
            "hostname": hostname
        })

# Port scanner


def validate_port(port):
    if 0 <= port <= 65535:
        return True

    print("\nPort must be between 0 and 65535!\n")
    return False


def get_port_range():

    while True:
        try:
            start_port = int(input("Start port: "))

            if not validate_port(start_port):
                continue

            break

        except ValueError:
            print("\nPlease enter a valid number!\n")

    while True:
        try:
            end_port = int(input("End port: "))

            if not validate_port(end_port):
                continue

            break

        except ValueError:
            print("\nPlease enter a valid number!\n")

    return range(start_port, end_port + 1)


common_services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP"
}


def get_service_name(port):
    return common_services.get(
        port,
        "Unknown"
    )


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(1)

    result = sock.connect_ex((str(ip), port))

    sock.close()

    return result == 0


def scan_port_tread(ip, port):
    if scan_port(ip, port):
        return port

    return None


def scan_ports(ip, ports):

    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as executor:

        results = executor.map(
            lambda port: scan_port_tread(ip, port),
            ports
        )

        for port in results:

            if port is not None:
                open_ports.append(port)

    return open_ports


def grab_banner(ip, port):

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((str(ip), port))

        banner = sock.recv(1024)

        sock.close()

        return banner.decode(errors="ignore").strip()

    except (socket.timeout, socket.error):

        return "Unknown"


def grab_http_banner(ip, port):
    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        sock.connect((str(ip), port))

        request = (
            "HEAD / HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(request.encode())

        response = sock.recv(4096)

        sock.close()

        return response.decode(errors="ignore").strip()

    except (socket.timeout, socket.error):
        return "Unknown"


def parse_http_response(response):
    if not response or response == "Unknown":
        return {
            "status_code": "Unknown",
            "status": "Unknown",
            "server": "Unknown",
            "content_type": "Unknown"
        }

    lines = response.splitlines()

    status_code = "Unknown"
    status = "Unknown"
    server = "Unknown"
    content_type = "Unknown"

    if lines:
        parts = lines[0].split()

        if len(parts) >= 2:
            status_code = parts[1]

            if len(parts) >= 3:
                status = " ".join(parts[2:])

    for line in lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1
        )

        key = key.strip().lower()
        value = value.strip()

        if key == "server":
            server = value

        elif key == "content_type":
            content_type = value

    return {
        "status_code": status_code,
        "status": status,
        "server": server,
        "content_type": content_type
    }


def grab_https_banner(ip, port):
    try:
        sock = socket.create_connection(
            (str(ip), port),
            timeout=2
        )

        # First try: HEAD
        request = (
            "HEAD / HTTP/1.0\r\n"
            f"Host: {ip}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(request.encode())

        response = sock.recv(4096).decode(errors="ignore")

        sock.close()

        # If HEAD is rejected, try GET
        if "400 Bad Request" in response or "405 Method Not Allowed" in response:
            sock = socket.create_connection(
                (str(ip), port),
                timeout=2
            )

            request = (
                "GET / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            sock.sendall(request.encode())

            response = sock.recv(4096).decode(errors="ignore")

            sock.close()

        return response

    except (socket.timeout, socket.error):
        return "Unknown"


def parse_certificate(certificate):

    if not certificate:
        return {
            "subject": "Unknown",
            "issuer": "Unknown",
            "valid_from": "Unknown",
            "valid_until": "Unknown",
            "san": []
        }

    subject = certificate.get("subject", ())
    issuer = certificate.get("issuer", ())

    subject_name = "Unknown"
    issuer_name = "Unknown"

    for item in subject:
        for key, value in item:
            if key == "commonName":
                subject_name = value

    for item in issuer:
        for key, value in item:
            if key == "commonName":
                issuer_name = value

    valid_from = certificate.get(
        "notBefore",
        "Unknown"
    )

    valid_until = certificate.get(
        "notAfter",
        "Unknown"
    )

    san = certificate.get(
        "subjectAltName",
        ()
    )

    san_names = []

    for name_type, name in san:
        if name_type == "DNS":
            san_names.append(name)

    return {
        "subject": subject_name,
        "issuer": issuer_name,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "san": san_names
    }


def detect_service(ip, port):

    service = get_service_name(port)

    if service == "HTTPS":
        return grab_https_banner(ip, port)

    if service == "HTTP":
        return grab_http_banner(ip, port)

    return grab_banner(ip, port)


# Scan network


print("=" * 65)
print("                            NETWORK SCANNER")
print("=" * 65)

print()

print("Local IP: ", local_ip)
print("Network: ", network)
print("Netmask: ", network.netmask)
print("Broadcast: ", network.broadcast_address)

print("\nScanning...\n")

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(scan_host, network.hosts())

# Get mac addresses

arp_table = get_arp_table()

for host in online_hosts:

    ip = host["ip"]

    host["mac"] = arp_table.get(
        ip,
        "Unknown"
    )

# scan ports

ports = get_port_range()

print()
print("Scanning ports...")
print()

for host in online_hosts:

    ip = host["ip"]

    host["open_ports"] = scan_ports(ip, ports)

    host["services"] = {}
    host["banners"] = {}

    for port in host["open_ports"]:
        host["services"][port] = get_service_name(port)

        host["banners"][port] = detect_service(ip, port)


# Display results

print("IP ADDRESS".ljust(18), end="")
print("HOSTNAME".ljust(21), end="")
print("MAC ADDRESS")

print("-" * 65)


for host in online_hosts:

    print(
        host["ip"].ljust(18),
        host["hostname"].ljust(21),
        host["mac"].ljust(22)
    )

    for port, service in host["services"].items():

        banner = host["banners"].get(
            port,
            "Unknown"
        )

        if isinstance(banner, dict):

            print(
                " " * 18,
                f"{port:<6}",
                service,
                "| TLS:",
                banner["tls_version"]
            )

            print(
                " " * 25,
                "Cipher:",
                banner["cipher"][0]
            )

            certificate_info = parse_certificate(
                banner["certificate"]
            )

            print(
                " " * 25,
                "Subject:",
                certificate_info["subject"]
            )

            print(
                " " * 25,
                "Issuer:",
                certificate_info["issuer"]
            )

            print(
                " " * 25,
                "Valid From:",
                certificate_info["valid_from"]
            )

            print(
                " " * 25,
                "Valid Until:",
                certificate_info["valid_until"]
            )

            print(
                " " * 25,
                "SAN:",
                ", ".join(certificate_info["san"])
            )

        else:

            http_info = parse_http_response(banner)

            print(
                " " * 18,
                f"{port:<6}",
                service,
                "|",
                http_info["status_code"],
                http_info["status"]
            )

            print(
                " " * 25,
                "Server:",
                http_info["server"]
            )

            print(
                " " * 25,
                "Content-Type:",
                http_info["content_type"]
            )

print()
print("-" * 65)

print(
    len(online_hosts),
    "hosts found"
)

print("=" * 65)
