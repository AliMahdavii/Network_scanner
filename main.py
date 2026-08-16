import socket
import ipaddress
import subprocess

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
    3389: "RDP"
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

    for port in host["open_ports"]:
        host["services"][port] = get_service_name(port)


# Display results

print("IP ADDRESS".ljust(18), end="")
print("HOSTNAME".ljust(21), end="")
print("MAC ADDRESS".ljust(22), end="")
print("OPEN PORTS")

print("-" * 80)


for host in online_hosts:

    print(
        host["ip"].ljust(18),
        host["hostname"].ljust(21),
        host["mac"].ljust(22)
    )

    for port, service in host["services"].items():
        print(
            " " * 18,
            f"{port:<6}",
            service
        )

print()
print("-" * 80)

print(
    len(online_hosts),
    "hosts found"
)

print("=" * 80)
