import socket
import ipaddress
import subprocess
import ssl

from scanner import (
    NetworkInfo,
    HostScanner,
    PortScanner,
    ServiceDetector
)

from concurrent.futures import ThreadPoolExecutor

network_info = NetworkInfo()

host_scanner = HostScanner()

port_scanner = PortScanner()

service_detectore = ServiceDetector()


local_ip = network_info.local_ip

network = network_info.network


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
    executor.map(host_scanner.scan_host, network.hosts())


# Get mac addresses

arp_table = host_scanner.get_arp_table()

for host in host_scanner.online_hosts:

    ip = host["ip"]

    host["mac"] = arp_table.get(
        ip,
        "Unknown"
    )

# scan ports

ports = port_scanner.get_port_range()

print()
print("Scanning ports...")
print()

for host in host_scanner.online_hosts:

    ip = host["ip"]

    host["open_ports"] = port_scanner.scan_ports(ip, ports)

    host["services"] = {}
    host["banners"] = {}

    for port in host["open_ports"]:
        host["services"][port] = service_detectore.get_service_name(port)

        host["banners"][port] = service_detectore.detect_service(ip, port)


# Display results

print("IP ADDRESS".ljust(18), end="")
print("HOSTNAME".ljust(21), end="")
print("MAC ADDRESS")

print("-" * 65)


for host in host_scanner.online_hosts:

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

            certificate_info = service_detectore.parse_certificate(
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

            http_info = service_detectore.parse_http_response(banner)

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
    len(host_scanner.online_hosts),
    "hosts found"
)

print("=" * 65)
