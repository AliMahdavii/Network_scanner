from scanner import (
    NetworkInfo,
    HostScanner,
    PortScanner,
    ServiceDetector,
    ResultFormatter
)

from concurrent.futures import ThreadPoolExecutor

network_info = NetworkInfo()

host_scanner = HostScanner()

port_scanner = PortScanner()

service_detector = ServiceDetector()

formatter = ResultFormatter()

# Header

formatter.print_header(network_info)


# Scan hosts

with ThreadPoolExecutor(max_workers=20) as executor:
    executor.map(host_scanner.scan_host, network_info.network.hosts())

# Get MAC addresses

arp_table = host_scanner.get_arp_table()


for host in host_scanner.online_hosts:

    ip = host["ip"]

    host["mac"] = arp_table.get(
        ip,
        "Unknown"
    )


# Get port range

ports = port_scanner.get_port_range()


# Scan ports and services

for host in host_scanner.online_hosts:

    ip = host["ip"]

    host["open_ports"] = port_scanner.scan_ports(ip, ports)

    host["services"] = {}
    host["banners"] = {}

    for port in host["open_ports"]:
        host["services"][port] = service_detector.get_service_name(port)

        host["banners"][port] = service_detector.detect_service(ip, port)


# Display hosts

formatter.print_hosts(host_scanner.online_hosts)


# Display services

for host in host_scanner.online_hosts:

    formatter.print_services(host, service_detector)


# Footer

formatter.print_footer(host_scanner.online_hosts)
