from network_info import NetworkInfo
from host_scanner import HostScanner
from port_scanner import PortScanner

from scanner import (
    ServiceDetector
)

from formatter import ResultFormatter

from concurrent.futures import ThreadPoolExecutor


class NetworkScanner:

    def __init__(self):

        self.network_info = NetworkInfo()

        self.host_scanner = HostScanner()

        self.port_scanner = PortScanner()

        self.service_detector = ServiceDetector()

        self.formatter = ResultFormatter()

    def scan_hosts(self):

        with ThreadPoolExecutor(
            max_workers=20
        ) as executor:

            executor.map(
                self.host_scanner.scan_host,
                self.network_info.network.hosts()
            )

    def get_mac_address(self):

        arp_table = self.host_scanner.get_arp_table()

        for host in self.host_scanner.online_hosts:

            ip = host["ip"]

            host["mac"] = arp_table.get(
                ip,
                "Unknown"
            )

    def scan_ports(self, ports):

        for host in self.host_scanner.online_hosts:

            ip = host["ip"]

            host["open_ports"] = self.port_scanner.scan_ports(ip, ports)

            host["services"] = {}
            host["banners"] = {}

            for port in host["open_ports"]:
                host["services"][port] = self.service_detector.get_service_name(
                    port)

                host["banners"][port] = self.service_detector.detect_service(
                    ip, port)

    def display_results(self):

        self.formatter.print_hosts(self.host_scanner.online_hosts)

        for host in self.host_scanner.online_hosts:

            self.formatter.print_services(host)

        self.formatter.print_footer(self.host_scanner.online_hosts)

    def run(self):

        self.formatter.print_header(self.network_info)

        self.scan_hosts()

        self.get_mac_address()

        ports = self.port_scanner.get_port_range()

        self.scan_ports(ports)

        self.display_results()
