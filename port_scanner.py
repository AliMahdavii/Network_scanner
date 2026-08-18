import socket

from concurrent.futures import ThreadPoolExecutor


class PortScanner:

    def validate_port(self, port):

        if 0 <= port <= 65535:
            return True

        print("\nPort must be between 0 and 65535!\n")
        return False

    def get_port_range(self):

        while True:
            try:
                start_port = int(input("Start port: "))

                if not self.validate_port(start_port):
                    continue

                break

            except ValueError:
                print("\nPlease enter a valid number!\n")

        while True:
            try:
                end_port = int(input("End port: "))

                if not self.validate_port(end_port):
                    continue

                break

            except ValueError:
                print("\nPlease enter a valid number!\n")

        print()
        print("Scanning ports...")
        print()

        return range(start_port, end_port + 1)

    def scan_port(self, ip, port):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(1)

        result = sock.connect_ex((str(ip), port))

        sock.close()

        return result == 0

    def scan_port_thread(self, ip, port):

        if self.scan_port(ip, port):
            return port

        return None

    def scan_ports(self, ip, ports):

        open_ports = []

        with ThreadPoolExecutor(max_workers=20) as executor:

            results = executor.map(
                lambda port: self.scan_port_thread(ip, port),
                ports
            )

            for port in results:

                if port is not None:
                    open_ports.append(port)

        return open_ports
