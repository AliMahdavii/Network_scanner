import socket
import ssl

from banner_grabber import BannerGrabber


class HTTPScanner:

    def grab_http_banner(self, ip, port):

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


class ServiceDetector:

    def __init__(self):
        self.banner_grabber = BannerGrabber()
        self.http_scanner = HTTPScanner()
        self.tls_scanner = TLSScanner()

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

    def get_service_name(self, port):
        return self.common_services.get(
            port,
            "Unknown"
        )

    def detect_service(self, ip, port):

        service = self.get_service_name(port)

        if service == "HTTPS":
            return self.tls_scanner.grab_https_banner(ip, port)

        if service == "HTTP":
            return self.http_scanner.grab_http_banner(ip, port)

        return self.banner_grabber.grab_banner(ip, port)


class TLSScanner:

    def grab_https_banner(self, ip, port):

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (str(ip), port),
                timeout=2,
            ) as raw_sock:

                with context.wrap_socket(
                    raw_sock,
                    server_hostname=str(ip)
                ) as sock:

                    return {
                        "tls_version": sock.version(),
                        "cipher": sock.cipher(),
                        "certificate": sock.getpeercert()
                    }

        except (
            socket.timeout,
            socket.error,
            ssl.SSLError
        ):
            return "Unknown"
