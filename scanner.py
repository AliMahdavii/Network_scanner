from banner_grabber import BannerGrabber
from http_scanner import HTTPScanner
from tls_scanner import TLSScanner


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
