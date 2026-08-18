import socket


class BannerGrabber:

    def grab_banner(self, ip, port):

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
