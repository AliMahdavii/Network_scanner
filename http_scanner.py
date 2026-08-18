import socket


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
