import socket
import ssl


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
