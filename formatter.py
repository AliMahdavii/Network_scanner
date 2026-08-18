class ResultFormatter:

    def print_header(self, network_info):

        print("=" * 65)
        print("                            NETWORK SCANNER")
        print("=" * 65)

        print()

        print("Local IP: ", network_info.local_ip)
        print("Network: ", network_info.network)
        print("Netmask: ", network_info.network.netmask)
        print("Broadcast: ", network_info.network.broadcast_address)

        print("\nScanning...\n")

    def print_hosts(self, hosts):

        print("IP ADDRESS".ljust(18), end="")
        print("HOSTNAME".ljust(21), end="")
        print("MAC ADDRESS")

        print("-" * 65)

        for host in hosts:

            print(
                host["ip"].ljust(18),
                host["hostname"].ljust(21),
                host["mac"].ljust(22)
            )

    def print_footer(self, hosts):

        print()
        print("-" * 65)

        print(
            len(hosts),
            "hosts found"
        )

        print("=" * 65)

    def print_services(self, host, service_detector):

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

                http_info = service_detector.parse_http_response(banner)

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
