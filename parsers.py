class HTTPParsers:

    def parse(self, response):

        if not response or response == "Unknown":
            return {
                "status_code": "Unknown",
                "status": "Unknown",
                "server": "Unknown",
                "content_type": "Unknown"
            }

        lines = response.splitlines()

        status_code = "Unknown"
        status = "Unknown"
        server = "Unknown"
        content_type = "Unknown"

        if lines:

            parts = lines[0].split()

            if len(parts) >= 2:

                status_code = parts[1]

                if len(parts) >= 3:

                    status = " ".join(parts[2:])

        for line in lines[1:]:

            if ":" not in line:
                continue

            key, value = line.split(
                ":",
                1
            )

            key = key.strip().lower()
            value = value.strip()

            if key == "server":

                server = value

            elif key == "content_type":

                content_type = value

        return {
            "status_code": status_code,
            "status": status,
            "server": server,
            "content_type": content_type
        }


class TLSParser:

    def parse_certificate(self, certificate):

        if not certificate:

            return {
                "subject": "Unknown",
                "issuer": "Unknown",
                "valid_from": "Unknown",
                "valid_until": "Unknown",
                "san": []
            }

        subject = certificate.get("subject", ())
        issuer = certificate.get("issuer", ())

        subject_name = "Unknown"
        issuer_name = "Unknown"

        for item in subject:
            for key, value in item:
                if key == "commonName":
                    subject_name = value

        for item in issuer:
            for key, value in item:
                if key == "commonName":
                    issuer_name = value

        valid_from = certificate.get(
            "notBefore",
            "Unknown"
        )

        valid_until = certificate.get(
            "notAfter",
            "Unknown"
        )

        san = certificate.get(
            "subjectAltName",
            ()
        )

        san_names = []

        for name_type, name in san:
            if name_type == "DNS":
                san_names.append(name)

        return {
            "subject": subject_name,
            "issuer": issuer_name,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "san": san_names
        }
