import socket
import ssl
from datetime import datetime, timezone


def get_tls_info(domain):
    result = {
        "tls_version": None,
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "expired": None,
        "san": [],
        "error": None
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as tls_socket:

                certificate = tls_socket.getpeercert()

                result["tls_version"] = (
                    tls_socket.version()
                )

                # Certificate subject
                subject_parts = []

                for group in certificate.get(
                    "subject", []
                ):
                    for key, value in group:
                        subject_parts.append(
                            f"{key}={value}"
                        )

                result["subject"] = ", ".join(
                    subject_parts
                )

                # Certificate issuer
                issuer_parts = []

                for group in certificate.get(
                    "issuer", []
                ):
                    for key, value in group:
                        issuer_parts.append(
                            f"{key}={value}"
                        )

                result["issuer"] = ", ".join(
                    issuer_parts
                )

                # Certificate validity
                valid_from = datetime.strptime(
                    certificate["notBefore"],
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                valid_until = datetime.strptime(
                    certificate["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                result["valid_from"] = (
                    valid_from.isoformat()
                )

                result["valid_until"] = (
                    valid_until.isoformat()
                )

                now = datetime.now(timezone.utc)

                days_remaining = (
                    valid_until - now
                ).days

                result["days_until_expiry"] = (
                    days_remaining
                )

                result["expired"] = (
                    valid_until < now
                )

                # Subject Alternative Names
                result["san"] = [
                    value
                    for key, value in certificate.get(
                        "subjectAltName", []
                    )
                    if key == "DNS"
                ]

    except Exception as error:
        result["error"] = str(error)

    return result