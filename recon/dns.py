import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME"
]


def get_dns_records(domain):
    results = {}

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            results[record_type] = [
                answer.to_text()
                for answer in answers
            ]

        except dns.resolver.NoAnswer:
            results[record_type] = []

        except dns.resolver.NXDOMAIN:
            results[record_type] = []

        except dns.resolver.NoNameservers:
            results[record_type] = []

        except Exception:
            results[record_type] = []

    return results


def extract_ips(records):
    ips = []

    for ip in records.get("A", []):
        if ip not in ips:
            ips.append(ip)

    for ip in records.get("AAAA", []):
        if ip not in ips:
            ips.append(ip)

    return ips