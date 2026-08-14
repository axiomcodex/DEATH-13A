SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def analyze_security_headers(headers):
    results = {}

    for header in SECURITY_HEADERS:
        value = headers.get(header)

        if value:
            results[header] = {
                "present": True,
                "value": value
            }
        else:
            results[header] = {
                "present": False,
                "value": None
            }

    return results


def get_header_summary(results):
    total = len(results)

    present = sum(
        1
        for result in results.values()
        if result["present"]
    )

    return {
        "total": total,
        "present": present,
        "missing": total - present
    }