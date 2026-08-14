def assess_change_impact(change):
    """
    Assess the security impact of a logical change.
    """

    source = change.get("source", "").upper()
    category = change.get("category", "").lower()
    change_type = change.get("type", "").upper()

    # --------------------------------------------------
    # SECURITY HEADERS
    # --------------------------------------------------

    if source == "SECURITY_HEADERS":

        if change_type == "REMOVED":

            return {
                "severity": "HIGH",
                "confidence": "HIGH",
                "impact": (
                    "A previously observed security header "
                    "is no longer present."
                ),
                "recommendation": (
                    "Verify whether the header was intentionally "
                    "removed and review the current web security configuration."
                )
            }

        if change_type == "CHANGED":

            return {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "impact": (
                    "A security header value changed between scans."
                ),
                "recommendation": (
                    "Review the new header value and confirm "
                    "that the security policy remains appropriate."
                )
            }

    # --------------------------------------------------
    # TLS
    # --------------------------------------------------

    if source == "TLS":

        if "version" in category:

            return {
                "severity": "HIGH",
                "confidence": "HIGH",
                "impact": (
                    "The observed TLS protocol configuration changed."
                ),
                "recommendation": (
                    "Verify that the new TLS configuration "
                    "uses an approved and secure protocol version."
                )
            }

        if "certificate" in category:

            return {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "impact": (
                    "A certificate-related property changed."
                ),
                "recommendation": (
                    "Verify the certificate change and confirm "
                    "that the certificate remains valid and trusted."
                )
            }

    # --------------------------------------------------
    # DNS
    # --------------------------------------------------

    if source == "DNS":

        if "ipv6" in category or "ip address" in category:

            return {
                "severity": "LOW",
                "confidence": "HIGH",
                "impact": (
                    "The observable IP address associated "
                    "with the target changed."
                ),
                "recommendation": (
                    "Verify whether the infrastructure or "
                    "deployment change was expected."
                )
            }

        if "ns" in category.lower() or "name server" in category.lower():

            return {
                "severity": "HIGH",
                "confidence": "HIGH",
                "impact": (
                    "The authoritative DNS infrastructure "
                    "associated with the target changed."
                ),
                "recommendation": (
                    "Verify the nameserver change and confirm "
                    "that the authoritative DNS configuration is expected."
                )
            }

    # --------------------------------------------------
    # HTTP
    # --------------------------------------------------

    if source == "HTTP":

        if "status" in category:

            return {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "impact": (
                    "The HTTP response status changed between scans."
                ),
                "recommendation": (
                    "Review the affected endpoint and determine "
                    "whether the status change was expected."
                )
            }

        if "server" in category:

            return {
                "severity": "LOW",
                "confidence": "MEDIUM",
                "impact": (
                    "The observable HTTP server information changed."
                ),
                "recommendation": (
                    "Verify whether the infrastructure or "
                    "web-server configuration changed intentionally."
                )
            }

    # --------------------------------------------------
    # DEFAULT
    # --------------------------------------------------

    return {
        "severity": "INFO",
        "confidence": "MEDIUM",
        "impact": (
            "An observable reconnaissance attribute "
            "changed between scans."
        ),
        "recommendation": (
            "Review the change and determine whether "
            "it was expected."
        )
    }