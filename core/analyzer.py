from core.evidence import EvidenceManager


def analyze_security_headers(header_results, manager):
    """
    Analyze HTTP security headers and create
    evidence records for observed conditions.
    """

    header_info = {
        "Strict-Transport-Security": {
            "observation_present": "Strict-Transport-Security was observed.",
            "observation_missing": "Strict-Transport-Security was not observed.",
            "significance": (
                "HSTS can help enforce HTTPS connections "
                "for supporting browsers."
            ),
            "recommendation": (
                "Review whether HSTS is appropriate for "
                "the application and its deployment."
            )
        },

        "Content-Security-Policy": {
            "observation_present": "Content-Security-Policy was observed.",
            "observation_missing": "Content-Security-Policy was not observed.",
            "significance": (
                "CSP can provide an additional browser-side "
                "security control over content sources."
            ),
            "recommendation": (
                "Review whether an appropriate CSP is "
                "suitable for the application."
            )
        },

        "X-Frame-Options": {
            "observation_present": "X-Frame-Options was observed.",
            "observation_missing": "X-Frame-Options was not observed.",
            "significance": (
                "This header can help control whether a page "
                "may be embedded in a frame."
            ),
            "recommendation": (
                "Review framing requirements and consider "
                "appropriate anti-framing controls."
            )
        },

        "X-Content-Type-Options": {
            "observation_present": "X-Content-Type-Options was observed.",
            "observation_missing": "X-Content-Type-Options was not observed.",
            "significance": (
                "This header can reduce MIME-type sniffing "
                "behavior in supporting browsers."
            ),
            "recommendation": (
                "Review whether the nosniff directive is "
                "appropriate for the application."
            )
        },

        "Referrer-Policy": {
            "observation_present": "Referrer-Policy was observed.",
            "observation_missing": "Referrer-Policy was not observed.",
            "significance": (
                "Referrer-Policy controls how much referrer "
                "information browsers send."
            ),
            "recommendation": (
                "Review whether the application's desired "
                "referrer disclosure policy is defined."
            )
        },

        "Permissions-Policy": {
            "observation_present": "Permissions-Policy was observed.",
            "observation_missing": "Permissions-Policy was not observed.",
            "significance": (
                "Permissions-Policy can control access to "
                "selected browser capabilities."
            ),
            "recommendation": (
                "Review whether browser feature permissions "
                "should be explicitly restricted."
            )
        }
    }

    for header, result in header_results.items():

        if header not in header_info:
            continue

        info = header_info[header]

        if result["present"]:

            observation = info["observation_present"]

            evidence_text = (
                f"Header: {header}\n"
                f"Value: {result['value']}"
            )

        else:

            observation = info["observation_missing"]

            evidence_text = (
                f"Header: {header}\n"
                f"Value: Not Present"
            )

        manager.add(
            source="HTTP Response Headers",
            observation=observation,
            evidence=evidence_text,
            significance=info["significance"],
            confidence="HIGH",
            recommendation=info["recommendation"]
        )
def analyze_tls(tls_info, manager):
    """
    Analyze TLS reconnaissance results and create
    evidence records.
    """

    if tls_info["error"]:
        manager.add(
            source="TLS Certificate",
            observation="TLS reconnaissance could not be completed.",
            evidence=f"Error: {tls_info['error']}",
            significance=(
                "The TLS configuration could not be fully "
                "observed during reconnaissance."
            ),
            confidence="HIGH",
            recommendation=(
                "Review TLS connectivity and certificate "
                "configuration."
            )
        )

        return

    # --------------------------------------------------
    # TLS Version
    # --------------------------------------------------

    tls_version = tls_info["tls_version"]

    if tls_version:

        manager.add(
            source="TLS Configuration",
            observation=(
                f"The target presented {tls_version}."
            ),
            evidence=(
                f"TLS Version: {tls_version}"
            ),
            significance=(
                "The observed TLS version describes the "
                "protocol used for the HTTPS connection."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify that the deployed TLS versions "
                "match the organization's security policy."
            )
        )

    # --------------------------------------------------
    # Certificate Expiration
    # --------------------------------------------------

    if tls_info["expired"]:

        manager.add(
            source="TLS Certificate",
            observation=(
                "The presented TLS certificate is expired."
            ),
            evidence=(
                f"Valid Until: {tls_info['valid_until']}\n"
                f"Expired: {tls_info['expired']}"
            ),
            significance=(
                "An expired certificate can cause browser "
                "trust warnings and disrupt HTTPS trust."
            ),
            confidence="HIGH",
            recommendation=(
                "Renew the certificate and verify that the "
                "renewed certificate is correctly deployed."
            )
        )

    else:

        manager.add(
            source="TLS Certificate",
            observation=(
                "The presented TLS certificate is currently valid."
            ),
            evidence=(
                f"Valid Until: {tls_info['valid_until']}\n"
                f"Days Until Expiry: "
                f"{tls_info['days_until_expiry']}"
            ),
            significance=(
                "Certificate validity provides evidence that "
                "the presented certificate has not expired."
            ),
            confidence="HIGH",
            recommendation=(
                "Continue monitoring certificate expiration "
                "to prevent future service disruption."
            )
        )

    # --------------------------------------------------
    # Certificate Issuer
    # --------------------------------------------------

    if tls_info["issuer"]:

        manager.add(
            source="TLS Certificate",
            observation=(
                "A certificate issuer was identified."
            ),
            evidence=(
                f"Issuer: {tls_info['issuer']}"
            ),
            significance=(
                "The certificate issuer identifies the "
                "certificate authority information presented "
                "by the server."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify that the certificate authority is "
                "expected for the deployment."
            )
        )

    # --------------------------------------------------
    # Subject Alternative Names
    # --------------------------------------------------

    if tls_info["san"]:

        manager.add(
            source="TLS Certificate",
            observation=(
                "Subject Alternative Names were observed "
                "in the certificate."
            ),
            evidence=(
                "Subject Alternative Names:\n" +
                "\n".join(
                    f"- {name}"
                    for name in tls_info["san"]
                )
            ),
            significance=(
                "Certificate SAN entries can reveal domain "
                "names associated with the certificate."
            ),
            confidence="HIGH",
            recommendation=(
                "Review certificate names and verify that "
                "all listed domains are expected."
            )
        )
def analyze_dns(records, ips, manager):


    # --------------------------------------------------
    # Resolved IP Addresses
    # --------------------------------------------------

    if ips:

        manager.add(
            source="DNS",
            observation=(
                f"The target resolved to {len(ips)} "
                f"IP address(es)."
            ),
            evidence=(
                "Resolved IP addresses:\n" +
                "\n".join(
                    f"- {ip}"
                    for ip in ips
                )
            ),
            significance=(
                "Resolved IP addresses provide evidence of "
                "the network endpoints associated with the "
                "observed domain."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify that all observed IP addresses "
                "belong to expected infrastructure."
            )
        )

    else:

        manager.add(
            source="DNS",
            observation=(
                "No IP addresses were resolved for the target."
            ),
            evidence=(
                "No A or AAAA address was observed."
            ),
            significance=(
                "The target did not produce an observable "
                "IP address during DNS reconnaissance."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify DNS configuration if the domain "
                "is expected to resolve."
            )
        )

    # --------------------------------------------------
    # DNS Record Types
    # --------------------------------------------------

 

    

    for record_type, values in records.items():

        if not values:
            continue

        # Remove invalid / placeholder DNS values
        valid_values = []

        for value in values:

            if value is None:
                continue

            value = str(value).strip()

            if not value:
                continue

            # Ignore common null MX representation
            if record_type == "MX" and value in ["0 .", "0."]:
                continue

            valid_values.append(value)

        if not valid_values:
            continue

        manager.add(
            source="DNS",
            observation=(
                f"{record_type} records were observed."
            ),
            evidence=(
                f"{record_type} Records:\n" +
                "\n".join(
                    f"- {value}"
                    for value in valid_values
                )
            ),
            significance=(
                f"{record_type} records provide information "
                f"about the domain's DNS configuration."
            ),
            confidence="HIGH",
            recommendation=(
                f"Review the observed {record_type} records "
                f"and verify that they correspond to "
                f"expected infrastructure."
            )
        )
        
def analyze_robots(robots_info, manager):
    """
    Analyze robots.txt reconnaissance results
    and create evidence records.
    """

    # --------------------------------------------------
    # robots.txt availability
    # --------------------------------------------------

    if robots_info["error"]:

        manager.add(
            source="robots.txt",
            observation=(
                "robots.txt could not be retrieved."
            ),
            evidence=(
                f"URL: {robots_info['url']}\n"
                f"Error: {robots_info['error']}"
            ),
            significance=(
                "The robots.txt resource could not be "
                "observed during reconnaissance."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify the resource manually if it is "
                "expected to be publicly available."
            )
        )

        return

    # --------------------------------------------------
    # robots.txt exists
    # --------------------------------------------------

    if robots_info["exists"]:

        manager.add(
            source="robots.txt",
            observation=(
                "robots.txt was publicly accessible."
            ),
            evidence=(
                f"URL: {robots_info['url']}\n"
                f"Status Code: {robots_info['status_code']}"
            ),
            significance=(
                "robots.txt can provide information about "
                "crawler directives and publicly disclosed "
                "site paths."
            ),
            confidence="HIGH",
            recommendation=(
                "Review robots.txt contents to ensure that "
                "sensitive or unnecessary information is "
                "not being disclosed."
            )
        )

    else:

        manager.add(
            source="robots.txt",
            observation=(
                "robots.txt was not observed at the "
                "checked location."
            ),
            evidence=(
                f"URL: {robots_info['url']}\n"
                f"Status Code: {robots_info['status_code']}"
            ),
            significance=(
                "The standard robots.txt resource was not "
                "available at the checked location."
            ),
            confidence="HIGH",
            recommendation=(
                "No action is required unless robots.txt "
                "is expected as part of the site's "
                "crawler-management strategy."
            )
        )

    # --------------------------------------------------
    # Disallowed paths
    # --------------------------------------------------

    if robots_info["disallow"]:

        paths = "\n".join(
            f"- [{entry['user_agent']}] {entry['path']}"
            for entry in robots_info["disallow"]
        )

        manager.add(
            source="robots.txt",
            observation=(
                f"{len(robots_info['disallow'])} "
                "disallowed path(s) were publicly disclosed."
            ),
            evidence=(
                f"Disallowed Paths:\n{paths}"
            ),
            significance=(
                "Disallowed paths reveal crawler directives "
                "and may expose names or locations of "
                "interesting application resources."
            ),
            confidence="HIGH",
            recommendation=(
                "Review disclosed paths and ensure that "
                "access control does not rely on robots.txt."
            )
        )

    # --------------------------------------------------
    # Sitemap references
    # --------------------------------------------------

    if robots_info["sitemaps"]:

        sitemaps = "\n".join(
            f"- {sitemap}"
            for sitemap in robots_info["sitemaps"]
        )

        manager.add(
            source="robots.txt",
            observation=(
                "Sitemap references were observed."
            ),
            evidence=(
                f"Sitemaps:\n{sitemaps}"
            ),
            significance=(
                "Sitemap references can provide additional "
                "public URL discovery information."
            ),
            confidence="HIGH",
            recommendation=(
                "Review referenced sitemaps as part of "
                "authorized reconnaissance."
            )
        )
def analyze_whois(whois_info, manager):
    """
    Analyze domain registration information
    and create evidence records.
    """

    # --------------------------------------------------
    # WHOIS error
    # --------------------------------------------------

    if whois_info["error"]:

        manager.add(
            source="Domain Registration",
            observation=(
                "Domain registration information "
                "could not be retrieved."
            ),
            evidence=(
                f"Error: {whois_info['error']}"
            ),
            significance=(
                "Registration information was not "
                "available during reconnaissance."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify registration information through "
                "an authorized registration data source."
            )
        )

        return

    # --------------------------------------------------
    # Registrar
    # --------------------------------------------------

    if whois_info["registrar"]:

        manager.add(
            source="Domain Registration",
            observation=(
                "A domain registrar was identified."
            ),
            evidence=(
                f"Registrar: {whois_info['registrar']}"
            ),
            significance=(
                "The registrar identifies the organization "
                "through which the domain registration "
                "was observed."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify that the observed registrar "
                "matches the expected domain registration."
            )
        )

    # --------------------------------------------------
    # Creation Date
    # --------------------------------------------------

    if whois_info["creation_date"]:

        manager.add(
            source="Domain Registration",
            observation=(
                "A domain creation date was observed."
            ),
            evidence=(
                f"Creation Date: "
                f"{whois_info['creation_date']}"
            ),
            significance=(
                "The creation date provides lifecycle "
                "information about the observed domain."
            ),
            confidence="HIGH",
            recommendation=(
                "Retain the observed date as part of the "
                "domain's reconnaissance record."
            )
        )

    # --------------------------------------------------
    # Expiration Date
    # --------------------------------------------------

    if whois_info["expiration_date"]:

        manager.add(
            source="Domain Registration",
            observation=(
                "A domain expiration date was observed."
            ),
            evidence=(
                f"Expiration Date: "
                f"{whois_info['expiration_date']}"
            ),
            significance=(
                "The expiration date provides information "
                "about the registration lifecycle of the domain."
            ),
            confidence="HIGH",
            recommendation=(
                "Monitor the registration lifecycle and "
                "renewal status where appropriate."
            )
        )

    # --------------------------------------------------
    # Name Servers
    # --------------------------------------------------

    if whois_info["name_servers"]:

        manager.add(
            source="Domain Registration",
            observation=(
                f"{len(whois_info['name_servers'])} "
                "name server(s) were observed."
            ),
            evidence=(
                "Name Servers:\n" +
                "\n".join(
                    f"- {server}"
                    for server in whois_info["name_servers"]
                )
            ),
            significance=(
                "Name servers provide information about "
                "the DNS infrastructure associated with "
                "the domain."
            ),
            confidence="HIGH",
            recommendation=(
                "Verify that the observed name servers "
                "belong to expected infrastructure."
            )
        )

    # --------------------------------------------------
    # Domain Status
    # --------------------------------------------------

    if whois_info["status"]:

        manager.add(
            source="Domain Registration",
            observation=(
                f"{len(whois_info['status'])} "
                "domain registration status value(s) "
                "were observed."
            ),
            evidence=(
                "Domain Status:\n" +
                "\n".join(
                    f"- {status}"
                    for status in whois_info["status"]
                )
            ),
            significance=(
                "Registration status values provide "
                "information about the current domain "
                "registration state."
            ),
            confidence="HIGH",
            recommendation=(
                "Review the observed registration status "
                "values against the expected domain state."
            )
        )
def analyze_sitemap(sitemap_info, manager):
    """
    Analyze sitemap reconnaissance results
    and create evidence records.
    """

    # --------------------------------------------------
    # Sitemap retrieval error
    # --------------------------------------------------

    if sitemap_info["error"]:

        manager.add(
            source="Sitemap",
            observation=(
                "The sitemap could not be retrieved "
                "or parsed."
            ),
            evidence=(
                f"URL: {sitemap_info['url']}\n"
                f"Error: {sitemap_info['error']}"
            ),
            significance=(
                "The sitemap resource could not be "
                "reliably observed during reconnaissance."
            ),
            confidence="HIGH",
            recommendation=(
                "Review the sitemap manually if the "
                "application is expected to publish one."
            )
        )

        return

    # --------------------------------------------------
    # Sitemap not found
    # --------------------------------------------------

    if not sitemap_info["exists"]:

        manager.add(
            source="Sitemap",
            observation=(
                "A sitemap was not observed at the "
                "checked location."
            ),
            evidence=(
                f"URL: {sitemap_info['url']}\n"
                f"Status Code: {sitemap_info['status_code']}"
            ),
            significance=(
                "No sitemap was available at the "
                "checked location."
            ),
            confidence="HIGH",
            recommendation=(
                "No action is required unless a sitemap "
                "is expected as part of the application's "
                "public site structure."
            )
        )

        return

    # --------------------------------------------------
    # URL Sitemap
    # --------------------------------------------------

    if sitemap_info["type"] == "URL Sitemap":

        manager.add(
            source="Sitemap",
            observation=(
                f"A URL sitemap containing "
                f"{sitemap_info['url_count']} URL(s) "
                f"was observed."
            ),
            evidence=(
                f"URL: {sitemap_info['url']}\n"
                f"URL Count: {sitemap_info['url_count']}"
            ),
            significance=(
                "A sitemap can provide a structured view "
                "of publicly referenced application URLs."
            ),
            confidence="HIGH",
            recommendation=(
                "Review publicly listed URLs and verify "
                "that sensitive or unintended resources "
                "are not being exposed through the sitemap."
            )
        )

        return

    # --------------------------------------------------
    # Sitemap Index
    # --------------------------------------------------

    if sitemap_info["type"] == "Sitemap Index":

        manager.add(
            source="Sitemap",
            observation=(
                f"A sitemap index containing "
                f"{sitemap_info['url_count']} "
                f"child sitemap(s) was observed."
            ),
            evidence=(
                f"URL: {sitemap_info['url']}\n"
                f"Child Sitemaps: "
                f"{sitemap_info['url_count']}"
            ),
            significance=(
                "A sitemap index can provide additional "
                "information about the site's publicly "
                "referenced URL structure."
            ),
            confidence="HIGH",
            recommendation=(
                "Review the referenced child sitemaps "
                "and verify that they expose only "
                "intended public resources."
            )
        )