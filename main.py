from core.validator import normalize_target
from core.evidence import EvidenceManager

from core.fingerprint import create_fingerprint

from core.analyzer import (
    analyze_security_headers,
    analyze_tls,
    analyze_dns,
    analyze_robots,
    analyze_whois,
    analyze_sitemap
)

from recon.dns import get_dns_records, extract_ips
from recon.http import get_http_info

from recon.security_headers import (
    analyze_security_headers as collect_security_headers,
    get_header_summary
)

from recon.tls import get_tls_info
from recon.whois import get_whois_info
from recon.robots import get_robots_info
from recon.sitemap import get_sitemap_info
from core.storage import (
    save_snapshot,
    get_snapshots,
    load_snapshot
)

from core.change_detector import compare_snapshots

from core.change_analyzer import (
    normalize_changes,
    attach_evidence
)

from core.change_report import display_change_report


def display_dns_results(records):
    print("\n" + "=" * 60)
    print("                    DNS RECON")
    print("=" * 60)

    for record_type, values in records.items():

        print(f"\n{record_type} Records:")

        if values:
            for value in values:
                print(f"  → {value}")
        else:
            print("  → Not found")


def display_http_results(http_info):

    print("\n" + "=" * 60)
    print("                    HTTP RECON")
    print("=" * 60)

    if http_info["error"]:
        print(f"\n[!] HTTP Error: {http_info['error']}")
        return

    print(f"\nStatus Code    : {http_info['status_code']}")
    print(f"Final URL      : {http_info['final_url']}")
    print(f"Server         : {http_info['server'] or 'Not disclosed'}")
    print(
        f"Content-Type   : "
        f"{http_info['content_type'] or 'Not disclosed'}"
    )
    print(
        f"Content-Length : "
        f"{http_info['content_length'] or 'Not disclosed'}"
    )
    print(
        f"Response Time  : "
        f"{http_info['response_time']} seconds"
    )

    if http_info["redirects"]:

        print("\nRedirects:")

        for redirect in http_info["redirects"]:

            print(
                f"  → {redirect['status_code']} "
                f"{redirect['url']} "
                f"→ {redirect['location']}"
            )

    else:
        print("\nRedirects      : None")


def display_security_headers(header_results):

    print("\n" + "=" * 60)
    print("               SECURITY HEADERS")
    print("=" * 60)

    for header, result in header_results.items():

        status = "Observed" if result["present"] else "Not observed"

        print(f"\n{header}")
        print(f"    Status: {status}")

        if result["present"]:
            print(f"    Value : {result['value']}")


def display_tls_results(tls_info):

    print("\n" + "=" * 60)
    print("                    TLS RECON")
    print("=" * 60)

    if tls_info["error"]:

        print(f"\n[!] TLS Error: {tls_info['error']}")
        return

    print(
        f"\nTLS Version        : "
        f"{tls_info['tls_version']}"
    )

    print(
        f"Certificate Subject: "
        f"{tls_info['subject']}"
    )

    print(
        f"Certificate Issuer  : "
        f"{tls_info['issuer']}"
    )

    print(
        f"Valid From          : "
        f"{tls_info['valid_from']}"
    )

    print(
        f"Valid Until         : "
        f"{tls_info['valid_until']}"
    )

    print(
        f"Days Until Expiry   : "
        f"{tls_info['days_until_expiry']}"
    )

    print(
        f"Expired             : "
        f"{tls_info['expired']}"
    )

    print("\nSubject Alternative Names:")

    if tls_info["san"]:

        for name in tls_info["san"]:
            print(f"  → {name}")

    else:
        print("  → None found")


def display_whois_results(whois_info):

    print("\n" + "=" * 60)
    print("              DOMAIN REGISTRATION")
    print("=" * 60)

    if whois_info["error"]:

        print(
            f"\n[!] WHOIS Error: "
            f"{whois_info['error']}"
        )

        return

    print(
        f"\nRegistrar       : "
        f"{whois_info['registrar'] or 'Not available'}"
    )

    print(
        f"Creation Date   : "
        f"{whois_info['creation_date'] or 'Not available'}"
    )

    print(
        f"Expiration Date : "
        f"{whois_info['expiration_date'] or 'Not available'}"
    )

    print(
        f"Updated Date    : "
        f"{whois_info['updated_date'] or 'Not available'}"
    )

    print("\nDomain Status:")

    if whois_info["status"]:

        for status in whois_info["status"]:
            print(f"  → {status}")

    else:
        print("  → None found")

    print("\nName Servers:")

    if whois_info["name_servers"]:

        for server in whois_info["name_servers"]:
            print(f"  → {server}")

    else:
        print("  → None found")


def display_robots_results(robots_info):

    print("\n" + "=" * 60)
    print("                   ROBOTS.TXT RECON")
    print("=" * 60)

    if robots_info["error"]:

        print(
            f"\n[!] robots.txt Error: "
            f"{robots_info['error']}"
        )

        return

    print(
        f"\nURL         : "
        f"{robots_info['url']}"
    )

    print(
        f"Status Code : "
        f"{robots_info['status_code']}"
    )

    print(
        f"Exists      : "
        f"{robots_info['exists']}"
    )

    print("\nUser-Agents:")

    if robots_info["user_agents"]:

        for agent in robots_info["user_agents"]:
            print(f"  → {agent}")

    else:
        print("  → None found")

    print("\nDisallowed Paths:")

    if robots_info["disallow"]:

        for entry in robots_info["disallow"]:

            print(
                f"  → [{entry['user_agent']}] "
                f"{entry['path']}"
            )

    else:
        print("  → None found")

    print("\nAllowed Paths:")

    if robots_info["allow"]:

        for entry in robots_info["allow"]:

            print(
                f"  → [{entry['user_agent']}] "
                f"{entry['path']}"
            )

    else:
        print("  → None found")

    print("\nSitemap References:")

    if robots_info["sitemaps"]:

        for sitemap in robots_info["sitemaps"]:
            print(f"  → {sitemap}")

    else:
        print("  → None found")


def display_sitemap_results(sitemap_info):

    print("\n" + "=" * 60)
    print("                  SITEMAP RECON")
    print("=" * 60)

    if sitemap_info["error"]:

        print(
            f"\n[!] Sitemap Error: "
            f"{sitemap_info['error']}"
        )

        return

    print(
        f"\nURL         : "
        f"{sitemap_info['url']}"
    )

    print(
        f"Status Code : "
        f"{sitemap_info['status_code']}"
    )

    print(
        f"Exists      : "
        f"{sitemap_info['exists']}"
    )

    print(
        f"Type        : "
        f"{sitemap_info['type'] or 'Not detected'}"
    )

    if sitemap_info["type"] == "URL Sitemap":

        print(
            f"\nURL Count   : "
            f"{sitemap_info['url_count']}"
        )

        print("\nDiscovered URLs:")

        if sitemap_info["urls"]:

            for url in sitemap_info["urls"][:20]:
                print(f"  → {url}")

            if len(sitemap_info["urls"]) > 20:

                print(
                    f"  ... and "
                    f"{len(sitemap_info['urls']) - 20}"
                    f" more"
                )

        else:
            print("  → None found")

    elif sitemap_info["type"] == "Sitemap Index":

        print(
            f"\nChild Sitemaps: "
            f"{sitemap_info['url_count']}"
        )

        if sitemap_info["child_sitemaps"]:

            for sitemap in sitemap_info["child_sitemaps"][:20]:
                print(f"  → {sitemap}")

            if len(sitemap_info["child_sitemaps"]) > 20:

                print(
                    f"  ... and "
                    f"{len(sitemap_info['child_sitemaps']) - 20}"
                    f" more"
                )

        else:
            print("  → None found")


def main():

    import io
    from contextlib import redirect_stdout

    evidence_manager = EvidenceManager()
    previous_snapshot = None
    header_results = {}
    snapshot_path = None
    current_snapshot = None
    changes_with_evidence = []

    print("=" * 60)
    print("          WEB RECON AUTOMATION FRAMEWORK")
    print("=" * 60)

    target = input("\nEnter target domain or URL: ")

    try:

        # --------------------------------------------------
        # TARGET VALIDATION
        # --------------------------------------------------

        target_info = normalize_target(target)

        existing_snapshots = get_snapshots(
            target_info["domain"]
        )

        if existing_snapshots:
            previous_snapshot = load_snapshot(
                existing_snapshots[-1]
            )

        print("\n[+] Target accepted")
        print(f"[+] URL    : {target_info['url']}")
        print(f"[+] Domain : {target_info['domain']}")

        # --------------------------------------------------
        # COLLECT RECON OUTPUT SILENTLY
        # --------------------------------------------------
        #
        # Reconnaissance creates the evidence records while
        # running. We temporarily capture its terminal output
        # so the final display can be arranged as:
        #
        # 1. Evidence Summary
        # 2. Reconnaissance Results
        # 3. Change Report
        # 4. Reconnaissance Complete
        #
        # No reconnaissance logic is changed here.

        recon_output = io.StringIO()

        with redirect_stdout(recon_output):

            # --------------------------------------------------
            # DNS RECONNAISSANCE
            # --------------------------------------------------

            print("\n[*] Starting DNS reconnaissance...")

            records = get_dns_records(
                target_info["domain"]
            )

            display_dns_results(records)

            ips = extract_ips(records)

            print("\n[*] Resolved IP addresses:")

            if ips:

                for ip in ips:
                    print(f"  → {ip}")

            else:
                print("  → No IP addresses found")

            analyze_dns(
                records,
                ips,
                evidence_manager
            )

            print("\n[+] DNS reconnaissance completed.")

            # --------------------------------------------------
            # HTTP RECONNAISSANCE
            # --------------------------------------------------

            print("\n[*] Starting HTTP reconnaissance...")

            http_info = get_http_info(
                target_info["url"]
            )

            display_http_results(http_info)

            # --------------------------------------------------
            # SECURITY HEADER ANALYSIS
            # --------------------------------------------------

            if not http_info["error"]:

                print("\n[*] Analyzing security headers...")

                header_results = collect_security_headers(
                    http_info["headers"]
                )

                display_security_headers(
                    header_results
                )

                analyze_security_headers(
                    header_results,
                    evidence_manager
                )

                summary = get_header_summary(
                    header_results
                )

                print(
                    f"\n[*] Security headers observed: "
                    f"{summary['present']}/{summary['total']}"
                )

                print(
                    f"[*] Security headers not observed: "
                    f"{summary['missing']}/{summary['total']}"
                )

            print("\n[+] HTTP reconnaissance completed.")

            # --------------------------------------------------
            # TLS RECONNAISSANCE
            # --------------------------------------------------

            print("\n[*] Starting TLS reconnaissance...")

            tls_info = get_tls_info(
                target_info["domain"]
            )

            display_tls_results(tls_info)

            analyze_tls(
                tls_info,
                evidence_manager
            )

            print("\n[+] TLS reconnaissance completed.")

            # --------------------------------------------------
            # DOMAIN REGISTRATION
            # --------------------------------------------------

            print(
                "\n[*] Starting domain registration reconnaissance..."
            )

            whois_info = get_whois_info(
                target_info["domain"]
            )

            display_whois_results(
                whois_info
            )

            analyze_whois(
                whois_info,
                evidence_manager
            )

            print(
                "\n[+] Domain registration reconnaissance completed."
            )

            # --------------------------------------------------
            # ROBOTS.TXT RECONNAISSANCE
            # --------------------------------------------------

            print("\n[*] Checking robots.txt...")

            robots_info = get_robots_info(
                target_info["domain"]
            )

            display_robots_results(
                robots_info
            )

            analyze_robots(
                robots_info,
                evidence_manager
            )

            print(
                "\n[+] robots.txt reconnaissance completed."
            )

            # --------------------------------------------------
            # SITEMAP RECONNAISSANCE
            # --------------------------------------------------

            print("\n[*] Checking sitemap.xml...")

            sitemap_info = get_sitemap_info(
                target_info["domain"],
                robots_info["sitemaps"]
            )

            display_sitemap_results(
                sitemap_info
            )

            analyze_sitemap(
                sitemap_info,
                evidence_manager
            )

            print(
                "\n[+] Sitemap reconnaissance completed."
            )

            # --------------------------------------------------
            # RECON FINGERPRINT
            # --------------------------------------------------

            print(
                "\n[*] Generating reconnaissance fingerprint..."
            )

            fingerprint = create_fingerprint(
                target_info,
                records,
                ips,
                http_info,
                header_results,
                tls_info,
                whois_info,
                robots_info,
                sitemap_info
            )

            print("\n" + "=" * 60)
            print("              RECON FINGERPRINT")
            print("=" * 60)

            print(
                f"\nTarget      : "
                f"{target_info['domain']}"
            )

            print(
                f"Fingerprint : "
                f"{fingerprint['hash']}"
            )

            print(
                f"Length      : "
                f"{len(fingerprint['hash'])}"
            )

            # --------------------------------------------------
            # SAVE SNAPSHOT
            # --------------------------------------------------

            print(
                "\n[*] Saving reconnaissance snapshot..."
            )

            snapshot_path = save_snapshot(
                target_info["domain"],
                fingerprint,
                evidence_manager.get_all()
            )

            print(
                f"[+] Snapshot saved: "
                f"{snapshot_path}"
            )

        # --------------------------------------------------
        # EVIDENCE SUMMARY — SHOWN FIRST
        # --------------------------------------------------

        print("\n" + "=" * 60)
        print("              EVIDENCE SUMMARY")
        print("=" * 60)

        print(
            f"\nTotal Evidence Records: "
            f"{evidence_manager.count()}"
        )

        for evidence in evidence_manager.get_all():
            evidence.display()

        # --------------------------------------------------
        # RECONNAISSANCE RESULTS — SHOWN AFTER EVIDENCE
        # --------------------------------------------------

        print("\n" + "=" * 60)
        print("              RECONNAISSANCE RESULTS")
        print("=" * 60)

        print(recon_output.getvalue(), end="")

        # --------------------------------------------------
        # CHANGE DETECTION — SHOWN AT THE BOTTOM
        # --------------------------------------------------

        if previous_snapshot and snapshot_path:

            print(
                "\n[*] Comparing with previous snapshot..."
            )

            current_snapshot = load_snapshot(
                snapshot_path
            )

            raw_changes = compare_snapshots(
                previous_snapshot["data"],
                current_snapshot["data"]
            )

            logical_changes = normalize_changes(
                raw_changes
            )

            evidence_data = []

            for item in evidence_manager.get_all():

                if hasattr(item, "to_dict"):
                    evidence_data.append(
                        item.to_dict()
                    )
                else:
                    evidence_data.append(item)

            changes_with_evidence = attach_evidence(
                logical_changes,
                evidence_data
            )

            display_change_report(
                previous_snapshot,
                current_snapshot,
                changes_with_evidence
            )

        elif snapshot_path:

            print(
                "\n[*] No previous snapshot found."
            )

            print(
                "[*] This scan will be used as "
                "the baseline."
            )

        # --------------------------------------------------
        # RECON COMPLETE — LAST
        # --------------------------------------------------

        print("\n" + "=" * 60)
        print("              RECONNAISSANCE COMPLETE")
        print("=" * 60)

    except ValueError as error:

        print(f"\n[!] Error: {error}")


if __name__ == "__main__":
    main()