import hashlib
import json


def create_fingerprint(
    target_info,
    records,
    ips,
    http_info,
    header_results,
    tls_info,
    whois_info,
    robots_info,
    sitemap_info
):
    fingerprint_data = {
        "target": target_info,

        "dns": {
            "records": records,
            "ips": sorted(ips)
        },

        "http": {
            "status_code": http_info["status_code"],
            "final_url": http_info["final_url"],
            "server": http_info["server"],
            "content_type": http_info["content_type"],
            "redirects": http_info["redirects"]
        },

        "security_headers": header_results,

        "tls": {
            "tls_version": tls_info["tls_version"],
            "subject": tls_info["subject"],
            "issuer": tls_info["issuer"],
            "valid_until": tls_info["valid_until"],
            "san": sorted(tls_info["san"])
        },

        "registration": {
            "registrar": whois_info["registrar"],
            "creation_date": str(
                whois_info["creation_date"]
            ),
            "expiration_date": str(
                whois_info["expiration_date"]
            ),
            "name_servers": sorted(
                whois_info["name_servers"]
            ),
            "status": sorted(
                whois_info["status"]
            )
        },

        "robots": {
            "exists": robots_info["exists"],
            "status_code": robots_info["status_code"],
            "user_agents": sorted(
                robots_info["user_agents"]
            ),
            "disallow": robots_info["disallow"],
            "allow": robots_info["allow"],
            "sitemaps": sorted(
                robots_info["sitemaps"]
            )
        },

        "sitemap": {
            "exists": sitemap_info["exists"],
            "status_code": sitemap_info["status_code"],
            "type": sitemap_info["type"],
            "url_count": sitemap_info["url_count"],
            "urls": sorted(
                sitemap_info["urls"]
            ),
            "child_sitemaps": sorted(
                sitemap_info["child_sitemaps"]
            )
        }
    }

    normalized_data = json.dumps(
        fingerprint_data,
        sort_keys=True,
        default=str
    )

    fingerprint_hash = hashlib.sha256(
        normalized_data.encode("utf-8")
    ).hexdigest()

    return {
        "hash": fingerprint_hash,
        "data": fingerprint_data
    }