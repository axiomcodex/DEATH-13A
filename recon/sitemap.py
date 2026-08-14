import requests
import xml.etree.ElementTree as ET


def get_sitemap_info(domain, robots_sitemaps=None):

    result = {
        "url": None,
        "status_code": None,
        "exists": False,
        "type": None,
        "url_count": 0,
        "urls": [],
        "child_sitemaps": [],
        "error": None
    }

    try:

        # --------------------------------------------------
        # Determine sitemap URL
        # --------------------------------------------------

        if robots_sitemaps:
            sitemap_url = robots_sitemaps[0]
        else:
            sitemap_url = f"https://{domain}/sitemap.xml"

        result["url"] = sitemap_url

        # --------------------------------------------------
        # Request sitemap
        # --------------------------------------------------

        response = requests.get(
            sitemap_url,
            timeout=10,
            headers={
                "User-Agent": "WebReconFramework/1.0"
            }
        )

        result["status_code"] = response.status_code

        if response.status_code != 200:
            return result

        result["exists"] = True

        # --------------------------------------------------
        # Parse XML
        # --------------------------------------------------

        root = ET.fromstring(response.content)

        # Handle XML namespace
        namespace = ""

        if "}" in root.tag:
            namespace = root.tag.split("}")[0] + "}"

        # --------------------------------------------------
        # Normal URL Sitemap
        # --------------------------------------------------

        if root.tag.endswith("urlset"):

            result["type"] = "URL Sitemap"

            for url_element in root.findall(
                f"{namespace}url"
            ):

                loc = url_element.find(
                    f"{namespace}loc"
                )

                if loc is not None and loc.text:

                    result["urls"].append(
                        loc.text.strip()
                    )

            result["url_count"] = len(
                result["urls"]
            )

        # --------------------------------------------------
        # Sitemap Index
        # --------------------------------------------------

        elif root.tag.endswith("sitemapindex"):

            result["type"] = "Sitemap Index"

            for sitemap_element in root.findall(
                f"{namespace}sitemap"
            ):

                loc = sitemap_element.find(
                    f"{namespace}loc"
                )

                if loc is not None and loc.text:

                    result["child_sitemaps"].append(
                        loc.text.strip()
                    )

            result["url_count"] = len(
                result["child_sitemaps"]
            )

    except ET.ParseError as error:

        result["error"] = (
            f"Invalid XML sitemap: {error}"
        )

    except requests.RequestException as error:

        result["error"] = (
            f"Sitemap request failed: {error}"
        )

    except Exception as error:

        result["error"] = str(error)

    return result