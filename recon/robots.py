import requests


def get_robots_info(domain):
    result = {
        "url": f"https://{domain}/robots.txt",
        "status_code": None,
        "exists": False,
        "user_agents": [],
        "disallow": [],
        "allow": [],
        "sitemaps": [],
        "raw_content": None,
        "error": None
    }

    try:
        response = requests.get(
            result["url"],
            timeout=10,
            headers={
                "User-Agent": "WebReconFramework/1.0"
            }
        )

        result["status_code"] = response.status_code

        if response.status_code == 200:
            result["exists"] = True
            result["raw_content"] = response.text

            current_user_agent = None

            for line in response.text.splitlines():

                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                if ":" not in line:
                    continue

                directive, value = line.split(
                    ":",
                    1
                )

                directive = directive.strip().lower()
                value = value.strip()

                if directive == "user-agent":
                    current_user_agent = value

                    if value not in result["user_agents"]:
                        result["user_agents"].append(value)

                elif directive == "disallow":

                    result["disallow"].append({
                        "user_agent": current_user_agent,
                        "path": value
                    })

                elif directive == "allow":

                    result["allow"].append({
                        "user_agent": current_user_agent,
                        "path": value
                    })

                elif directive == "sitemap":

                    result["sitemaps"].append(value)

        else:
            result["exists"] = False

    except requests.RequestException as error:
        result["error"] = str(error)

    return result