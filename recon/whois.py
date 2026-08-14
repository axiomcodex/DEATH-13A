import requests


def get_whois_info(domain):
    result = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "status": [],
        "name_servers": [],
        "error": None
    }

    try:
        url = f"https://rdap.org/domain/{domain}"

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "WebReconFramework/1.0"
            }
        )

        response.raise_for_status()

        data = response.json()

        # --------------------------------------------------
        # Domain Events
        # --------------------------------------------------

        for event in data.get("events", []):

            event_action = event.get("eventAction")
            event_date = event.get("eventDate")

            if event_action == "registration":
                result["creation_date"] = event_date

            elif event_action == "expiration":
                result["expiration_date"] = event_date

            elif event_action == "last changed":
                result["updated_date"] = event_date

        # --------------------------------------------------
        # Domain Status
        # --------------------------------------------------

        result["status"] = data.get(
            "status",
            []
        )

        # --------------------------------------------------
        # Name Servers
        # --------------------------------------------------

        for nameserver in data.get(
            "nameservers",
            []
        ):

            name = nameserver.get(
                "ldhName"
            )

            if name:
                result["name_servers"].append(
                    name
                )

        # --------------------------------------------------
        # Registrar
        # --------------------------------------------------

        for entity in data.get(
            "entities",
            []
        ):

            roles = entity.get(
                "roles",
                []
            )

            if "registrar" in roles:

                vcard = entity.get(
                    "vcardArray",
                    []
                )

                if len(vcard) > 1:

                    for item in vcard[1]:

                        if (
                            isinstance(item, list)
                            and len(item) >= 4
                        ):

                            if item[0] == "fn":

                                result["registrar"] = (
                                    item[3]
                                )

                                break

        # --------------------------------------------------
        # If RDAP responded successfully but no
        # registration information was available
        # --------------------------------------------------

        if not any([
            result["registrar"],
            result["creation_date"],
            result["expiration_date"],
            result["updated_date"],
            result["status"],
            result["name_servers"]
        ]):

            result["error"] = (
                "RDAP responded, but no "
                "registration information was available."
            )

    except requests.RequestException as error:

        result["error"] = (
            f"RDAP request failed: {error}"
        )

    except ValueError as error:

        result["error"] = (
            f"Invalid RDAP response: {error}"
        )

    except Exception as error:

        result["error"] = str(error)

    return result