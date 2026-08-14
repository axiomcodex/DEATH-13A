def normalize_changes(changes):
    """
    Convert raw snapshot differences into meaningful
    logical changes.
    """

    normalized = []

    added_ips = set()
    removed_ips = set()

    added_aaaa = set()
    removed_aaaa = set()

    other_changes = []

    for change in changes:

        path = change["path"]

        # DNS IP addresses
        if path == "dns.ips":

            if change["type"] == "ADDED":
                added_ips.add(str(change["new"]))

            elif change["type"] == "REMOVED":
                removed_ips.add(str(change["old"]))

            continue

        # DNS AAAA records
        if path == "dns.records.AAAA":

            if change["type"] == "ADDED":
                added_aaaa.add(str(change["new"]))

            elif change["type"] == "REMOVED":
                removed_aaaa.add(str(change["old"]))

            continue

        # Everything else
        other_changes.append(change)

    # --------------------------------------------------
    # Combine IPv6 IP + AAAA changes
    # --------------------------------------------------

    matched_removed = set()
    matched_added = set()

    for old_ip in removed_ips:

        for new_ip in added_ips:

            if (
                old_ip in removed_aaaa
                and new_ip in added_aaaa
            ):

                normalized.append({
                    "source": "DNS",
                    "category": "IPv6 Address",
                    "type": "CHANGED",
                    "old": old_ip,
                    "new": new_ip,
                    "raw_paths": [
                        "dns.ips",
                        "dns.records.AAAA"
                    ]
                })

                matched_removed.add(old_ip)
                matched_added.add(new_ip)

                break

    # --------------------------------------------------
    # Unmatched IP additions
    # --------------------------------------------------

    for ip in sorted(added_ips - matched_added):

        normalized.append({
            "source": "DNS",
            "category": "IP Address",
            "type": "ADDED",
            "old": None,
            "new": ip,
            "raw_paths": ["dns.ips"]
        })

    # --------------------------------------------------
    # Unmatched IP removals
    # --------------------------------------------------

    for ip in sorted(removed_ips - matched_removed):

        normalized.append({
            "source": "DNS",
            "category": "IP Address",
            "type": "REMOVED",
            "old": ip,
            "new": None,
            "raw_paths": ["dns.ips"]
        })

    # --------------------------------------------------
    # Unmatched AAAA additions
    # --------------------------------------------------

    for ip in sorted(added_aaaa - matched_added):

        normalized.append({
            "source": "DNS",
            "category": "AAAA Record",
            "type": "ADDED",
            "old": None,
            "new": ip,
            "raw_paths": ["dns.records.AAAA"]
        })

    # --------------------------------------------------
    # Unmatched AAAA removals
    # --------------------------------------------------

    for ip in sorted(removed_aaaa - matched_removed):

        normalized.append({
            "source": "DNS",
            "category": "AAAA Record",
            "type": "REMOVED",
            "old": ip,
            "new": None,
            "raw_paths": ["dns.records.AAAA"]
        })

    # --------------------------------------------------
    # Other changes
    # --------------------------------------------------

    for change in other_changes:

        normalized.append({
            "source": change["path"].split(".")[0],
            "category": change["path"],
            "type": change["type"],
            "old": change["old"],
            "new": change["new"],
            "raw_paths": [
                change["path"]
            ]
        })

    return normalized


def attach_evidence(changes, evidence):
    """
    Attach the most relevant evidence to each
    logical change.
    """

    results = []

    for change in changes:

        supporting = []

        source = change.get(
            "source",
            ""
        )

        category = change.get(
            "category",
            ""
        ).lower()

        old_value = str(
            change.get(
                "old",
                ""
            )
        )

        new_value = str(
            change.get(
                "new",
                ""
            )
        )

        # --------------------------------------------------
        # Find evidence containing the actual changed value
        # --------------------------------------------------

        for item in evidence:

            item_source = str(
                item.get(
                    "source",
                    ""
                )
            )

            item_observation = str(
                item.get(
                    "observation",
                    ""
                )
            )

            item_evidence = str(
                item.get(
                    "evidence",
                    ""
                )
            )

            searchable_text = (
                item_observation
                + " "
                + item_evidence
            ).lower()

            # --------------------------------------------------
            # DNS IPv6 change
            # --------------------------------------------------

            if (
                source == "DNS"
                and "ipv6" in category
                and item_source.upper() == "DNS"
            ):

                # Strong match:
                # evidence contains the NEW or OLD address

                if (
                    new_value.lower()
                    in searchable_text
                    or
                    old_value.lower()
                    in searchable_text
                ):

                    supporting.append(item)

        # --------------------------------------------------
        # If no exact evidence was found, use source match
        # as a fallback.
        # --------------------------------------------------

        if not supporting:

            for item in evidence:

                if (
                    str(
                        item.get(
                            "source",
                            ""
                        )
                    ).upper()
                    == source.upper()
                ):

                    supporting.append(item)

        # --------------------------------------------------
        # Limit evidence to the most relevant records
        # --------------------------------------------------

        supporting = supporting[:2]

        result = change.copy()

        result["supporting_evidence"] = supporting

        results.append(result)

    return results