def compare_snapshots(old_data, new_data):
    """
    Compare two reconnaissance fingerprint data sets.

    Returns:
        A list containing detected changes.
    """

    changes = []

    compare_section(
        old_data,
        new_data,
        "",
        changes
    )

    return changes


def compare_section(old_value, new_value, path, changes):
    """
    Recursively compare dictionaries, lists and values.
    """

    # --------------------------------------------------
    # DICTIONARY COMPARISON
    # --------------------------------------------------

    if isinstance(old_value, dict) and isinstance(new_value, dict):

        all_keys = set(old_value.keys()) | set(new_value.keys())

        for key in sorted(all_keys):

            current_path = (
                f"{path}.{key}"
                if path
                else key
            )

            # Added field
            if key not in old_value:

                changes.append({
                    "type": "ADDED",
                    "path": current_path,
                    "old": None,
                    "new": new_value[key]
                })

                continue

            # Removed field
            if key not in new_value:

                changes.append({
                    "type": "REMOVED",
                    "path": current_path,
                    "old": old_value[key],
                    "new": None
                })

                continue

            compare_section(
                old_value[key],
                new_value[key],
                current_path,
                changes
            )

        return

    # --------------------------------------------------
    # LIST COMPARISON
    # --------------------------------------------------

    if isinstance(old_value, list) and isinstance(new_value, list):

        old_items = {
            str(item)
            for item in old_value
        }

        new_items = {
            str(item)
            for item in new_value
        }

        added = new_items - old_items
        removed = old_items - new_items

        for item in sorted(added):

            changes.append({
                "type": "ADDED",
                "path": path,
                "old": None,
                "new": item
            })

        for item in sorted(removed):

            changes.append({
                "type": "REMOVED",
                "path": path,
                "old": item,
                "new": None
            })

        return

    # --------------------------------------------------
    # VALUE COMPARISON
    # --------------------------------------------------

    if old_value != new_value:

        changes.append({
            "type": "CHANGED",
            "path": path,
            "old": old_value,
            "new": new_value
        })