import json
import os
from datetime import datetime


SNAPSHOT_DIR = "snapshots"


def save_snapshot(target, fingerprint, evidence=None):
    """
    Save a reconnaissance snapshot without
    overwriting previous scans.
    """

    target_dir = os.path.join(
        SNAPSHOT_DIR,
        target
    )

    os.makedirs(
        target_dir,
        exist_ok=True
    )

    existing_files = [
        file
        for file in os.listdir(target_dir)
        if file.startswith("scan_")
        and file.endswith(".json")
    ]

    scan_number = len(existing_files) + 1

    filename = f"scan_{scan_number:03d}.json"

    filepath = os.path.join(
        target_dir,
        filename
    )

    # Convert Evidence objects into dictionaries
    evidence_data = []

    if evidence:

        for item in evidence:

            if hasattr(item, "to_dict"):
                evidence_data.append(
                    item.to_dict()
                )

            else:
                evidence_data.append(item)

    snapshot = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "scan_number": scan_number,
        "fingerprint": fingerprint["hash"],
        "data": fingerprint["data"],
        "evidence": evidence_data
    }

    with open(
        filepath,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            snapshot,
            file,
            indent=4,
            default=str
        )

    return filepath


def get_snapshots(target):
    """
    Return all saved snapshots for a target.
    """

    target_dir = os.path.join(
        SNAPSHOT_DIR,
        target
    )

    if not os.path.exists(target_dir):
        return []

    files = [
        file
        for file in os.listdir(target_dir)
        if file.startswith("scan_")
        and file.endswith(".json")
    ]

    files.sort()

    return [
        os.path.join(
            target_dir,
            file
        )
        for file in files
    ]
def get_snapshots(target):
    """
    Return all saved snapshots for a target.
    """

    target_dir = os.path.join(
        SNAPSHOT_DIR,
        target
    )

    if not os.path.exists(target_dir):
        return []

    files = [
        file
        for file in os.listdir(target_dir)
        if file.startswith("scan_")
        and file.endswith(".json")
    ]

    files.sort()

    return [
        os.path.join(
            target_dir,
            file
        )
        for file in files
    ]


def load_snapshot(filepath):
    """
    Load a saved reconnaissance snapshot.
    """

    with open(
        filepath,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)