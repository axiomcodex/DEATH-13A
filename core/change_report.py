from core.impact_analyzer import assess_change_impact


def _print_evidence(item):
    """Print one evidence record in a compact audit-friendly format."""

    print(f"\n{item.get('id', 'Unknown')}")
    print("  Source:")
    print(f"    {item.get('source', 'Unknown')}")

    print("  Observation:")
    print(f"    {item.get('observation', 'Not available')}")

    print("  Evidence:")
    evidence_text = item.get('evidence', 'Not available')

    for line in str(evidence_text).splitlines():
        print(f"    {line}")

    print("  Confidence:")
    print(f"    {item.get('confidence', 'Not available')}")


def display_change_report(
    previous_snapshot,
    current_snapshot,
    changes
):
    """
    Display an evidence-backed reconnaissance change report.

    Only evidence records explicitly linked to each change are
    printed beside that change, in ascending EVD number order.
    """

    print("\n" + "=" * 60)
    print("              RECON CHANGE REPORT")
    print("=" * 60)

    print(
        f"\nPrevious Scan : "
        f"scan_{previous_snapshot['scan_number']:03d}"
    )

    print(
        f"Current Scan  : "
        f"scan_{current_snapshot['scan_number']:03d}"
    )

    print(
        f"Previous Time : "
        f"{previous_snapshot['timestamp']}"
    )

    print(
        f"Current Time  : "
        f"{current_snapshot['timestamp']}"
    )

    print("\n" + "-" * 60)

    if not changes:

        print("\nNo observable changes detected.")

        print(
            "\nThe current reconnaissance state "
            "matches the previous snapshot."
        )

        print("\n" + "=" * 60)
        return

    print(f"\nChanges Detected: {len(changes)}")

    for index, change in enumerate(changes, start=1):

        impact = assess_change_impact(change)

        print("\n" + "=" * 60)

        print(f"CHANGE ID    : CHG-{index:03d}")
        print(f"Source       : {change['source']}")
        print(f"Category     : {change['category']}")
        print(f"Change Type  : {change['type']}")
        print(f"Severity     : {impact['severity']}")
        print(f"Confidence   : {impact['confidence']}")

        print("\nPrevious:")
        if change["old"] is None:
            print("  Not previously observed")
        else:
            print(f"  {change['old']}")

        print("\nCurrent:")
        if change["new"] is None:
            print("  No longer observed")
        else:
            print(f"  {change['new']}")

        print("\nWhy It Matters:")
        print(f"  {impact['impact']}")

        print("\nRecommended Review:")
        print(f"  {impact['recommendation']}")

        evidence = list(change.get("supporting_evidence", []))

        def evidence_number(item):
            value = str(item.get("id", ""))
            try:
                return int(value.split("-")[-1])
            except (ValueError, IndexError):
                return 999999

        evidence.sort(key=evidence_number)

        print("\nSupporting Evidence:")

        if not evidence:
            print("  → No directly linked evidence")
            continue

        for item in evidence:
            print(f"  → {item.get('id', 'Unknown')}")

        print("\n" + "-" * 60)
        print("        SUPPORTING EVIDENCE FOR THIS CHANGE")
        print("-" * 60)

        for item in evidence:
            _print_evidence(item)

    print("\n" + "=" * 60)