class Evidence:
    def __init__(
        self,
        evidence_id,
        source,
        observation,
        evidence,
        significance,
        confidence,
        recommendation
    ):
        self.evidence_id = evidence_id
        self.source = source
        self.observation = observation
        self.evidence = evidence
        self.significance = significance
        self.confidence = confidence
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "id": self.evidence_id,
            "source": self.source,
            "observation": self.observation,
            "evidence": self.evidence,
            "significance": self.significance,
            "confidence": self.confidence,
            "recommendation": self.recommendation
        }

    def display(self):
        print("\n" + "=" * 60)
        print(f"                    {self.evidence_id}")
        print("=" * 60)

        print("\nSource:")
        print(f"  {self.source}")

        print("\nObservation:")
        print(f"  {self.observation}")

        print("\nEvidence:")
        print(f"  {self.evidence}")

        print("\nWhy It Matters:")
        print(f"  {self.significance}")

        print("\nConfidence:")
        print(f"  {self.confidence}")

        print("\nRecommended Review:")
        print(f"  {self.recommendation}")


class EvidenceManager:
    def __init__(self):
        self.evidence = []
        self.counter = 1

    def add(
        self,
        source,
        observation,
        evidence,
        significance,
        confidence,
        recommendation
    ):
        evidence_id = f"EVD-{self.counter:03d}"

        item = Evidence(
            evidence_id,
            source,
            observation,
            evidence,
            significance,
            confidence,
            recommendation
        )

        self.evidence.append(item)
        self.counter += 1

        return item

    def get_all(self):
        return self.evidence

    def count(self):
        return len(self.evidence)