"""
Agentic AI-SOC
Attack Chain Reasoning Engine v1
"""

from typing import Any


class AttackChainEngine:
    """Correlates security findings into attack-chain stages."""

    STAGE_ORDER = {
        "Initial Access": 1,
        "Execution": 2,
        "Discovery": 3,
        "Credential Access": 4,
        "Privilege Escalation": 5,
        "Lateral Movement": 6,
        "Command and Control": 7,
        "Exfiltration": 8,
    }

    def build_chain(
        self,
        findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Build an explainable attack chain from detection findings."""

        stages = []

        for finding in findings:
            stage = self._classify_stage(finding)

            stages.append({
                "stage": stage,
                "order": self.STAGE_ORDER.get(stage, 99),
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "host": finding.get("host"),
                "username": finding.get("username"),
                "mitre_attack": finding.get("mitre_attack"),
                "evidence": finding.get("reason"),
            })

        stages.sort(key=lambda item: item["order"])

        unique_stages = []
        seen = set()

        for stage in stages:
            key = stage["stage"]

            if key not in seen:
                unique_stages.append(stage)
                seen.add(key)

        risk_score = self._calculate_risk(stages)

        return {
            "chain_id": "CHAIN-001",
            "status": self._determine_status(risk_score),
            "risk_score": risk_score,
            "stage_count": len(unique_stages),
            "stages": unique_stages,
            "explanation": self._build_explanation(unique_stages),
        }

    def _classify_stage(
        self,
        finding: dict[str, Any]
    ) -> str:
        """Map a detection finding to an attack lifecycle stage."""

        rule_id = finding.get("rule_id")
        technique = (
            finding
            .get("mitre_attack", {})
            .get("technique_id")
        )

        if rule_id == "DET-001":
            return "Execution"

        if rule_id == "DET-002":
            return "Discovery"

        if rule_id == "DET-003":
            return "Initial Access"

        if rule_id == "DET-004":
            return "Command and Control"

        if technique == "T1059":
            return "Execution"

        return "Unknown"

    @staticmethod
    def _calculate_risk(
        stages: list[dict[str, Any]]
    ) -> int:
        """Calculate a bounded 0-100 attack-chain risk score."""

        severity_weights = {
            "LOW": 10,
            "MEDIUM": 20,
            "HIGH": 35,
            "CRITICAL": 50,
        }

        score = sum(
            severity_weights.get(stage["severity"], 0)
            for stage in stages
        )

        if len(stages) >= 3:
            score += 10

        if len(stages) >= 5:
            score += 10

        return min(score, 100)

    @staticmethod
    def _determine_status(risk_score: int) -> str:

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 30:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _build_explanation(
        stages: list[dict[str, Any]]
    ) -> str:

        if not stages:
            return "No correlated attack stages were identified."

        stage_names = [stage["stage"] for stage in stages]

        return (
            "The detection engine identified a potentially related "
            "sequence across these stages: "
            + " -> ".join(stage_names)
            + ". Further investigation is recommended."
        )


if __name__ == "__main__":
    print("Agentic AI-SOC Attack Chain Engine")
    print("=" * 40)
    print("Attack Chain Engine v1 initialized.")
    print("Status: READY")
