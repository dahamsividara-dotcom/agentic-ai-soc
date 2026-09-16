"""
Agentic AI-SOC
AI Reasoning Agent v3

Evidence-grounded reasoning layer with:
- Observed evidence
- Inferred conclusions
- Uncertainty analysis
- MITRE ATT&CK normalization
- Confidence estimation
"""

from typing import Any


class AIReasoningAgent:
    """Generates evidence-grounded threat reasoning."""

    def __init__(self):
        self.name = "AI Reasoning Agent"
        self.version = "v3"
        self.mode = "Evidence-Grounded Reasoning"

    def reason(
        self,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> dict[str, Any]:

        stages = attack_chain.get("stages", [])
        evidence = investigation.get("evidence", [])
        cti_context = investigation.get("cti_context", [])

        risk_score = int(
            attack_chain.get("risk_score", 0)
        )

        status = attack_chain.get(
            "status",
            "LOW"
        )

        stage_names = [
            stage.get("stage", "Unknown")
            for stage in stages
        ]

        mitre_techniques = self._extract_mitre_techniques(
            stages
        )

        evidence_classification = (
            self._classify_evidence(
                evidence,
                stages,
            )
        )

        reasoning = self._build_reasoning(
            status=status,
            risk_score=risk_score,
            stages=stage_names,
            mitre_techniques=mitre_techniques,
            evidence=evidence,
            cti_context=cti_context,
        )

        confidence = self._calculate_confidence(
            attack_chain,
            investigation,
        )

        uncertainty = self._build_uncertainty(
            evidence,
            stages,
            cti_context,
        )

        return {
            "agent": self.name,
            "version": self.version,
            "reasoning_mode": self.mode,

            "threat_assessment": status,
            "risk_score": risk_score,
            "confidence": confidence,

            "attack_stages": stage_names,
            "mitre_techniques": mitre_techniques,

            "evidence_count": len(evidence),
            "cti_matches": len(cti_context),

            "evidence_classification":
                evidence_classification,

            "reasoning": reasoning,

            "uncertainty_analysis": uncertainty,

            "limitations": [
                "Assessment is based only on available telemetry.",
                "Observed events do not independently prove malicious intent.",
                "Additional endpoint and network telemetry may change the conclusion.",
                "LLM-generated inferences must remain distinguishable from observed evidence.",
                "Human analyst validation is required before response actions."
            ],
        }

    @staticmethod
    def _extract_mitre_techniques(
        stages: list[dict[str, Any]]
    ) -> list[str]:

        techniques = []

        for stage in stages:

            mitre = stage.get(
                "mitre_attack"
            )

            if not mitre:
                continue

            if isinstance(mitre, dict):

                technique_id = (
                    mitre.get("id")
                    or mitre.get("technique_id")
                    or mitre.get("mitre_id")
                )

                technique_name = (
                    mitre.get("name")
                    or mitre.get("technique")
                    or mitre.get("title")
                )

                if technique_id and technique_name:
                    value = (
                        f"{technique_id} - "
                        f"{technique_name}"
                    )

                elif technique_id:
                    value = str(technique_id)

                elif technique_name:
                    value = str(technique_name)

                else:
                    value = str(mitre)

            else:
                value = str(mitre)

            if value not in techniques:
                techniques.append(value)

        return techniques

    @staticmethod
    def _classify_evidence(
        evidence: list[dict[str, Any]],
        stages: list[dict[str, Any]],
    ) -> dict[str, Any]:

        observed = []

        for item in evidence:

            observed_item = {
                "classification": "OBSERVED",
                "timestamp": item.get("timestamp"),
                "host": item.get("host"),
                "username": item.get("username"),
                "rule_id": item.get("rule_id"),
                "stage": item.get("stage"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "evidence": item.get("evidence"),
            }

            observed.append(
                observed_item
            )

        inferred = []

        if len(stages) >= 2:

            inferred.append({
                "classification": "INFERRED",
                "statement": (
                    "The observed events may represent "
                    "a related multi-stage security activity."
                ),
                "basis": (
                    "Multiple correlated stages were "
                    "identified by the attack-chain engine."
                ),
            })

        if any(
            stage.get("stage") == "Command and Control"
            for stage in stages
        ):

            inferred.append({
                "classification": "INFERRED",
                "statement": (
                    "The external network activity may "
                    "represent command-and-control communication."
                ),
                "basis": (
                    "An external network connection was "
                    "associated with the correlated chain."
                ),
            })

        uncertain = [
            {
                "classification": "UNCERTAIN",
                "statement": (
                    "Malicious intent cannot be confirmed "
                    "from the available telemetry alone."
                ),
                "required_evidence": [
                    "Endpoint process ancestry",
                    "Full command-line telemetry",
                    "Network destination reputation",
                    "Authentication history",
                    "Additional host telemetry",
                ],
            }
        ]

        return {
            "observed": observed,
            "inferred": inferred,
            "uncertain": uncertain,
        }

    @staticmethod
    def _build_reasoning(
        status: str,
        risk_score: int,
        stages: list[str],
        mitre_techniques: list[str],
        evidence: list[dict[str, Any]],
        cti_context: list[dict[str, Any]],
    ) -> str:

        if not stages:

            return (
                "Insufficient correlated security activity "
                "was available to construct a meaningful "
                "threat hypothesis."
            )

        stage_sequence = " -> ".join(
            stages
        )

        reasoning = (
            f"The correlated telemetry produced a "
            f"{status} threat assessment with a risk "
            f"score of {risk_score}/100. "
            f"The observed sequence is "
            f"{stage_sequence}. "
        )

        if mitre_techniques:

            reasoning += (
                "The observed activity is associated "
                "with the following MITRE ATT&CK techniques: "
                f"{', '.join(mitre_techniques)}. "
            )

        if cti_context:

            reasoning += (
                f"{len(cti_context)} relevant CTI knowledge "
                f"entry/entries were retrieved. "
            )

        reasoning += (
            f"The assessment is supported by "
            f"{len(evidence)} observed evidence item(s). "
            "The chain represents a security hypothesis "
            "and should not be treated as confirmed malicious "
            "activity without additional validation."
        )

        return reasoning

    @staticmethod
    def _build_uncertainty(
        evidence: list[dict[str, Any]],
        stages: list[dict[str, Any]],
        cti_context: list[dict[str, Any]],
    ) -> dict[str, Any]:

        gaps = []

        if not evidence:
            gaps.append(
                "No direct evidence was available."
            )

        if not cti_context:
            gaps.append(
                "No matching CTI context was available."
            )

        if not any(
            stage.get("host")
            for stage in stages
        ):
            gaps.append(
                "Host attribution is incomplete."
            )

        gaps.extend([
            "Malicious intent is not directly observable.",
            "Attack-chain relationships are inferred from available telemetry.",
            "Additional endpoint and network telemetry may change the assessment.",
        ])

        return {
            "level": "MEDIUM",
            "known_evidence": len(evidence),
            "evidence_gaps": gaps,
            "human_validation_required": True,
        }

    @staticmethod
    def _calculate_confidence(
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> float:

        chain_risk = float(
            attack_chain.get(
                "risk_score",
                0
            )
        )

        investigation_confidence = float(
            investigation.get(
                "confidence",
                0.5
            )
        )

        evidence_count = len(
            investigation.get(
                "evidence",
                []
            )
        )

        confidence = (
            (chain_risk / 100) * 0.45
            + investigation_confidence * 0.40
            + min(evidence_count / 5, 1.0) * 0.15
        )

        return round(
            min(confidence, 0.99),
            2
        )


if __name__ == "__main__":

    print(
        "Agentic AI-SOC AI Reasoning Agent"
    )
    print("=" * 45)
    print(
        "AI Reasoning Agent v3 initialized."
    )
    print(
        "Mode: Evidence-Grounded Reasoning"
    )
    print(
        "Features: Evidence Classification + Uncertainty Analysis"
    )
    print("Status: READY")
