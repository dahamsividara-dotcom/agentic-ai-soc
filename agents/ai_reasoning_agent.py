"""
Agentic AI-SOC
AI Reasoning Agent v4

Evidence-Grounded Reasoning with Dynamic Risk Synchronization.

Responsibilities:
- Classify observed / inferred / uncertain evidence
- Extract MITRE ATT&CK techniques
- Summarize attack stages
- Incorporate CTI evidence
- Use authoritative dynamic risk assessment
- Generate explainable reasoning
- Preserve uncertainty and human validation requirements
"""


from typing import Any


class AIReasoningAgent:
    """
    Evidence-Grounded AI Reasoning Agent.

    The Dynamic Risk Assessment is treated as the authoritative
    quantitative risk source when supplied.

    Attack-chain risk is used only as a fallback for compatibility.
    """

    VERSION = "4.0"

    REASONING_MODE = "Evidence-Grounded Reasoning"

    def __init__(self):
        pass

    # ==========================================================
    # PUBLIC REASONING METHOD
    # ==========================================================

    def reason(
        self,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
        risk_assessment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Generate evidence-grounded AI reasoning.

        Parameters
        ----------
        attack_chain:
            Output from AttackChainEngine.

        investigation:
            Output from InvestigationAgent.

        risk_assessment:
            Output from RiskAssessmentAgent.
            This is the authoritative risk source.

        Returns
        -------
        dict
            Structured AI reasoning result.
        """

        attack_chain = attack_chain or {}
        investigation = investigation or {}
        risk_assessment = risk_assessment or {}

        # ======================================================
        # 1. AUTHORITATIVE RISK
        # ======================================================

        if risk_assessment:
            risk_score = self._safe_number(
                risk_assessment.get(
                    "risk_score",
                    attack_chain.get("risk_score", 0),
                )
            )

            risk_level = str(
                risk_assessment.get(
                    "risk_level",
                    self._risk_level_from_score(risk_score),
                )
            ).upper()

            risk_confidence = self._safe_number(
                risk_assessment.get(
                    "confidence",
                    0.0,
                )
            )

        else:
            # Compatibility fallback for older callers.
            risk_score = self._safe_number(
                attack_chain.get("risk_score", 0)
            )

            risk_level = self._risk_level_from_score(
                risk_score
            )

            risk_confidence = 0.0

        risk_score = max(
            0.0,
            min(100.0, risk_score),
        )

        # ======================================================
        # 2. ATTACK STAGES
        # ======================================================

        stages = attack_chain.get(
            "stages",
            [],
        )

        if not isinstance(stages, list):
            stages = []

        attack_stages = []

        for stage in stages:
            if not isinstance(stage, dict):
                continue

            stage_name = stage.get("stage")

            if stage_name and stage_name not in attack_stages:
                attack_stages.append(
                    stage_name
                )

        # ======================================================
        # 3. EVIDENCE
        # ======================================================

        evidence = investigation.get(
            "evidence",
            [],
        )

        if not isinstance(evidence, list):
            evidence = []

        evidence_classification = (
            self._classify_evidence(
                evidence=evidence,
                attack_chain=attack_chain,
            )
        )

        evidence_count = len(evidence)

        # ======================================================
        # 4. MITRE ATT&CK
        # ======================================================

        mitre_techniques = self._extract_mitre(
            stages
        )

        # ======================================================
        # 5. CTI
        # ======================================================

        cti_matches = investigation.get(
            "cti_matches",
            [],
        )

        if not isinstance(cti_matches, list):
            cti_matches = []

        cti_count = len(cti_matches)

        # ======================================================
        # 6. CONFIDENCE
        # ======================================================

        investigation_confidence = self._safe_number(
            investigation.get(
                "confidence",
                0.0,
            )
        )

        confidence = self._calculate_confidence(
            risk_score=risk_score,
            risk_confidence=risk_confidence,
            investigation_confidence=investigation_confidence,
            evidence_count=evidence_count,
        )

        # ======================================================
        # 7. UNCERTAINTY
        # ======================================================

        uncertainty_analysis = (
            self._build_uncertainty_analysis(
                evidence=evidence,
                attack_chain=attack_chain,
                investigation=investigation,
            )
        )

        # ======================================================
        # 8. HUMAN VALIDATION
        # ======================================================

        human_validation_required = True

        # ======================================================
        # 9. REASONING TEXT
        # ======================================================

        reasoning = self._build_reasoning(
            risk_score=risk_score,
            risk_level=risk_level,
            attack_stages=attack_stages,
            mitre_techniques=mitre_techniques,
            cti_count=cti_count,
            evidence_count=evidence_count,
        )

        # ======================================================
        # 10. FINAL STRUCTURED RESULT
        # ======================================================

        return {
            "agent": "AI Reasoning Agent",

            "version": self.VERSION,

            "reasoning_mode": self.REASONING_MODE,

            # IMPORTANT:
            # These values now come from RiskAssessmentAgent.
            "threat_assessment": risk_level,

            "risk_score": int(
                round(risk_score)
            ),

            "risk_level": risk_level,

            "risk_confidence": round(
                risk_confidence,
                2,
            ),

            "confidence": round(
                confidence,
                2,
            ),

            "attack_stages": attack_stages,

            "mitre_techniques": mitre_techniques,

            "evidence_count": evidence_count,

            "cti_matches": cti_count,

            "evidence_classification": (
                evidence_classification
            ),

            "reasoning": reasoning,

            "uncertainty_analysis": (
                uncertainty_analysis
            ),

            "human_validation_required": (
                human_validation_required
            ),

            "limitations": [
                "Assessment is based only on available telemetry.",
                "Observed events do not independently prove malicious intent.",
                "Attack-chain relationships are inferred from available telemetry.",
                "Additional endpoint and network telemetry may change the assessment.",
                "LLM-generated inferences must remain distinguishable from observed evidence.",
                "Human analyst validation is required before response actions.",
            ],
        }

    # ==========================================================
    # EVIDENCE CLASSIFICATION
    # ==========================================================

    def _classify_evidence(
        self,
        evidence: list[dict[str, Any]],
        attack_chain: dict[str, Any],
    ) -> dict[str, list[dict[str, Any]]]:

        observed = []
        inferred = []
        uncertain = []

        for item in evidence:

            if not isinstance(item, dict):
                continue

            observed.append(
                {
                    "classification": "OBSERVED",
                    "timestamp": item.get(
                        "timestamp"
                    ),
                    "host": item.get(
                        "host"
                    ),
                    "username": item.get(
                        "username"
                    ),
                    "rule_id": item.get(
                        "rule_id"
                    ),
                    "stage": item.get(
                        "stage"
                    ),
                    "severity": item.get(
                        "severity"
                    ),
                    "confidence": item.get(
                        "confidence"
                    ),
                    "evidence": item.get(
                        "evidence"
                    ),
                }
            )

        if attack_chain.get("relationships"):
            inferred.append(
                {
                    "classification": "INFERRED",
                    "statement": (
                        "The observed events may represent "
                        "a related multi-stage security activity."
                    ),
                    "basis": (
                        "Multiple correlated stages were "
                        "identified by the attack-chain engine."
                    ),
                }
            )

        uncertain.append(
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
        )

        return {
            "observed": observed,
            "inferred": inferred,
            "uncertain": uncertain,
        }

    # ==========================================================
    # MITRE EXTRACTION
    # ==========================================================

    @staticmethod
    def _extract_mitre(
        stages: list[dict[str, Any]]
    ) -> list[str]:

        techniques = []

        for stage in stages:

            if not isinstance(stage, dict):
                continue

            mitre = stage.get(
                "mitre_attack"
            )

            if not isinstance(mitre, dict):
                continue

            technique_id = mitre.get(
                "technique_id"
            )

            technique_name = mitre.get(
                "technique"
            )

            if not technique_id:
                continue

            if technique_name:
                value = (
                    f"{technique_id} - "
                    f"{technique_name}"
                )
            else:
                value = str(
                    technique_id
                )

            if value not in techniques:
                techniques.append(
                    value
                )

        return techniques

    # ==========================================================
    # CONFIDENCE
    # ==========================================================

    @staticmethod
    def _calculate_confidence(
        risk_score: float,
        risk_confidence: float,
        investigation_confidence: float,
        evidence_count: int,
    ) -> float:

        risk_component = (
            risk_score / 100.0
        ) * 0.35

        risk_conf_component = (
            max(
                0.0,
                min(
                    1.0,
                    risk_confidence,
                ),
            )
            * 0.25
        )

        investigation_component = (
            max(
                0.0,
                min(
                    1.0,
                    investigation_confidence,
                ),
            )
            * 0.25
        )

        evidence_component = (
            min(
                evidence_count / 5.0,
                1.0,
            )
            * 0.15
        )

        confidence = (
            risk_component
            + risk_conf_component
            + investigation_component
            + evidence_component
        )

        return max(
            0.0,
            min(
                0.99,
                confidence,
            ),
        )

    # ==========================================================
    # UNCERTAINTY
    # ==========================================================

    @staticmethod
    def _build_uncertainty_analysis(
        evidence: list[dict[str, Any]],
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> dict[str, Any]:

        evidence_gaps = [
            "Malicious intent is not directly observable.",
            "Attack-chain relationships are inferred from available telemetry.",
            "Additional endpoint and network telemetry may change the assessment.",
        ]

        if not evidence:
            evidence_gaps.insert(
                0,
                "No direct security evidence was available.",
            )

        return {
            "level": "MEDIUM",
            "known_evidence": len(
                evidence
            ),
            "evidence_gaps": evidence_gaps,
            "human_validation_required": True,
        }

    # ==========================================================
    # REASONING GENERATION
    # ==========================================================

    @staticmethod
    def _build_reasoning(
        risk_score: float,
        risk_level: str,
        attack_stages: list[str],
        mitre_techniques: list[str],
        cti_count: int,
        evidence_count: int,
    ) -> str:

        stage_text = (
            " -> ".join(
                attack_stages
            )
            if attack_stages
            else "No observed attack stages"
        )

        technique_text = (
            ", ".join(
                mitre_techniques
            )
            if mitre_techniques
            else "No MITRE ATT&CK techniques identified"
        )

        return (
            f"The evidence-grounded assessment produced "
            f"{risk_level} risk with a risk score of "
            f"{int(round(risk_score))}/100. "
            f"The observed sequence is {stage_text}. "
            f"The observed activity is associated with "
            f"the following MITRE ATT&CK techniques: "
            f"{technique_text}. "
            f"{cti_count} relevant CTI knowledge entry/entries "
            f"were retrieved. "
            f"The assessment is supported by "
            f"{evidence_count} observed evidence item(s). "
            f"The chain represents a security hypothesis "
            f"and should not be treated as confirmed malicious "
            f"activity without additional validation."
        )

    # ==========================================================
    # RISK LEVEL
    # ==========================================================

    @staticmethod
    def _risk_level_from_score(
        score: float
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "LOW"

    # ==========================================================
    # SAFE NUMBER
    # ==========================================================

    @staticmethod
    def _safe_number(
        value: Any
    ) -> float:

        try:
            return float(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0.0


if __name__ == "__main__":

    print(
        "Agentic AI-SOC AI Reasoning Agent"
    )

    print(
        "=" * 45
    )

    print(
        "AI Reasoning Agent v4 initialized."
    )

    print(
        "Mode: Evidence-Grounded Reasoning"
    )

    print(
        "Features: Dynamic Risk Synchronization + "
        "Evidence Classification + Uncertainty Analysis"
    )

    print(
        "Status: READY"
    ) 