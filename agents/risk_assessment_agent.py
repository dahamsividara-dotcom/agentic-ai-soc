"""
Agentic AI-SOC
Evidence-Weighted Risk Assessment Agent v3

Research-grade dynamic risk scoring using:
- Severity
- Detection confidence
- Evidence strength
- Temporal correlation
- Entity correlation
- MITRE technique coverage
- Threat Intelligence (CTI)
- Context classification
- Uncertainty penalty

Design principle:
Risk must be evidence-driven and must distinguish:
    BENIGN / ADMINISTRATIVE
    SUSPICIOUS
    MALICIOUS

CTI is treated as an independent evidence source.
"""

from typing import Any


class RiskAssessmentAgent:

    VERSION = "3.0"

    SEVERITY_SCORE = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 35,
        "CRITICAL": 45,
    }

    CTI_SCORE = {
        "MALICIOUS": 15,
        "SUSPICIOUS": 8,
        "UNKNOWN": 0,
        "BENIGN": -3,
    }

    CONTEXT_MODIFIER = {
        "ADMINISTRATIVE": -12,
        "LEGITIMATE": -12,
        "NORMAL": -10,
        "HIGH_VALUE_DISCOVERY": 0,
        "SUSPICIOUS": 4,
        "MALICIOUS": 12,
        "UNKNOWN": 0,
    }

    def assess(
        self,
        findings: list[dict[str, Any]],
        attack_chain: dict[str, Any],
        investigation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        investigation = investigation or {}

        if not findings:
            return self._empty_result()

        evidence_score = self._calculate_evidence_score(findings)

        temporal_score = self._calculate_temporal_score(
            attack_chain
        )

        entity_score = self._calculate_entity_score(
            attack_chain
        )

        mitre_score = self._calculate_mitre_score(
            attack_chain
        )

        cti_score, cti_details = self._calculate_cti_score(
            investigation
        )

        context_modifier = self._calculate_context_modifier(
            findings
        )

        uncertainty = attack_chain.get(
            "uncertainty",
            {}
        )

        uncertainty_penalty = (
            self._calculate_uncertainty_penalty(
                uncertainty
            )
        )

        raw_score = (
            evidence_score
            + temporal_score
            + entity_score
            + mitre_score
            + cti_score
            + context_modifier
            - uncertainty_penalty
        )

        risk_score = max(
            0,
            min(
                round(raw_score),
                100
            )
        )

        risk_level = self._risk_level(
            risk_score
        )

        confidence = self._confidence(
            findings,
            attack_chain,
            investigation,
        )

        return {
            "agent": "Risk Assessment Agent",
            "version": self.VERSION,

            "risk_score": risk_score,
            "risk_level": risk_level,

            "components": {
                "evidence_score": evidence_score,
                "temporal_score": temporal_score,
                "entity_score": entity_score,
                "mitre_score": mitre_score,
                "cti_score": cti_score,
                "context_modifier": context_modifier,
                "uncertainty_penalty": uncertainty_penalty,
            },

            "cti_details": cti_details,

            "method": (
                "Evidence-Weighted Dynamic Risk Scoring "
                "with CTI and Context Awareness"
            ),

            "confidence": confidence,

            "human_validation_required": True,

            "explanation": self._build_explanation(
                risk_score=risk_score,
                risk_level=risk_level,
                evidence_score=evidence_score,
                temporal_score=temporal_score,
                entity_score=entity_score,
                mitre_score=mitre_score,
                cti_score=cti_score,
                context_modifier=context_modifier,
                uncertainty_penalty=uncertainty_penalty,
                cti_details=cti_details,
            ),
        }

    # ==========================================================
    # EVIDENCE
    # ==========================================================

    @staticmethod
    def _calculate_evidence_score(
        findings: list[dict[str, Any]]
    ) -> int:

        score = 0.0

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "LOW"
                )
            ).upper()

            base = RiskAssessmentAgent.SEVERITY_SCORE.get(
                severity,
                10
            )

            try:
                confidence = float(
                    finding.get(
                        "confidence",
                        0.5
                    )
                )
            except (TypeError, ValueError):
                confidence = 0.5

            decision = str(
                finding.get(
                    "decision",
                    "SUSPICIOUS"
                )
            ).upper()

            # Attack evidence receives stronger weighting.
            if decision == "ATTACK":
                multiplier = 0.80

            elif decision == "SUSPICIOUS":
                multiplier = 0.55

            else:
                multiplier = 0.30

            score += (
                base
                * confidence
                * multiplier
            )

        return min(
            round(score),
            45
        )

    # ==========================================================
    # TEMPORAL CORRELATION
    # ==========================================================

    @staticmethod
    def _calculate_temporal_score(
        attack_chain: dict[str, Any]
    ) -> int:

        relationships = attack_chain.get(
            "relationships",
            []
        )

        if not isinstance(
            relationships,
            list
        ):
            return 0

        strong = sum(
            1
            for relationship in relationships
            if isinstance(
                relationship,
                dict
            )
            and relationship.get(
                "score",
                0
            ) >= 5
        )

        return min(
            strong * 5,
            15
        )

    # ==========================================================
    # ENTITY CORRELATION
    # ==========================================================

    @staticmethod
    def _calculate_entity_score(
        attack_chain: dict[str, Any]
    ) -> int:

        relationships = attack_chain.get(
            "relationships",
            []
        )

        if not isinstance(
            relationships,
            list
        ):
            return 0

        score = 0

        for relationship in relationships:

            if not isinstance(
                relationship,
                dict
            ):
                continue

            reasons = relationship.get(
                "reasons",
                []
            )

            if not isinstance(
                reasons,
                list
            ):
                continue

            if "Same host" in reasons:
                score += 3

            if "Same user" in reasons:
                score += 3

            if "Same source IP" in reasons:
                score += 2

        return min(
            score,
            15
        )

    # ==========================================================
    # MITRE COVERAGE
    # ==========================================================

    @staticmethod
    def _calculate_mitre_score(
        attack_chain: dict[str, Any]
    ) -> int:

        stages = attack_chain.get(
            "stages",
            []
        )

        if not isinstance(
            stages,
            list
        ):
            return 0

        techniques = set()

        for stage in stages:

            if not isinstance(
                stage,
                dict
            ):
                continue

            mitre = stage.get(
                "mitre_attack",
                {}
            )

            if not isinstance(
                mitre,
                dict
            ):
                continue

            technique_id = mitre.get(
                "technique_id"
            )

            if technique_id:
                techniques.add(
                    str(
                        technique_id
                    )
                )

        return min(
            len(techniques) * 3,
            12
        )

    # ==========================================================
    # THREAT INTELLIGENCE
    # ==========================================================

    @staticmethod
    def _calculate_cti_score(
        investigation: dict[str, Any]
    ) -> tuple[int, list[dict[str, Any]]]:

        """
        CTI can appear in InvestigationAgent output as:

            cti_matches: [...]
            cti_context: [...]

        The previous implementation only read cti_context,
        which caused CTI evidence to be ignored in some cases.

        This implementation prioritizes structured cti_matches.
        """

        matches = investigation.get(
            "cti_matches",
            []
        )

        # Backward compatibility.
        if not isinstance(
            matches,
            list
        ):
            matches = []

        # If cti_matches is unavailable, attempt cti_context.
        if not matches:

            context = investigation.get(
                "cti_context",
                []
            )

            if isinstance(
                context,
                list
            ):
                matches = context

        score = 0.0

        details = []

        for match in matches:

            if not isinstance(
                match,
                dict
            ):
                continue

            classification = str(
                match.get(
                    "classification",
                    match.get(
                        "verdict",
                        match.get(
                            "status",
                            "UNKNOWN"
                        )
                    )
                )
            ).upper()

            try:
                confidence = float(
                    match.get(
                        "confidence",
                        0.5
                    )
                )
            except (
                TypeError,
                ValueError
            ):
                confidence = 0.5

            confidence = max(
                0.0,
                min(
                    confidence,
                    1.0
                )
            )

            base_score = (
                RiskAssessmentAgent.CTI_SCORE.get(
                    classification,
                    0
                )
            )

            contribution = (
                base_score
                * confidence
            )

            score += contribution

            details.append(
                {
                    "classification": classification,
                    "confidence": round(
                        confidence,
                        2
                    ),
                    "contribution": round(
                        contribution,
                        2
                    ),
                    "indicator": match.get(
                        "indicator"
                    ),
                    "indicator_type": match.get(
                        "indicator_type"
                    ),
                    "source": match.get(
                        "source",
                        "Local CTI Knowledge Base"
                    ),
                }
            )

        # Strong CTI evidence must be meaningful,
        # but must never by itself exceed the risk cap.
        score = max(
            -5,
            min(
                round(score),
                25
            )
        )

        return score, details

    # ==========================================================
    # CONTEXT AWARENESS
    # ==========================================================

    @staticmethod
    def _calculate_context_modifier(
        findings: list[dict[str, Any]]
    ) -> int:

        modifier = 0

        for finding in findings:

            classification = str(
                finding.get(
                    "context_classification",
                    "UNKNOWN"
                )
            ).upper()

            modifier += (
                RiskAssessmentAgent.CONTEXT_MODIFIER.get(
                    classification,
                    0
                )
            )

        # Prevent context from completely dominating
        # the evidence model.
        return max(
            -20,
            min(
                modifier,
                20
            )
        )

    # ==========================================================
    # UNCERTAINTY
    # ==========================================================

    @staticmethod
    def _calculate_uncertainty_penalty(
        uncertainty: dict[str, Any]
    ) -> int:

        if not isinstance(
            uncertainty,
            dict
        ):
            return 0

        level = str(
            uncertainty.get(
                "level",
                "LOW"
            )
        ).upper()

        if level == "HIGH":
            return 12

        if level == "MEDIUM":
            return 7

        return 0

    # ==========================================================
    # CONFIDENCE
    # ==========================================================

    @staticmethod
    def _confidence(
        findings: list[dict[str, Any]],
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> float:

        detection_confidences = []

        for finding in findings:

            try:
                detection_confidences.append(
                    float(
                        finding.get(
                            "confidence",
                            0.5
                        )
                    )
                )

            except (
                TypeError,
                ValueError
            ):
                continue

        detection_confidence = (
            sum(
                detection_confidences
            )
            / len(
                detection_confidences
            )
            if detection_confidences
            else 0.5
        )

        relationships = attack_chain.get(
            "relationships",
            []
        )

        relationship_confidences = []

        for relationship in relationships:

            if not isinstance(
                relationship,
                dict
            ):
                continue

            try:
                relationship_confidences.append(
                    float(
                        relationship.get(
                            "relationship_confidence",
                            0.35
                        )
                    )
                )

            except (
                TypeError,
                ValueError
            ):
                continue

        relationship_confidence = (
            sum(
                relationship_confidences
            )
            / len(
                relationship_confidences
            )
            if relationship_confidences
            else 0.35
        )

        try:
            investigation_confidence = float(
                investigation.get(
                    "confidence",
                    0.5
                )
            )

        except (
            TypeError,
            ValueError
        ):
            investigation_confidence = 0.5

        confidence = (
            detection_confidence * 0.40
            + relationship_confidence * 0.25
            + investigation_confidence * 0.35
        )

        return round(
            min(
                max(
                    confidence,
                    0.0
                ),
                0.99
            ),
            2
        )

    # ==========================================================
    # RISK LEVEL
    # ==========================================================

    @staticmethod
    def _risk_level(
        score: int
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"

    # ==========================================================
    # EMPTY RESULT
    # ==========================================================

    @staticmethod
    def _empty_result() -> dict[str, Any]:

        return {
            "agent": "Risk Assessment Agent",
            "version": RiskAssessmentAgent.VERSION,
            "risk_score": 0,
            "risk_level": "LOW",
            "components": {},
            "cti_details": [],
            "method": (
                "Evidence-Weighted Dynamic Risk Scoring "
                "with CTI and Context Awareness"
            ),
            "confidence": 0.0,
            "human_validation_required": True,
            "explanation": (
                "No security findings were available."
            ),
        }

    # ==========================================================
    # EXPLANATION
    # ==========================================================

    @staticmethod
    def _build_explanation(
        risk_score: int,
        risk_level: str,
        evidence_score: int,
        temporal_score: int,
        entity_score: int,
        mitre_score: int,
        cti_score: int,
        context_modifier: int,
        uncertainty_penalty: int,
        cti_details: list[dict[str, Any]],
    ) -> str:

        explanation = (
            f"Dynamic risk assessment produced "
            f"{risk_score}/100 ({risk_level}). "
            f"Evidence contributed {evidence_score} points, "
            f"temporal correlation contributed "
            f"{temporal_score}, "
            f"entity correlation contributed "
            f"{entity_score}, "
            f"MITRE technique coverage contributed "
            f"{mitre_score}, "
            f"CTI contributed {cti_score}, "
            f"and context contributed "
            f"{context_modifier}. "
            f"An uncertainty penalty of "
            f"{uncertainty_penalty} was applied."
        )

        if cti_details:

            malicious = sum(
                1
                for item in cti_details
                if item.get(
                    "classification"
                ) == "MALICIOUS"
            )

            suspicious = sum(
                1
                for item in cti_details
                if item.get(
                    "classification"
                ) == "SUSPICIOUS"
            )

            explanation += (
                f" CTI evidence included "
                f"{malicious} malicious and "
                f"{suspicious} suspicious "
                f"indicator match(es)."
            )

        else:

            explanation += (
                " No structured CTI matches "
                "were available."
            )

        explanation += (
            " The score is an evidence-weighted "
            "investigative assessment and requires "
            "human validation."
        )

        return explanation


if __name__ == "__main__":

    agent = RiskAssessmentAgent()

    result = agent.assess(
        findings=[],
        attack_chain={},
        investigation={},
    )

    print(
        "Risk Assessment Agent v3"
    )
    print("=" * 40)
    print(
        "Status: READY"
    )
    print(
        f"Version: {result['version']}"
    ) 