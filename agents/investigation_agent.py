"""
Agentic AI-SOC
Investigation Agent v3

CTI-enriched, evidence-based security investigation.

Features:
- Attack-chain evidence collection
- MITRE ATT&CK context
- IOC / indicator-based CTI lookup
- Destination IP correlation
- Source IP correlation
- Domain correlation
- CTI classification and confidence
- Evidence-grounded investigation
"""

from typing import Any

from threat_intel.cti_knowledge_base import CTIKnowledgeBase


class InvestigationAgent:
    """Investigates attack chains using security evidence and CTI."""

    VERSION = "3.0"

    def __init__(self):
        self.cti = CTIKnowledgeBase()

    def investigate(
        self,
        attack_chain: dict[str, Any]
    ) -> dict[str, Any]:

        stages = attack_chain.get(
            "stages",
            []
        )

        if not stages:
            return {
                "incident_status": "NO_ACTIVITY",
                "hypothesis": (
                    "No suspicious activity was identified."
                ),
                "confidence": 0.0,
                "evidence_count": 0,
                "cti_matches": [],
                "evidence": [],
                "cti_context": [],
                "recommendations": [],
            }

        evidence = self._collect_evidence(
            stages
        )

        # ------------------------------------------------------
        # MITRE / TECHNIQUE CTI
        # ------------------------------------------------------

        technique_context = (
            self._retrieve_cti_context(
                stages
            )
        )

        # ------------------------------------------------------
        # IOC / INDICATOR CTI
        # ------------------------------------------------------

        indicator_context = (
            self._retrieve_indicator_context(
                stages
            )
        )

        # ------------------------------------------------------
        # MERGE CTI RESULTS
        # ------------------------------------------------------

        combined_cti = self._merge_cti_results(
            technique_context,
            indicator_context
        )

        hypothesis = self._generate_hypothesis(
            stages,
            combined_cti
        )

        confidence = self._calculate_confidence(
            stages,
            combined_cti
        )

        recommendations = (
            self._generate_recommendations(
                stages,
                combined_cti
            )
        )

        return {
            "incident_status": self._determine_status(
                attack_chain.get(
                    "risk_score",
                    0
                )
            ),

            "hypothesis": hypothesis,

            "confidence": confidence,

            "evidence_count": len(
                evidence
            ),

            # Actual structured CTI matches.
            "cti_matches": combined_cti,

            "evidence": evidence,

            # Backward-compatible CTI field.
            "cti_context": combined_cti,

            "recommendations": recommendations,
        }

    # ==========================================================
    # EVIDENCE COLLECTION
    # ==========================================================

    @staticmethod
    def _collect_evidence(
        stages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        evidence = []

        for stage in stages:

            evidence.append({
                "timestamp": stage.get(
                    "timestamp"
                ),

                "host": stage.get(
                    "host"
                ),

                "username": stage.get(
                    "username"
                ),

                "rule_id": stage.get(
                    "rule_id"
                ),

                "stage": stage.get(
                    "stage"
                ),

                "severity": stage.get(
                    "severity"
                ),

                "confidence": stage.get(
                    "confidence"
                ),

                "mitre_attack": stage.get(
                    "mitre_attack"
                ),

                "source_ip": stage.get(
                    "source_ip"
                ),

                "destination_ip": stage.get(
                    "destination_ip"
                ),

                "domain": stage.get(
                    "domain"
                ),

                "process": stage.get(
                    "process"
                ),

                "command_line": stage.get(
                    "command_line"
                ),

                "message": stage.get(
                    "message"
                ),

                "evidence": stage.get(
                    "evidence"
                ),
            })

        return evidence

    # ==========================================================
    # MITRE / TECHNIQUE CTI
    # ==========================================================

    def _retrieve_cti_context(
        self,
        stages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        results = []
        seen = set()

        for stage in stages:

            mitre = (
                stage.get(
                    "mitre_attack"
                )
                or {}
            )

            if not isinstance(
                mitre,
                dict
            ):
                mitre = {}

            technique_id = mitre.get(
                "technique_id"
            )

            technique_name = (
                mitre.get(
                    "technique"
                )
                or mitre.get(
                    "technique_name"
                )
            )

            # --------------------------------------------------
            # MITRE ID lookup
            # --------------------------------------------------

            if technique_id:

                matches = self.cti.search_by_mitre(
                    str(
                        technique_id
                    )
                )

                for entry in matches:

                    # IOC records are resolved separately
                    # through exact indicator matching.
                    if entry.get(
                        "indicator"
                    ):
                        continue

                    entry_id = entry.get(
                        "id"
                    )

                    if entry_id not in seen:

                        seen.add(
                            entry_id
                        )

                        results.append(
                            entry
                        )

            # --------------------------------------------------
            # Technique name lookup
            # --------------------------------------------------

            if technique_name:

                matches = self.cti.search(
                    str(
                        technique_name
                    )
                )

                for entry in matches:

                    # Do not contaminate technique context
                    # with unrelated IOC records.
                    if entry.get(
                        "indicator"
                    ):
                        continue

                    entry_id = entry.get(
                        "id"
                    )

                    if entry_id not in seen:

                        seen.add(
                            entry_id
                        )

                        results.append(
                            entry
                        )

            # --------------------------------------------------
            # Stage lookup
            # --------------------------------------------------

            stage_name = stage.get(
                "stage"
            )

            if stage_name:

                matches = self.cti.search(
                    str(
                        stage_name
                    )
                )

                for entry in matches:

                    if entry.get(
                        "indicator"
                    ):
                        continue

                    entry_id = entry.get(
                        "id"
                    )

                    if entry_id not in seen:

                        seen.add(
                            entry_id
                        )

                        results.append(
                            entry
                        )

        return results

    # ==========================================================
    # IOC / INDICATOR CTI
    # ==========================================================

    def _retrieve_indicator_context(
        self,
        stages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        indicators = []

        for stage in stages:

            destination_ip = stage.get(
                "destination_ip"
            )

            if destination_ip:
                indicators.append(
                    str(
                        destination_ip
                    )
                )

            source_ip = stage.get(
                "source_ip"
            )

            if source_ip:
                indicators.append(
                    str(
                        source_ip
                    )
                )

            domain = stage.get(
                "domain"
            )

            if domain:
                indicators.append(
                    str(
                        domain
                    )
                )

        # Remove duplicate indicators.
        indicators = list(
            dict.fromkeys(
                indicators
            )
        )

        if not indicators:
            return []

        return self.cti.get_indicator_context(
            indicators
        )

    # ==========================================================
    # MERGE CTI RESULTS
    # ==========================================================

    @staticmethod
    def _merge_cti_results(
        *result_sets: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        merged = []
        seen = set()

        for result_set in result_sets:

            if not isinstance(
                result_set,
                list
            ):
                continue

            for result in result_set:

                if not isinstance(
                    result,
                    dict
                ):
                    continue

                result_id = result.get(
                    "id"
                )

                if not result_id:

                    result_id = (
                        result.get(
                            "title"
                        ),
                        result.get(
                            "indicator"
                        ),
                        result.get(
                            "mitre_id"
                        ),
                    )

                if result_id in seen:
                    continue

                seen.add(
                    result_id
                )

                merged.append(
                    result
                )

        return merged

    # ==========================================================
    # HYPOTHESIS
    # ==========================================================

    @staticmethod
    def _generate_hypothesis(
        stages: list[dict[str, Any]],
        cti_context: list[dict[str, Any]]
    ) -> str:

        stage_names = [
            stage.get(
                "stage"
            )
            for stage in stages
            if stage.get(
                "stage"
            )
        ]

        malicious_cti = [
            item
            for item in cti_context
            if str(
                item.get(
                    "classification",
                    ""
                )
            ).upper() == "MALICIOUS"
        ]

        suspicious_cti = [
            item
            for item in cti_context
            if str(
                item.get(
                    "classification",
                    ""
                )
            ).upper() == "SUSPICIOUS"
        ]

        if malicious_cti:

            indicators = [
                item.get(
                    "indicator"
                )
                for item in malicious_cti
                if item.get(
                    "indicator"
                )
            ]

            indicator_text = (
                ", ".join(
                    indicators
                )
                if indicators
                else "known malicious indicators"
            )

            return (
                "The available security telemetry suggests "
                "potential malicious activity involving "
                + " -> ".join(
                    stage_names
                )
                + ". Threat-intelligence evidence identifies "
                + indicator_text
                + " as malicious with supporting confidence. "
                  "The finding should be validated against "
                  "additional telemetry before containment."
            )

        if suspicious_cti:

            indicators = [
                item.get(
                    "indicator"
                )
                for item in suspicious_cti
                if item.get(
                    "indicator"
                )
            ]

            indicator_text = (
                ", ".join(
                    indicators
                )
                if indicators
                else "suspicious indicators"
            )

            return (
                "The available security telemetry suggests "
                "suspicious activity involving "
                + " -> ".join(
                    stage_names
                )
                + ". Threat-intelligence evidence identifies "
                + indicator_text
                + " as suspicious. Further correlation "
                  "and analyst validation are required before "
                  "malicious classification."
            )

        if cti_context:

            return (
                "The available security telemetry suggests "
                "potential suspicious activity involving "
                + " -> ".join(
                    stage_names
                )
                + ". Relevant threat-intelligence knowledge "
                  "supports further investigation of the "
                  "observed techniques. Additional telemetry "
                  "and analyst validation are required before "
                  "response actions."
            )

        return (
            "The available security telemetry suggests "
            "potential suspicious activity involving "
            + " -> ".join(
                stage_names
            )
            + ". The hypothesis requires validation using "
              "additional telemetry and threat intelligence."
        )

    # ==========================================================
    # CONFIDENCE
    # ==========================================================

    @staticmethod
    def _calculate_confidence(
        stages: list[dict[str, Any]],
        cti_context: list[dict[str, Any]]
    ) -> float:

        values = []

        for stage in stages:

            try:

                values.append(
                    float(
                        stage.get(
                            "confidence",
                            0.0
                        )
                    )
                )

            except (
                TypeError,
                ValueError
            ):
                continue

        if not values:
            return 0.0

        detection_confidence = (
            sum(values)
            / len(values)
        )

        cti_values = []

        for context in cti_context:

            try:

                cti_confidence = float(
                    context.get(
                        "confidence",
                        0.0
                    )
                )

                cti_values.append(
                    cti_confidence
                )

            except (
                TypeError,
                ValueError
            ):
                continue

        if cti_values:

            average_cti_confidence = (
                sum(cti_values)
                / len(cti_values)
            )

            confidence = (
                detection_confidence * 0.70
                + average_cti_confidence * 0.30
            )

        else:

            confidence = detection_confidence

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
    # INCIDENT STATUS
    # ==========================================================

    @staticmethod
    def _determine_status(
        risk_score: int
    ) -> str:

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 30:
            return "MEDIUM"

        return "LOW"

    # ==========================================================
    # RECOMMENDATIONS
    # ==========================================================

    @staticmethod
    def _generate_recommendations(
        stages: list[dict[str, Any]],
        cti_context: list[dict[str, Any]]
    ) -> list[str]:

        recommendations = []

        for context in cti_context:

            actions = context.get(
                "investigation",
                []
            )

            if not isinstance(
                actions,
                list
            ):
                continue

            for action in actions:

                if action not in recommendations:

                    recommendations.append(
                        action
                    )

        stage_names = {
            stage.get(
                "stage"
            )
            for stage in stages
            if stage.get(
                "stage"
            )
        }

        if "Execution" in stage_names:

            recommendations.append(
                "Review process creation telemetry "
                "and complete command-line arguments."
            )

        if "Discovery" in stage_names:

            recommendations.append(
                "Correlate discovery activity with "
                "the affected account and host."
            )

        if "Command and Control" in stage_names:

            recommendations.append(
                "Validate external destinations against "
                "trusted threat-intelligence sources."
            )

        if "Initial Access" in stage_names:

            recommendations.append(
                "Review authentication telemetry for "
                "credential-abuse indicators."
            )

        recommendations.append(
            "Require human analyst validation before "
            "executing containment or remediation actions."
        )

        return list(
            dict.fromkeys(
                recommendations
            )
        )


if __name__ == "__main__":

    print(
        "Agentic AI-SOC Investigation Agent"
    )
    print("=" * 50)
    print(
        "Investigation Agent v3"
    )
    print(
        "Mode: CTI + IOC Enriched Investigation"
    )
    print(
        "Status: READY"
    ) 