from typing import Any, Dict, List


class DecisionAgent:
    """
    Security Decision Agent
    Version 3.1

    Context-aware, evidence-grounded security classification.

    Decision levels:
        BENIGN
        SUSPICIOUS
        MALICIOUS

    Safety:
        - No automatic destructive actions
        - Human approval required
    """

    VERSION = "3.1"

    def __init__(self):
        self.automatic_action = False
        self.human_approval_required = True

    # =============================================================
    # CTI
    # =============================================================

    def _get_cti_matches(
        self,
        investigation: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        matches = investigation.get("cti_matches", [])

        if isinstance(matches, list):
            return matches

        return []

    def _classify_cti(
        self,
        cti_matches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:

        malicious = []
        suspicious = []

        for match in cti_matches:

            if not isinstance(match, dict):
                continue

            classification = str(
                match.get("classification", "UNKNOWN")
            ).upper()

            confidence = float(
                match.get("confidence", 0.0) or 0.0
            )

            if classification == "MALICIOUS":
                malicious.append(match)

            elif classification == "SUSPICIOUS":
                suspicious.append(match)

        strong_malicious = [
            item
            for item in malicious
            if float(
                item.get("confidence", 0.0) or 0.0
            ) >= 0.90
        ]

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "strong_malicious": strong_malicious
        }

    # =============================================================
    # HELPERS
    # =============================================================

    def _finding_rules(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:

        return [
            str(f.get("rule_id", "")).upper()
            for f in findings
        ]

    def _has_administrative_context(
        self,
        findings: List[Dict[str, Any]]
    ) -> bool:

        return any(
            str(
                f.get("context_classification", "")
            ).upper() == "ADMINISTRATIVE"
            for f in findings
        )

    # =============================================================
    # MAIN DECISION
    # =============================================================

    def decide(
        self,
        findings: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any],
        attack_chain: Dict[str, Any],
        investigation: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        investigation = investigation or {}

        # ---------------------------------------------------------
        # Risk
        # ---------------------------------------------------------

        risk_score = float(
            risk_assessment.get("risk_score", 0) or 0
        )

        risk_level = str(
            risk_assessment.get(
                "risk_level",
                "UNKNOWN"
            )
        ).upper()

        risk_confidence = float(
            risk_assessment.get(
                "confidence",
                0.0
            ) or 0.0
        )

        # ---------------------------------------------------------
        # Findings
        # ---------------------------------------------------------

        finding_count = len(findings)

        attack_findings = [
            f for f in findings
            if str(
                f.get("decision", "")
            ).upper() == "ATTACK"
        ]

        suspicious_findings = [
            f for f in findings
            if str(
                f.get("decision", "")
            ).upper() == "SUSPICIOUS"
        ]

        strong_attack_findings = [
            f for f in attack_findings
            if float(
                f.get("confidence", 0.0) or 0.0
            ) >= 0.80
        ]

        # ---------------------------------------------------------
        # Attack-chain relationships
        # ---------------------------------------------------------

        relationships = attack_chain.get(
            "relationships",
            []
        )

        strong_relationships = [
            r for r in relationships
            if float(
                r.get("confidence", 0.0) or 0.0
            ) >= 0.80
        ]

        stages = attack_chain.get(
            "stages",
            []
        )

        # ---------------------------------------------------------
        # CTI
        # ---------------------------------------------------------

        cti_matches = self._get_cti_matches(
            investigation
        )

        cti_analysis = self._classify_cti(
            cti_matches
        )

        malicious_cti = cti_analysis["malicious"]

        suspicious_cti = cti_analysis["suspicious"]

        strong_malicious_cti = (
            cti_analysis["strong_malicious"]
        )

        # ---------------------------------------------------------
        # Context
        # ---------------------------------------------------------

        rules = self._finding_rules(findings)

        administrative_context = (
            self._has_administrative_context(
                findings
            )
        )

        # =========================================================
        # DECISION
        # =========================================================

        decision = "BENIGN"

        reason = ""

        confidence = 0.99

        # ---------------------------------------------------------
        # 1. NO FINDINGS
        # ---------------------------------------------------------

        if finding_count == 0:

            decision = "BENIGN"

            reason = (
                "No security findings were detected "
                "and no malicious CTI evidence was identified."
            )

            confidence = 0.99

        # ---------------------------------------------------------
        # 2. HIGH-CONFIDENCE MALICIOUS CTI
        #
        # Direct malicious IOC evidence has priority.
        # ---------------------------------------------------------

        elif strong_malicious_cti:

            decision = "MALICIOUS"

            indicators = [
                str(item.get("indicator"))
                for item in strong_malicious_cti
                if item.get("indicator")
            ]

            indicator_text = ", ".join(
                indicators
            )

            reason = (
                "High-confidence malicious "
                "threat-intelligence evidence was identified"
            )

            if indicator_text:
                reason += (
                    f" for indicator(s): {indicator_text}."
                )
            else:
                reason += "."

            confidence = max(
                0.90,
                min(
                    0.98,
                    risk_confidence + 0.20
                )
            )

        # ---------------------------------------------------------
        # 3. MALICIOUS CTI
        # ---------------------------------------------------------

        elif malicious_cti:

            decision = "MALICIOUS"

            reason = (
                "Malicious threat-intelligence evidence "
                "was identified and correlated with "
                "security telemetry."
            )

            confidence = max(
                0.85,
                min(
                    0.95,
                    risk_confidence + 0.15
                )
            )

        # ---------------------------------------------------------
        # 4. ADMINISTRATIVE POWERSELL ONLY
        #
        # Legitimate administrative PowerShell should not
        # automatically become a security incident.
        # ---------------------------------------------------------

        elif (
            administrative_context
            and set(rules).issubset({"DET-001"})
        ):

            decision = "BENIGN"

            reason = (
                "PowerShell activity was classified as "
                "administrative activity without additional "
                "malicious or correlated attack evidence."
            )

            confidence = 0.90

        # ---------------------------------------------------------
        # 5. SINGLE WEAK EXTERNAL CONNECTION
        # ---------------------------------------------------------

        elif (
            finding_count == 1
            and rules == ["DET-004"]
            and risk_score < 30
        ):

            decision = "BENIGN"

            reason = (
                "An isolated external network connection "
                "was detected without additional correlated "
                "evidence of malicious activity."
            )

            confidence = 0.85

        # ---------------------------------------------------------
        # 6. SINGLE FAILED LOGIN
        # ---------------------------------------------------------

        elif (
            finding_count == 1
            and rules == ["DET-003"]
            and risk_score < 30
        ):

            decision = "BENIGN"

            reason = (
                "An isolated failed authentication event "
                "was detected without sufficient evidence "
                "of brute-force or malicious activity."
            )

            confidence = 0.85

        # ---------------------------------------------------------
        # 7. DET-006 ALONE
        #
        # Correlation signal by itself is not enough to
        # declare malicious activity.
        # ---------------------------------------------------------

        elif (
            "DET-006" in rules
            and len(strong_attack_findings) == 1
            and finding_count <= 3
            and len(strong_relationships) == 0
        ):

            decision = "SUSPICIOUS"

            reason = (
                "A correlated execution/network activity "
                "pattern was detected, but additional evidence "
                "is required before malicious classification."
            )

            confidence = max(
                0.60,
                min(
                    0.79,
                    risk_confidence
                )
            )

        # ---------------------------------------------------------
        # 8. STRONG ATTACK FINDINGS + CORRELATION
        # ---------------------------------------------------------

        elif (
            len(strong_attack_findings) >= 1
            and (
                len(strong_relationships) > 0
                or len(attack_findings) >= 2
                or risk_score >= 60
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "High-confidence attack findings were "
                "supported by additional correlated evidence "
                "or elevated risk."
            )

            confidence = 0.90

        # ---------------------------------------------------------
        # 9. MULTIPLE ATTACK FINDINGS
        # ---------------------------------------------------------

        elif (
            len(attack_findings) >= 2
            and (
                risk_score >= 40
                or len(strong_relationships) > 0
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "Multiple attack findings were correlated "
                "with elevated risk or strong attack-chain "
                "relationships."
            )

            confidence = 0.85

        # ---------------------------------------------------------
        # 10. HIGH RISK
        # ---------------------------------------------------------

        elif risk_score >= 80:

            decision = "MALICIOUS"

            reason = (
                "The evidence-weighted risk assessment "
                "reached a critical level."
            )

            confidence = 0.90

        elif risk_score >= 60:

            decision = "MALICIOUS"

            reason = (
                "The evidence-weighted risk assessment "
                "indicates a high likelihood of malicious activity."
            )

            confidence = 0.82

        # ---------------------------------------------------------
        # 11. SUSPICIOUS CTI
        # ---------------------------------------------------------

        elif suspicious_cti:

            decision = "SUSPICIOUS"

            reason = (
                "Suspicious threat-intelligence evidence "
                "was identified, but the available evidence "
                "is insufficient for malicious classification."
            )

            confidence = max(
                0.60,
                min(
                    0.79,
                    risk_confidence
                )
            )

        # ---------------------------------------------------------
        # 12. GENERAL SUSPICIOUS ACTIVITY
        # ---------------------------------------------------------

        elif (
            suspicious_findings
            or attack_findings
            or risk_score >= 30
        ):

            decision = "SUSPICIOUS"

            reason = (
                "Suspicious security evidence was detected, "
                "but the available evidence is insufficient "
                "for a malicious classification."
            )

            confidence = max(
                0.55,
                min(
                    0.79,
                    risk_confidence
                )
            )

        # ---------------------------------------------------------
        # 13. BENIGN FALLBACK
        # ---------------------------------------------------------

        else:

            decision = "BENIGN"

            reason = (
                "The available evidence does not indicate "
                "malicious activity."
            )

            confidence = 0.90

        # =========================================================
        # FINAL STRUCTURED OUTPUT
        # =========================================================

        return {
            "agent": "Security Decision Agent",
            "version": self.VERSION,

            "decision": decision,

            "risk_score": risk_score,
            "risk_level": risk_level,

            "confidence": round(
                confidence,
                2
            ),

            "risk_confidence": round(
                risk_confidence,
                2
            ),

            "finding_count": finding_count,

            "attack_finding_count": len(
                attack_findings
            ),

            "strong_attack_finding_count": len(
                strong_attack_findings
            ),

            "suspicious_finding_count": len(
                suspicious_findings
            ),

            "stage_count": len(
                stages
            ),

            "strong_relationship_count": len(
                strong_relationships
            ),

            "cti_match_count": len(
                cti_matches
            ),

            "malicious_cti_count": len(
                malicious_cti
            ),

            "strong_malicious_cti_count": len(
                strong_malicious_cti
            ),

            "suspicious_cti_count": len(
                suspicious_cti
            ),

            "reason": reason,

            "human_validation_required": True,

            "automatic_action": False,

            "safety_policy": {
                "automatic_destructive_actions": False,
                "human_approval_required": True,
                "decision_agent_version": self.VERSION
            }
        } 