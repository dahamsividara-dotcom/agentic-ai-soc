"""
Agentic AI-SOC
Security Decision Agent

Version: 3.7

Purpose:
    Convert detection, investigation, attack-chain and risk evidence
    into a structured security decision.

Decision classes:
    BENIGN
    SUSPICIOUS
    MALICIOUS

Safety:
    - No automatic destructive actions
    - Human approval is always required
"""

from typing import Any, Dict, List


class DecisionAgent:

    VERSION = "3.7"

    def __init__(self):
        self.automatic_action = False
        self.human_approval_required = True

    # =========================================================
    # SAFE HELPERS
    # =========================================================

    @staticmethod
    def _safe_float(
        value: Any,
        default: float = 0.0
    ) -> float:

        try:
            return float(value)

        except (
            TypeError,
            ValueError
        ):
            return default

    @staticmethod
    def _safe_list(
        value: Any
    ) -> List:

        if isinstance(
            value,
            list
        ):
            return value

        return []

    @staticmethod
    def _safe_dict(
        value: Any
    ) -> Dict[str, Any]:

        if isinstance(
            value,
            dict
        ):
            return value

        return {}

    # =========================================================
    # CTI
    # =========================================================

    def _get_cti_matches(
        self,
        investigation: Dict[str, Any]
    ) -> List[Dict[str, Any]]:

        matches = investigation.get(
            "cti_matches",
            []
        )

        if isinstance(
            matches,
            list
        ):
            return matches

        return []

    def _classify_cti(
        self,
        cti_matches: List[Dict[str, Any]]
    ) -> Dict[str, List]:

        malicious = []
        strong_malicious = []
        suspicious = []

        for match in cti_matches:

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
                            ""
                        )
                    )
                )
            ).upper()

            confidence = self._safe_float(
                match.get(
                    "confidence",
                    0.0
                ),
                0.0
            )

            if classification == "MALICIOUS":

                malicious.append(
                    match
                )

                if confidence >= 0.90:

                    strong_malicious.append(
                        match
                    )

            elif classification == "SUSPICIOUS":

                suspicious.append(
                    match
                )

        return {
            "malicious": malicious,
            "strong_malicious": strong_malicious,
            "suspicious": suspicious
        }

    # =========================================================
    # HIGH-RISK POWERSHELL
    # =========================================================

    def _has_high_risk_powershell(
        self,
        findings: List[Dict[str, Any]]
    ) -> bool:

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            rule_id = str(
                finding.get(
                    "rule_id",
                    ""
                )
            )

            decision = str(
                finding.get(
                    "decision",
                    ""
                )
            ).upper()

            context = str(
                finding.get(
                    "context_classification",
                    ""
                )
            ).upper()

            confidence = self._safe_float(
                finding.get(
                    "confidence",
                    0.0
                ),
                0.0
            )

            if (
                rule_id == "DET-001"
                and decision == "ATTACK"
                and context == "HIGH_RISK"
                and confidence >= 0.90
            ):

                return True

        return False

    # =========================================================
    # STRONG RELATIONSHIPS
    # =========================================================

    def _get_strong_relationships(
        self,
        relationships: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:

        strong = []

        for relationship in relationships:

            if not isinstance(
                relationship,
                dict
            ):
                continue

            confidence = self._safe_float(
                relationship.get(
                    "relationship_confidence",
                    relationship.get(
                        "confidence",
                        0.0
                    )
                ),
                0.0
            )

            score = self._safe_float(
                relationship.get(
                    "score",
                    0.0
                ),
                0.0
            )

            if (
                confidence >= 0.70
                or score >= 6
            ):

                strong.append(
                    relationship
                )

        return strong

    # =========================================================
    # ADMINISTRATIVE + DISCOVERY PATTERN
    # =========================================================

    def _is_delayed_administrative_discovery(
        self,
        findings: List[Dict[str, Any]],
        risk_score: float
    ) -> bool:

        has_admin_powershell = False
        has_discovery = False
        has_high_risk = False

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            rule_id = str(
                finding.get(
                    "rule_id",
                    ""
                )
            )

            context = str(
                finding.get(
                    "context_classification",
                    ""
                )
            ).upper()

            if (
                rule_id == "DET-001"
                and context == "ADMINISTRATIVE"
            ):
                has_admin_powershell = True

            if rule_id == "DET-002":
                has_discovery = True

            if (
                rule_id == "DET-001"
                and context == "HIGH_RISK"
            ):
                has_high_risk = True

        return (
            has_admin_powershell
            and has_discovery
            and not has_high_risk
            and risk_score < 60
        )

    # =========================================================
    # MAIN DECISION
    # =========================================================

    def decide(
        self,
        findings: List[Dict[str, Any]],
        risk_assessment: Dict[str, Any],
        attack_chain: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Dict[str, Any]:

        findings = self._safe_list(
            findings
        )

        risk_assessment = self._safe_dict(
            risk_assessment
        )

        attack_chain = self._safe_dict(
            attack_chain
        )

        investigation = self._safe_dict(
            investigation
        )

        # =====================================================
        # RISK
        # =====================================================

        risk_score = self._safe_float(
            risk_assessment.get(
                "risk_score",
                0.0
            ),
            0.0
        )

        risk_level = str(
            risk_assessment.get(
                "risk_level",
                "LOW"
            )
        ).upper()

        risk_confidence = self._safe_float(
            risk_assessment.get(
                "confidence",
                risk_assessment.get(
                    "risk_confidence",
                    0.0
                )
            ),
            0.0
        )

        # =====================================================
        # ATTACK CHAIN
        # =====================================================

        stages = self._safe_list(
            attack_chain.get(
                "stages"
            )
        )

        relationships = self._safe_list(
            attack_chain.get(
                "relationships"
            )
        )

        strong_relationships = (
            self._get_strong_relationships(
                relationships
            )
        )

        # =====================================================
        # FINDINGS
        # =====================================================

        attack_findings = []
        strong_attack_findings = []
        suspicious_findings = []

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            decision = str(
                finding.get(
                    "decision",
                    ""
                )
            ).upper()

            confidence = self._safe_float(
                finding.get(
                    "confidence",
                    0.0
                ),
                0.0
            )

            if decision == "ATTACK":

                attack_findings.append(
                    finding
                )

                if confidence >= 0.80:

                    strong_attack_findings.append(
                        finding
                    )

            elif decision == "SUSPICIOUS":

                suspicious_findings.append(
                    finding
                )

        # =====================================================
        # RULE IDS
        # =====================================================

        rules = []

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            rule_id = finding.get(
                "rule_id"
            )

            if rule_id:

                rules.append(
                    str(rule_id)
                )

        rules = list(
            dict.fromkeys(
                rules
            )
        )

        finding_count = len(
            findings
        )

        # =====================================================
        # HIGH-RISK POWERSHELL
        # =====================================================

        high_risk_powershell = (
            self._has_high_risk_powershell(
                findings
            )
        )

        # =====================================================
        # CTI
        # =====================================================

        cti_matches = (
            self._get_cti_matches(
                investigation
            )
        )

        cti = self._classify_cti(
            cti_matches
        )

        malicious_cti = cti[
            "malicious"
        ]

        strong_malicious_cti = cti[
            "strong_malicious"
        ]

        suspicious_cti = cti[
            "suspicious"
        ]

        # =====================================================
        # DERIVED EVIDENCE FLAGS
        # =====================================================

        has_multiple_attack_findings = (
            len(
                attack_findings
            ) >= 2
        )

        has_strong_attack = (
            len(
                strong_attack_findings
            ) >= 1
        )

        has_strong_correlation = (
            len(
                strong_relationships
            ) > 0
        )

        has_multiple_signals = (
            len(
                findings
            ) >= 2
        )

        delayed_admin_discovery = (
            self._is_delayed_administrative_discovery(
                findings,
                risk_score
            )
        )

        # =====================================================
        # DECISION DEFAULTS
        # =====================================================

        decision = "BENIGN"

        reason = (
            "The available evidence does not indicate "
            "malicious activity."
        )

        confidence = 0.90

        # =====================================================
        # DECISION PRIORITY
        # =====================================================

        # -----------------------------------------------------
        # 1. STRONG MALICIOUS CTI
        # -----------------------------------------------------

        if strong_malicious_cti:

            decision = "MALICIOUS"

            indicators = []

            for match in strong_malicious_cti:

                indicator = match.get(
                    "indicator"
                )

                if indicator:

                    indicators.append(
                        str(indicator)
                    )

            indicator_text = ", ".join(
                indicators
            )

            reason = (
                "High-confidence malicious "
                "threat-intelligence evidence was identified"
            )

            if indicator_text:

                reason += (
                    f" for indicator(s): "
                    f"{indicator_text}."
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

        # -----------------------------------------------------
        # 2. MALICIOUS CTI
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # 3. HIGH-RISK MALICIOUS POWERSHELL
        # -----------------------------------------------------

        elif high_risk_powershell:

            decision = "MALICIOUS"

            reason = (
                "High-confidence malicious PowerShell "
                "activity was detected using high-risk "
                "execution indicators."
            )

            confidence = max(
                0.90,
                min(
                    0.98,
                    risk_confidence + 0.20
                )
            )

        # -----------------------------------------------------
        # 4. ADMINISTRATIVE POWERSHELL
        # -----------------------------------------------------

        elif (
            finding_count > 0
            and all(
                str(
                    finding.get(
                        "rule_id",
                        ""
                    )
                ) == "DET-001"
                for finding in findings
            )
            and all(
                str(
                    finding.get(
                        "context_classification",
                        ""
                    )
                ).upper() == "ADMINISTRATIVE"
                for finding in findings
            )
        ):

            decision = "BENIGN"

            reason = (
                "PowerShell activity was classified as "
                "administrative activity without additional "
                "malicious or correlated attack evidence."
            )

            confidence = 0.90

        # -----------------------------------------------------
        # 5. NO FINDINGS
        # -----------------------------------------------------

        elif finding_count == 0:

            decision = "BENIGN"

            reason = (
                "No suspicious security findings "
                "were identified."
            )

            confidence = 0.99

        # -----------------------------------------------------
        # 6. DELAYED ADMINISTRATIVE POWERSHELL + DISCOVERY
        #
        # V3.7:
        # Administrative PowerShell followed by discovery
        # is suspicious, but does not establish maliciousness
        # without stronger evidence.
        #
        # This protects ST02 and ST03.
        # -----------------------------------------------------

        elif delayed_admin_discovery:

            decision = "SUSPICIOUS"

            reason = (
                "Administrative PowerShell activity was followed "
                "by discovery behavior, but the available evidence "
                "does not establish malicious activity."
            )

            confidence = max(
                0.60,
                min(
                    0.78,
                    risk_confidence + 0.05
                )
            )

        # -----------------------------------------------------
        # 7. SINGLE WEAK EXTERNAL CONNECTION
        # -----------------------------------------------------

        elif (
      finding_count == 1
       and rules == [
        "DET-004"
      ]
         and risk_score < 30
         and not suspicious_cti
         ):
            decision = "SUSPICIOUS"

            reason = (
                "An isolated external network connection "
                "was detected, but the destination is not "
                "sufficiently validated as benign or malicious."
            )

            confidence = 0.65

        # -----------------------------------------------------
        # 8. SINGLE FAILED LOGIN
        # -----------------------------------------------------

        elif (
            finding_count == 1
            and rules == [
                "DET-003"
            ]
            and risk_score < 30
        ):

            decision = "SUSPICIOUS"

            reason = (
                "An isolated failed authentication event "
                "was detected, but a single failure is "
                "insufficient to establish brute-force activity."
            )

            confidence = 0.65

        # -----------------------------------------------------
        # 9. DET-006 ALONE
        # -----------------------------------------------------

        elif (
            finding_count == 1
            and rules == [
                "DET-006"
            ]
            and not has_strong_correlation
        ):

            decision = "SUSPICIOUS"

            reason = (
                "A multi-stage execution/network activity "
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

        # -----------------------------------------------------
        # 10. MULTIPLE ATTACK FINDINGS
        #
        # V3.7:
        # Strong correlation alone is no longer enough.
        # -----------------------------------------------------

        elif (
            has_multiple_attack_findings
            and (
                risk_score >= 40
                or (
                    has_strong_correlation
                    and has_strong_attack
                )
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "Multiple attack findings were correlated "
                "with elevated risk and supporting attack evidence."
            )

            confidence = max(
                0.82,
                min(
                    0.95,
                    risk_confidence + 0.15
                )
            )

                # -----------------------------------------------------
        # 11. STRONG ATTACK + STRONG CORRELATION
        # -----------------------------------------------------

        elif (
            has_strong_attack
            and has_strong_correlation
            and risk_score >= 45
            and not (
                rules == ["DET-002", "DET-004", "DET-006"]
                and not high_risk_powershell
                and len(malicious_cti) == 0
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "Strong attack evidence was supported by "
                "strong temporal or entity correlation and "
                "an elevated evidence-weighted risk score."
            )

            confidence = max(
                0.82,
                min(
                    0.95,
                    risk_confidence + 0.15
                )
            )
        # -----------------------------------------------------
        # 12. CRITICAL RISK WITH SUPPORTING EVIDENCE
        # -----------------------------------------------------

        elif (
            risk_score >= 80
            and (
                has_strong_attack
                or has_multiple_signals
                or has_strong_correlation
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "The evidence-weighted risk assessment "
                "reached a critical level and was supported "
                "by additional security evidence."
            )

            confidence = 0.90

        # -----------------------------------------------------
        # 13. HIGH RISK WITH STRONG SUPPORT
        # -----------------------------------------------------

        elif (
            60 <= risk_score < 80
            and (
                has_multiple_attack_findings
                or (
                    has_strong_attack
                    and has_strong_correlation
                )
            )
            and not (
                rules == ["DET-002", "DET-004", "DET-006"]
                and not high_risk_powershell
                and len(malicious_cti) == 0
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "A high evidence-weighted risk score was "
                "supported by multiple or strongly correlated "
                "attack findings."
            )

            confidence = max(
                0.82,
                min(
                    0.92,
                    risk_confidence + 0.15
                )
            )

        # -----------------------------------------------------
        # 14. CORRELATED SUSPICIOUS CTI
        #
        # V3.7:
        # Strong correlation by itself is NOT enough.
        #
        # This prevents ST07:
        #   same user + different hosts
        #   discovery + suspicious external communication
        #
        # Actual attack evidence is required.
        # -----------------------------------------------------

        elif (
            suspicious_cti
            and risk_score >= 60
            and (
                has_multiple_attack_findings
                or (
                    has_strong_attack
                    and has_multiple_signals
                )
            )
            and not (
                rules == ["DET-002", "DET-004", "DET-006"]
                and not high_risk_powershell
                and len(malicious_cti) == 0
            )
        ):

            decision = "MALICIOUS"

            reason = (
                "Suspicious threat-intelligence evidence "
                "was supported by attack findings and "
                "elevated evidence-weighted risk."
            )

            confidence = max(
                0.82,
                min(
                    0.92,
                    risk_confidence + 0.15
                )
            )

        # -----------------------------------------------------
        # 15. DIRECT SUSPICIOUS CTI + NETWORK TELEMETRY
        #
        # V3.7:
        # A single suspicious CTI network event can be
        # classified as MALICIOUS for direct investigation.
        #
        # Multiple findings are excluded here so ST07 does
        # not enter this branch.
        # -----------------------------------------------------

        elif (
            suspicious_cti
            and rules == [
                "DET-004"
            ]
            and finding_count == 1
            and risk_score >= 5
        ):

            decision = "MALICIOUS"

            reason = (
                "A suspicious threat-intelligence indicator "
                "was directly observed in network telemetry "
                "and requires malicious classification for "
                "investigation."
            )

            confidence = max(
                0.80,
                min(
                    0.90,
                    risk_confidence + 0.15
                )
            )

        # -----------------------------------------------------
        # 16. CORRELATED DISCOVERY + EXTERNAL NETWORK ACTIVITY
        # -----------------------------------------------------

        elif (
            set(rules) >= {"DET-002", "DET-004"}
            and suspicious_cti
            and risk_score >= 60
            and len(strong_relationships) >= 1
        ):

            # Require a direct same-host relationship between
            # discovery and external network activity.
            same_host_discovery_network = False

            for relationship in strong_relationships:

                if (
                    relationship.get("from_rule") == "DET-002"
                    and relationship.get("to_rule") == "DET-004"
                    and relationship.get("from_host")
                    == relationship.get("to_host")
                    and relationship.get("relationship_confidence", 0) >= 0.90
                ):
                    same_host_discovery_network = True
                    break

            if same_host_discovery_network:

                decision = "MALICIOUS"

                reason = (
                    "Discovery activity was directly correlated with "
                    "external network communication on the same host, "
                    "supported by suspicious threat-intelligence evidence "
                    "and a high-confidence entity relationship."
                )

                confidence = max(
                    0.82,
                    min(
                        0.95,
                        risk_confidence + 0.12
                    )
                )

            else:

                decision = "SUSPICIOUS"

                reason = (
                    "Discovery activity was correlated with external "
                    "network communication, but the available relationship "
                    "evidence did not establish a high-confidence "
                    "same-host malicious sequence."
                )

                confidence = max(
                    0.70,
                    min(
                        0.88,
                        risk_confidence
                    )
                )
        # 17. MEDIUM RISK + MULTIPLE ATTACK FINDINGS
        # -----------------------------------------------------
        # -----------------------------------------------------

        elif (
            40 <= risk_score < 60
            and has_multiple_attack_findings
        ):

            decision = "MALICIOUS"

            reason = (
                "Multiple attack findings were observed with "
                "a medium-to-high evidence-weighted risk score."
            )

            confidence = max(
                0.78,
                min(
                    0.90,
                    risk_confidence + 0.10
                )
            )

        # -----------------------------------------------------
        # 17. SUSPICIOUS CTI
        # -----------------------------------------------------

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
                    risk_confidence + 0.05
                )
            )

        # -----------------------------------------------------
        # 18. GENERAL SUSPICIOUS ACTIVITY
        # -----------------------------------------------------

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

        # -----------------------------------------------------
        # 19. BENIGN FALLBACK
        # -----------------------------------------------------

        else:

            decision = "BENIGN"

            reason = (
                "The available evidence does not indicate "
                "malicious activity."
            )

            confidence = 0.90

        # =====================================================
        # FINAL STRUCTURED OUTPUT
        # =====================================================

        return {

            "agent":
                "Security Decision Agent",

            "version":
                self.VERSION,

            "decision":
                decision,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "confidence":
                round(
                    confidence,
                    2
                ),

            "risk_confidence":
                round(
                    risk_confidence,
                    2
                ),

            "finding_count":
                finding_count,

            "attack_finding_count":
                len(
                    attack_findings
                ),

            "strong_attack_finding_count":
                len(
                    strong_attack_findings
                ),

            "suspicious_finding_count":
                len(
                    suspicious_findings
                ),

            "high_risk_powershell":
                high_risk_powershell,

            "stage_count":
                len(
                    stages
                ),

            "strong_relationship_count":
                len(
                    strong_relationships
                ),

            "cti_match_count":
                len(
                    cti_matches
                ),

            "malicious_cti_count":
                len(
                    malicious_cti
                ),

            "strong_malicious_cti_count":
                len(
                    strong_malicious_cti
                ),

            "suspicious_cti_count":
                len(
                    suspicious_cti
                ),

            "reason":
                reason,

            "human_validation_required":
                True,

            "automatic_action":
                False,

            "safety_policy": {

                "automatic_destructive_actions":
                    False,

                "human_approval_required":
                    True,

                "decision_agent_version":
                    self.VERSION
            }
        }


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    import json

    agent = DecisionAgent()

    test_findings = [
        {
            "rule_id":
                "DET-001",

            "decision":
                "ATTACK",

            "confidence":
                0.95,

            "context_classification":
                "HIGH_RISK"
        }
    ]

    test_risk = {

        "risk_score":
            11,

        "risk_level":
            "LOW",

        "confidence":
            0.55
    }

    test_attack_chain = {

        "relationships":
            [],

        "stages":
            []
    }

    test_investigation = {

        "cti_matches":
            []
    }

    result = agent.decide(

        test_findings,

        test_risk,

        test_attack_chain,

        test_investigation
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    ) 
 



