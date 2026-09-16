from typing import Any, Dict, List, Optional


class ResponseAgent:
    """
    Incident Response Agent

    Converts the final Risk Assessment and Security Decision
    into safe, human-approved response recommendations.

    No destructive action is executed automatically.
    """

    VERSION = "1.1"

    def __init__(self) -> None:
        self.agent_name = "Incident Response Agent"

    # =========================================================
    # MAIN RESPONSE RECOMMENDATION
    # =========================================================

    def recommend(
        self,
        events: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        attack_chain: Dict[str, Any],
        investigation: Dict[str, Any],
        risk_assessment: Dict[str, Any],
        decision: Dict[str, Any],
        reasoning: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate incident response recommendations.

        `reasoning` is accepted for compatibility with the
        SOC orchestrator, but the authoritative risk comes from
        Risk Assessment Agent.
        """

        # =====================================================
        # AUTHORITATIVE RISK
        # =====================================================

        risk_score = float(
            risk_assessment.get("risk_score", 0)
        )

        risk_level = str(
            risk_assessment.get(
                "risk_level",
                "UNKNOWN"
            )
        ).upper()

        final_decision = str(
            decision.get(
                "decision",
                "BENIGN"
            )
        ).upper()

        # =====================================================
        # RESPONSE ACTIONS
        # =====================================================

        actions: List[Dict[str, Any]] = []

        # =====================================================
        # MALICIOUS / HIGH-RISK
        # =====================================================

        if final_decision == "MALICIOUS" or risk_score >= 60:

            actions.append(
                {
                    "action_id": "IR-001",
                    "action": "Isolate affected host",
                    "priority": "HIGH",
                    "reason": (
                        "High-confidence malicious or high-risk "
                        "activity requires containment review."
                    ),
                    "requires_human_approval": True,
                    "destructive": False
                }
            )

            external_destinations = (
                self._get_external_destinations(events)
            )

            if external_destinations:

                actions.append(
                    {
                        "action_id": "IR-002",
                        "action": (
                            "Block suspicious external destination"
                        ),
                        "priority": "HIGH",
                        "reason": (
                            "Reduce potential malicious network "
                            "communication after analyst validation."
                        ),
                        "destinations": external_destinations,
                        "requires_human_approval": True,
                        "destructive": False
                    }
                )

            actions.append(
                {
                    "action_id": "IR-003",
                    "action": "Review affected user accounts",
                    "priority": "MEDIUM",
                    "reason": (
                        "Review authentication and account activity "
                        "associated with the incident."
                    ),
                    "requires_human_approval": True,
                    "destructive": False
                }
            )

            response_status = "PENDING_HUMAN_APPROVAL"

        # =====================================================
        # SUSPICIOUS
        # =====================================================

        elif final_decision == "SUSPICIOUS" or risk_score >= 30:

            actions.append(
                {
                    "action_id": "IR-004",
                    "action": "Investigate affected host",
                    "priority": "MEDIUM",
                    "reason": (
                        "Suspicious activity requires additional "
                        "endpoint investigation."
                    ),
                    "requires_human_approval": True,
                    "destructive": False
                }
            )

            actions.append(
                {
                    "action_id": "IR-005",
                    "action": "Review network activity",
                    "priority": "MEDIUM",
                    "reason": (
                        "Review observed network connections and "
                        "destination context."
                    ),
                    "requires_human_approval": True,
                    "destructive": False
                }
            )

            response_status = "PENDING_HUMAN_APPROVAL"

        # =====================================================
        # BENIGN
        # =====================================================

        else:

            actions.append(
                {
                    "action_id": "IR-006",
                    "action": "Continue monitoring",
                    "priority": "LOW",
                    "reason": (
                        "Available evidence does not currently "
                        "require containment."
                    ),
                    "requires_human_approval": False,
                    "destructive": False
                }
            )

            response_status = "MONITORING"

        # =====================================================
        # SAFETY POLICY
        # =====================================================

        safety_policy = {
            "automatic_destructive_actions": False,
            "human_approval_required": True
        }

        # =====================================================
        # FINAL RESPONSE
        # =====================================================

        return {
            "agent": self.agent_name,
            "version": self.VERSION,

            # Authoritative values come from Risk Assessment Agent
            "threat_assessment": risk_level,
            "risk_score": risk_score,
            "risk_level": risk_level,

            "final_decision": final_decision,

            "response_status": response_status,

            "actions": actions,

            "safety_policy": safety_policy
        }

    # =========================================================
    # EXTERNAL DESTINATION EXTRACTION
    # =========================================================

    @staticmethod
    def _get_external_destinations(
        events: List[Dict[str, Any]]
    ) -> List[str]:

        destinations: List[str] = []

        for event in events:

            destination_ip = event.get(
                "destination_ip"
            )

            if destination_ip:

                destination_ip = str(
                    destination_ip
                )

                if destination_ip not in destinations:
                    destinations.append(
                        destination_ip
                    )

        return destinations 