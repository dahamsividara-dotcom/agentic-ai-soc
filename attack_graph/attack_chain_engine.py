"""
Agentic AI-SOC
Attack Chain Reasoning Engine v4

Evidence-aware temporal and entity correlation engine.
"""

from datetime import datetime, timezone
from typing import Any


class AttackChainEngine:

    SEVERITY_WEIGHT = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 35,
        "CRITICAL": 50,
    }

    CORRELATION_WINDOW_MINUTES = 15
    MIN_RELATIONSHIP_SCORE = 2

    def build_chain(
        self,
        findings: list[dict[str, Any]]
    ) -> dict[str, Any]:

        if not findings:
            return self._empty_chain()

        ordered = sorted(
            findings,
            key=self._timestamp
        )

        correlated, relationships = (
            self._correlate_findings(ordered)
        )

        stages = [
            self._build_stage(finding)
            for finding in correlated
        ]

        risk_score = self._calculate_risk(
            correlated,
            relationships,
            stages,
        )

        evidence = self._build_evidence(
            correlated
        )

        uncertainty = self._build_uncertainty(
            correlated,
            stages,
            relationships,
        )

        return {
            "chain_id": "CHAIN-001",
            "status": self._risk_status(risk_score),
            "risk_score": risk_score,
            "stage_count": len(stages),
            "stages": stages,
            "evidence": evidence,
            "relationships": relationships,
            "uncertainty": uncertainty,
            "explanation": self._build_explanation(
                correlated,
                stages,
                relationships,
                risk_score,
                uncertainty,
            ),
        }

    @staticmethod
    def _empty_chain() -> dict[str, Any]:

        return {
            "chain_id": "CHAIN-000",
            "status": "LOW",
            "risk_score": 0,
            "stage_count": 0,
            "stages": [],
            "evidence": [],
            "relationships": [],
            "uncertainty": {
                "level": "HIGH",
                "reasons": [
                    "No security findings were available."
                ],
            },
            "explanation": (
                "No security findings were available "
                "for correlation."
            ),
        }

    def _correlate_findings(
        self,
        findings: list[dict[str, Any]]
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]]
    ]:

        if len(findings) <= 1:
            return findings, []

        correlated = [findings[0]]
        relationships = []

        for current in findings[1:]:

            best_relationship = None
            best_score = 0

            for previous in correlated:

                score, reasons = (
                    self._relationship_score(
                        previous,
                        current,
                    )
                )

                if score > best_score:
                    best_score = score
                    best_relationship = (
                        previous,
                        reasons,
                    )

            if (
                best_relationship
                and best_score >= self.MIN_RELATIONSHIP_SCORE
            ):

                previous, reasons = best_relationship

                correlated.append(current)

                relationships.append({
                    "from_rule": previous.get(
                        "rule_id"
                    ),
                    "to_rule": current.get(
                        "rule_id"
                    ),
                    "from_host": previous.get(
                        "host"
                    ),
                    "to_host": current.get(
                        "host"
                    ),
                    "from_user": previous.get(
                        "username"
                    ),
                    "to_user": current.get(
                        "username"
                    ),
                    "score": best_score,
                    "reasons": reasons,
                    "relationship_confidence":
                        self._relationship_confidence(
                            best_score
                        ),
                })

            elif current.get("severity") in {
                "HIGH",
                "CRITICAL",
            }:

                correlated.append(current)

                relationships.append({
                    "from_rule": None,
                    "to_rule": current.get(
                        "rule_id"
                    ),
                    "from_host": None,
                    "to_host": current.get(
                        "host"
                    ),
                    "from_user": None,
                    "to_user": current.get(
                        "username"
                    ),
                    "score": 1,
                    "reasons": [
                        "High-severity finding retained "
                        "for investigation"
                    ],
                    "relationship_confidence": 0.35,
                })

        return correlated, relationships

    def _relationship_score(
        self,
        previous: dict[str, Any],
        current: dict[str, Any],
    ) -> tuple[int, list[str]]:

        score = 0
        reasons = []

        previous_time = self._timestamp(
            previous
        )

        current_time = self._timestamp(
            current
        )

        if (
            previous_time != datetime.max
            and current_time != datetime.max
        ):

            delta = (
                current_time - previous_time
            ).total_seconds() / 60

            if (
                0 <= delta
                <= self.CORRELATION_WINDOW_MINUTES
            ):

                score += 2

                reasons.append(
                    "Temporal proximity"
                )

        previous_host = previous.get(
            "host"
        )

        current_host = current.get(
            "host"
        )

        if (
            previous_host
            and current_host
            and previous_host == current_host
        ):

            score += 3

            reasons.append(
                "Same host"
            )

        previous_user = previous.get(
            "username"
        )

        current_user = current.get(
            "username"
        )

        if (
            previous_user
            and current_user
            and previous_user == current_user
        ):

            score += 3

            reasons.append(
                "Same user"
            )

        previous_ip = previous.get(
            "source_ip"
        )

        current_ip = current.get(
            "source_ip"
        )

        if (
            previous_ip
            and current_ip
            and previous_ip == current_ip
        ):

            score += 2

            reasons.append(
                "Same source IP"
            )

        previous_destination = previous.get(
            "destination_ip"
        )

        if (
            previous_destination
            and current_ip
            and previous_destination == current_ip
        ):

            score += 2

            reasons.append(
                "Network continuity"
            )

        previous_mitre = self._mitre_id(
            previous.get("mitre_attack")
        )

        current_mitre = self._mitre_id(
            current.get("mitre_attack")
        )

        if (
            previous_mitre
            and current_mitre
            and previous_mitre == current_mitre
        ):

            score += 2

            reasons.append(
                "Same MITRE technique"
            )

        return score, reasons

    @staticmethod
    def _relationship_confidence(
        score: int
    ) -> float:

        if score >= 8:
            return 0.95

        if score >= 6:
            return 0.85

        if score >= 4:
            return 0.70

        if score >= 2:
            return 0.55

        return 0.35

    def _build_stage(
        self,
        finding: dict[str, Any]
    ) -> dict[str, Any]:

        stage, classification = (
            self._classify_stage(
                finding
            )
        )

        return {
            "timestamp": finding.get(
                "timestamp"
            ),
            "stage": stage,
            "classification": classification,
            "rule_id": finding.get(
                "rule_id"
            ),
            "title": finding.get(
                "title"
            ),
            "severity": finding.get(
                "severity"
            ),
            "confidence": finding.get(
                "confidence"
            ),
            "host": finding.get(
                "host"
            ),
            "username": finding.get(
                "username"
            ),
            "source_ip": finding.get(
                "source_ip"
            ),
            "destination_ip": finding.get(
                "destination_ip"
            ),
            "mitre_attack": finding.get(
                "mitre_attack"
            ),
            "evidence": finding.get(
                "reason"
            ),
        }

    @staticmethod
    def _classify_stage(
        finding: dict[str, Any]
    ) -> tuple[str, str]:

        rule_id = finding.get(
            "rule_id"
        )

        mapping = {
            "DET-001": (
                "Execution",
                "OBSERVED",
            ),

            "DET-002": (
                "Discovery",
                "OBSERVED",
            ),

            "DET-003": (
                "Credential Access",
                "OBSERVED",
            ),

            "DET-004": (
                "Network Activity",
                "OBSERVED",
            ),

            "DET-005": (
                "Credential Access",
                "OBSERVED",
            ),

            "DET-006": (
                "Execution",
                "OBSERVED",
            ),
        }

        return mapping.get(
            rule_id,
            (
                "Unknown",
                "UNCERTAIN",
            ),
        )

    @staticmethod
    def _mitre_id(
        mitre: Any
    ) -> str:

        if isinstance(
            mitre,
            dict,
        ):

            return str(
                mitre.get("technique_id")
                or mitre.get("id")
                or ""
            )

        if mitre:
            return str(mitre)

        return ""

    def _calculate_risk(
        self,
        findings: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        stages: list[dict[str, Any]],
    ) -> int:

        if not findings:
            return 0

        score = 0.0

        for finding in findings:

            severity = finding.get(
                "severity",
                "LOW",
            )

            confidence = float(
                finding.get(
                    "confidence",
                    0.5,
                )
            )

            weight = self.SEVERITY_WEIGHT.get(
                severity,
                10,
            )

            score += (
                weight * confidence
            )

        if len(findings) >= 2:
            score += 5

        if len(findings) >= 3:
            score += 8

        if len(findings) >= 4:
            score += 10

        strong_relationships = sum(
            1
            for relationship in relationships
            if relationship.get(
                "score",
                0,
            ) >= 5
        )

        score += min(
            strong_relationships * 4,
            16,
        )

        observed_stages = {
            stage.get("stage")
            for stage in stages
            if stage.get(
                "classification"
            ) == "OBSERVED"
        }

        if len(observed_stages) >= 2:
            score += 5

        if len(observed_stages) >= 3:
            score += 5

        return min(
            round(score),
            100,
        )

    @staticmethod
    def _risk_status(
        risk_score: int
    ) -> str:

        if risk_score >= 80:
            return "CRITICAL"

        if risk_score >= 60:
            return "HIGH"

        if risk_score >= 30:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _build_evidence(
        findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:

        evidence = []

        for finding in findings:

            evidence.append({
                "classification": "OBSERVED",
                "rule_id": finding.get(
                    "rule_id"
                ),
                "timestamp": finding.get(
                    "timestamp"
                ),
                "host": finding.get(
                    "host"
                ),
                "username": finding.get(
                    "username"
                ),
                "reason": finding.get(
                    "reason"
                ),
                "mitre_attack": finding.get(
                    "mitre_attack"
                ),
            })

        return evidence

    @staticmethod
    def _build_uncertainty(
        findings: list[dict[str, Any]],
        stages: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
    ) -> dict[str, Any]:

        reasons = []

        if not findings:
            reasons.append(
                "No findings available."
            )

        if not relationships:
            reasons.append(
                "No strong event relationships identified."
            )

        if any(
            stage.get("stage")
            == "Network Activity"
            for stage in stages
        ):

            reasons.append(
                "External network activity does not "
                "independently prove command-and-control."
            )

        if any(
            stage.get("stage")
            == "Credential Access"
            for stage in stages
        ):

            reasons.append(
                "Authentication activity does not "
                "independently prove successful initial access."
            )

        reasons.append(
            "Attack-chain relationships are hypotheses "
            "derived from available telemetry."
        )

        return {
            "level": (
                "MEDIUM"
                if reasons
                else "LOW"
            ),
            "reasons": reasons,
            "human_validation_required": True,
        }

    @staticmethod
    def _timestamp(
        finding: dict[str, Any]
    ) -> datetime:

        value = finding.get(
            "timestamp"
        )

        if not value:
            return datetime.max

        try:

            parsed = datetime.fromisoformat(
                str(value).replace(
                    "Z",
                    "+00:00",
                )
            )

            if parsed.tzinfo is None:

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed

        except ValueError:

            return datetime.max

    @staticmethod
    def _build_explanation(
        findings: list[dict[str, Any]],
        stages: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        risk_score: int,
        uncertainty: dict[str, Any],
    ) -> str:

        if not stages:

            return (
                "No correlated attack activity "
                "was identified."
            )

        stage_names = [
            stage.get("stage")
            for stage in stages
        ]

        hosts = sorted({
            stage.get("host")
            for stage in stages
            if stage.get("host")
        })

        users = sorted({
            stage.get("username")
            for stage in stages
            if stage.get("username")
        })

        return (
            f"Correlated {len(findings)} security "
            f"findings across {len(hosts)} host(s) "
            f"and {len(users)} user(s). "
            f"Observed activity includes "
            f"{' -> '.join(stage_names)}. "
            f"{len(relationships)} relationship(s) "
            f"were identified using temporal and "
            f"entity-based signals. "
            f"Calculated risk score: "
            f"{risk_score}/100. "
            f"Uncertainty level: "
            f"{uncertainty.get('level')}. "
            "The chain represents an investigative "
            "hypothesis and requires validation "
            "before response actions."
        )


if __name__ == "__main__":

    print(
        "Agentic AI-SOC Attack Chain Engine"
    )
    print("=" * 45)
    print(
        "Attack Chain Engine v4 initialized."
    )
    print(
        "Mode: Evidence-Aware Temporal + "
        "Entity Correlation"
    )
    print(
        "Features: Evidence Classification + "
        "Uncertainty Analysis"
    )
    print("Status: READY")
