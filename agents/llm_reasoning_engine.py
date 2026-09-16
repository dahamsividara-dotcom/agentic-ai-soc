import os
import re
from typing import Any

import requests
from dotenv import load_dotenv


class LLMReasoningEngine:

    def __init__(self):
        load_dotenv()

        self.provider = os.getenv("LLM_PROVIDER", "mock").lower()
        self.model = os.getenv("LLM_MODEL", "")
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.ollama_url = os.getenv(
            "OLLAMA_URL",
            "http://localhost:11434/api/generate",
        )

    def is_configured(self) -> bool:
        if self.provider == "mock":
            return True

        if self.provider == "ollama":
            return bool(self.model)

        if self.provider == "openai":
            return bool(
                self.api_key
                and self.api_key != "YOUR_API_KEY_HERE"
                and self.api_key.startswith("sk-")
                and self.model
            )

        return False

    def build_security_prompt(
        self,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
        risk_assessment: dict[str, Any] | None = None,
    ) -> str:

        stages = attack_chain.get("stages", [])
        if not isinstance(stages, list):
            stages = []

        stage_summary = []

        for stage in stages:
            if not isinstance(stage, dict):
                continue

            mitre = stage.get("mitre_attack", {})

            if isinstance(mitre, dict):
                technique_id = mitre.get("technique_id", "")
                technique_name = mitre.get("technique_name", "")
            else:
                technique_id = str(mitre)
                technique_name = ""

            stage_summary.append(
                {
                    "timestamp": stage.get("timestamp"),
                    "stage": stage.get("stage"),
                    "host": stage.get("host"),
                    "username": stage.get("username"),
                    "rule_id": stage.get("rule_id"),
                    "severity": stage.get("severity"),
                    "confidence": stage.get("confidence"),
                    "technique": f"{technique_id} {technique_name}".strip(),
                    "evidence": stage.get("evidence"),
                }
            )

        raw_cti_matches = investigation.get("cti_matches", [])

        if isinstance(raw_cti_matches, list):
            cti_matches = raw_cti_matches
        else:
            cti_matches = investigation.get("cti_context", [])

        if not isinstance(cti_matches, list):
            cti_matches = []

        compact_cti = []

        for match in cti_matches:
            if not isinstance(match, dict):
                continue

            compact_cti.append(
                {
                    "id": match.get("id"),
                    "title": match.get("title"),
                    "mitre_id": match.get("mitre_id"),
                    "category": match.get("category"),
                    "description": match.get("description"),
                    "investigation": match.get("investigation", []),
                }
            )

        if not isinstance(risk_assessment, dict):
            risk_assessment = {}

        compact_incident = {
            "chain_id": attack_chain.get("chain_id"),
            "status": attack_chain.get("status"),
            "risk_score": risk_assessment.get(
                "risk_score",
                attack_chain.get("risk_score")
            ),
            "risk_level": risk_assessment.get(
                "risk_level",
                attack_chain.get("status")
            ),
            "risk_confidence": risk_assessment.get("confidence"),
            "stage_count": attack_chain.get("stage_count"),
            "stages": stage_summary,
            "cti_matches": compact_cti,
        }

        return f"""
You are an evidence-grounded SOC analyst.

Analyze ONLY the supplied security evidence.

INCIDENT:
{compact_incident}

Provide a concise security assessment with:

1. Threat assessment
2. Attack-chain interpretation
3. Key evidence
4. MITRE ATT&CK techniques
5. Risk level
6. Recommended response actions
7. Uncertainty and limitations

STRICT EVIDENCE RULES:

- Do not invent evidence, users, attackers, motives, identities, or attack stages.
- Do not assume an insider, external attacker, compromised account, privilege escalation,
  lateral movement, persistence, initial access, or command-and-control unless directly
  supported by the supplied evidence.
- A PowerShell event does NOT automatically mean malicious execution.
- A failed login does NOT prove successful compromise.
- An external network connection does NOT automatically prove C2.
- A correlated sequence is an investigative hypothesis, not proof of an attack.
- Clearly label statements as OBSERVED or INFERRED when appropriate.
- If evidence is insufficient, explicitly say that the conclusion cannot be confirmed.
- Never upgrade uncertainty into certainty.
- Human approval is required before containment or destructive actions.

IMPORTANT:

Use only the supplied incident data and CTI context.
Do not add facts from your general cybersecurity knowledge.

Keep the response concise.
""".strip()

    def _extract_evidence_terms(
        self,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> set[str]:

        terms = set()

        stages = attack_chain.get("stages", [])

        if not isinstance(stages, list):
            stages = []

        for stage in stages:

            if not isinstance(stage, dict):
                continue

            for key in [
                "host",
                "username",
                "rule_id",
                "stage",
                "severity",
                "timestamp",
                "process",
                "command_line",
                "evidence",
            ]:
                value = stage.get(key)

                if value:
                    terms.add(str(value).lower())

            mitre = stage.get("mitre_attack", {})

            if isinstance(mitre, dict):

                for key in [
                    "technique_id",
                    "technique_name",
                ]:
                    value = mitre.get(key)

                    if value:
                        terms.add(str(value).lower())

        raw_cti_matches = investigation.get("cti_matches", [])

        if isinstance(raw_cti_matches, list):
            cti_matches = raw_cti_matches
        else:
            cti_matches = investigation.get("cti_context", [])

        if not isinstance(cti_matches, list):
            cti_matches = []

        for match in cti_matches:

            if not isinstance(match, dict):
                continue

            for value in match.values():

                if isinstance(value, (str, int, float)):
                    terms.add(str(value).lower())

                elif isinstance(value, list):

                    for item in value:
                        if isinstance(item, (str, int, float)):
                            terms.add(str(item).lower())

        return terms

    def validate_evidence_grounding(
        self,
        assessment: str,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
    ) -> dict[str, Any]:

        text = assessment.strip()

        unsupported_patterns = {
            "insider": r"\binsider\b",
            "external attacker": r"\bexternal attacker\b",
            "attacker identity": r"\b(attacker|threat actor)\b",
            "privilege escalation": r"\bprivilege escalation\b|\bescalat(ed|ion)\b",
            "lateral movement": r"\blateral movement\b",
            "initial access": r"\binitial access\b",
            "persistence": r"\bpersistence\b",
            "confirmed compromise": r"\bconfirmed\b.*\b(compromise|attack|breach)\b",
        }

        detected = []

        for label, pattern in unsupported_patterns.items():

            if re.search(pattern, text, re.IGNORECASE):
                detected.append(label)

        evidence_terms = self._extract_evidence_terms(
            attack_chain,
            investigation,
        )

        grounding_warnings = []

        if detected:
            grounding_warnings.extend(detected)

        if "insider" in text.lower():
            grounding_warnings.append(
                "Insider involvement cannot be determined from supplied telemetry."
            )

        if "lateral movement" in text.lower():
            grounding_warnings.append(
                "Lateral movement is not directly established by the supplied evidence."
            )

        if "privilege escalation" in text.lower():
            grounding_warnings.append(
                "Privilege escalation is not directly established by the supplied evidence."
            )

        if "initial access" in text.lower():
            grounding_warnings.append(
                "Initial access is not directly established by the supplied evidence."
            )

        if "confirmed" in text.lower() and any(
            word in text.lower()
            for word in ["attack", "compromise", "breach"]
        ):
            grounding_warnings.append(
                "The supplied telemetry does not independently confirm a malicious attack."
            )

        grounded = len(grounding_warnings) == 0

        return {
            "grounded": grounded,
            "warnings": list(dict.fromkeys(grounding_warnings)),
            "evidence_term_count": len(evidence_terms),
            "guard_status": (
                "PASSED"
                if grounded
                else "REVIEW_REQUIRED"
            ),
        }

    def _apply_grounding_guard(
        self,
        assessment: str,
        validation: dict[str, Any],
    ) -> str:

        if validation["grounded"]:
            return assessment

        warning_text = (
            "\n\n[EVIDENCE GROUNDING GUARD]\n"
            "The LLM generated one or more claims that require analyst validation.\n"
            "Those claims must not be treated as confirmed facts.\n"
        )

        for warning in validation["warnings"]:
            warning_text += f"- {warning}\n"

        warning_text += (
            "Human analyst validation is required before treating inferred claims "
            "as confirmed incident facts."
        )

        return assessment + warning_text

    def generate(
        self,
        attack_chain: dict[str, Any],
        investigation: dict[str, Any],
        risk_assessment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        prompt = self.build_security_prompt(
            attack_chain,
            investigation,
            risk_assessment,
        )

        if self.provider == "mock":

            assessment = (
                "Mock LLM assessment generated successfully. "
                "Incident requires evidence validation."
            )

            validation = self.validate_evidence_grounding(
                assessment,
                attack_chain,
                investigation,
            )

            return {
                "provider": "mock",
                "model": "local-test",
                "status": "MOCK_RESPONSE",
                "configured": True,
                "assessment": self._apply_grounding_guard(
                    assessment,
                    validation,
                ),
                "evidence_grounding": validation,
                "prompt": prompt,
            }

        if self.provider == "ollama":

            if not self.is_configured():

                return {
                    "provider": "ollama",
                    "model": self.model,
                    "status": "LLM_CONFIGURATION_REQUIRED",
                    "configured": False,
                    "assessment": "Ollama model is not configured.",
                    "prompt": prompt,
                }

            try:

                response = requests.post(
                    self.ollama_url,
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                    timeout=600,
                )

                response.raise_for_status()

                data = response.json()

                if not isinstance(data, dict):
                    raise ValueError(
                        "Ollama returned an unexpected response format."
                    )

                assessment = data.get("response", "")

                if not isinstance(assessment, str):
                    assessment = str(assessment)

                assessment = assessment.strip()

                if not assessment:
                    raise ValueError(
                        "Ollama returned an empty response."
                    )

                validation = self.validate_evidence_grounding(
                    assessment,
                    attack_chain,
                    investigation,
                )

                guarded_assessment = self._apply_grounding_guard(
                    assessment,
                    validation,
                )

                return {
                    "provider": "ollama",
                    "model": self.model,
                    "status": "LLM_RESPONSE",
                    "configured": True,
                    "assessment": guarded_assessment,
                    "evidence_grounding": validation,
                    "prompt": prompt,
                }

            except Exception as exc:

                return {
                    "provider": "ollama",
                    "model": self.model,
                    "status": "LLM_ERROR",
                    "configured": True,
                    "assessment": (
                        "The local LLM request failed. "
                        "The incident remains pending human validation."
                    ),
                    "error": str(exc),
                    "prompt": prompt,
                }

        if self.provider == "openai":

            return {
                "provider": "openai",
                "model": self.model,
                "status": "OPENAI_DISABLED",
                "configured": False,
                "assessment": (
                    "OpenAI API mode is currently disabled. "
                    "Use the local Ollama provider."
                ),
                "prompt": prompt,
            }

        return {
            "provider": self.provider,
            "model": self.model,
            "status": "UNSUPPORTED_PROVIDER",
            "configured": False,
            "assessment": "Unsupported LLM provider.",
            "prompt": prompt,
        }


if __name__ == "__main__":

    engine = LLMReasoningEngine()

    print("=" * 70)
    print("AGENTIC AI-SOC - LLM REASONING ENGINE")
    print("=" * 70)
    print(f"Provider       : {engine.provider}")
    print(f"Model          : {engine.model}")
    print(f"Configured     : {engine.is_configured()}")
    print("Evidence Guard : ENABLED")
    print("Status         : READY")
