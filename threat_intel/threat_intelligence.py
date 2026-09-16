"""
Agentic AI-SOC
Threat Intelligence Engine v1

Local IOC extraction and threat-intelligence enrichment.
"""

import ipaddress
import re
from typing import Any


class ThreatIntelligenceEngine:
    """Extracts and enriches Indicators of Compromise (IOCs)."""

    IOC_TYPES = {
        "ipv4",
        "domain",
        "sha256",
        "md5",
    }

    # Synthetic/local intelligence for development and testing.
    # These are intentionally non-real indicators.
    LOCAL_INTELLIGENCE = {
        "203.0.113.50": {
            "type": "ipv4",
            "threat": "SUSPICIOUS",
            "confidence": 0.90,
            "category": "Command and Control",
        },
        "198.51.100.25": {
            "type": "ipv4",
            "threat": "MALICIOUS",
            "confidence": 0.95,
            "category": "Botnet",
        },
        "malicious-example.test": {
            "type": "domain",
            "threat": "MALICIOUS",
            "confidence": 0.94,
            "category": "Phishing",
        },
    }

    def analyze_event(
        self,
        event: dict[str, Any]
    ) -> dict[str, Any]:

        text = self._event_to_text(event)
        indicators = self.extract_iocs(text)

        enriched = []

        for indicator in indicators:
            enriched.append(
                self.enrich_indicator(indicator)
            )

        return {
            "indicator_count": len(enriched),
            "indicators": enriched,
        }

    def extract_iocs(
        self,
        text: str
    ) -> list[dict[str, str]]:

        indicators = []

        # IPv4 extraction
        ip_pattern = (
            r"\b(?:"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"\b"
        )

        for ip in re.findall(ip_pattern, text):
            if self._valid_ipv4(ip):
                indicators.append({
                    "value": ip,
                    "type": "ipv4",
                })

        # SHA-256
        for value in re.findall(
            r"\b[a-fA-F0-9]{64}\b",
            text
        ):
            indicators.append({
                "value": value.lower(),
                "type": "sha256",
            })

        # MD5
        for value in re.findall(
            r"\b[a-fA-F0-9]{32}\b",
            text
        ):
            indicators.append({
                "value": value.lower(),
                "type": "md5",
            })

        # Domains
        domain_pattern = (
            r"\b(?:[a-zA-Z0-9-]+\.)+"
            r"[a-zA-Z]{2,}\b"
        )

        for domain in re.findall(
            domain_pattern,
            text
        ):
            if not self._looks_like_internal_domain(domain) and not self._looks_like_process_name(domain):
                indicators.append({
                    "value": domain.lower(),
                    "type": "domain",
                })

        return self._deduplicate(indicators)

    def enrich_indicator(
        self,
        indicator: dict[str, str]
    ) -> dict[str, Any]:

        value = indicator["value"]
        indicator_type = indicator["type"]

        intelligence = self.LOCAL_INTELLIGENCE.get(
            value
        )

        if intelligence:
            return {
                "value": value,
                "type": indicator_type,
                "threat": intelligence["threat"],
                "confidence": intelligence["confidence"],
                "category": intelligence["category"],
                "source": "LOCAL_TEST_INTELLIGENCE",
            }

        return {
            "value": value,
            "type": indicator_type,
            "threat": "UNKNOWN",
            "confidence": 0.0,
            "category": "No intelligence available",
            "source": "LOCAL_TEST_INTELLIGENCE",
        }

    @staticmethod
    def _event_to_text(
        event: dict[str, Any]
    ) -> str:

        return " ".join(
            str(value)
            for value in event.values()
            if value is not None
        )

    @staticmethod
    def _valid_ipv4(
        value: str
    ) -> bool:

        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _looks_like_internal_domain(
        domain: str
    ) -> bool:

        internal_suffixes = (
            ".local",
            ".internal",
            ".lan",
        )

        return domain.lower().endswith(
            internal_suffixes
        )

    @staticmethod
    def _looks_like_process_name(domain: str) -> bool:
        return domain.lower().endswith(".exe")

    @staticmethod
    def _deduplicate(
        indicators: list[dict[str, str]]
    ) -> list[dict[str, str]]:

        unique = []
        seen = set()

        for indicator in indicators:
            key = (
                indicator["type"],
                indicator["value"].lower(),
            )

            if key not in seen:
                seen.add(key)
                unique.append(indicator)

        return unique


if __name__ == "__main__":
    print("Agentic AI-SOC Threat Intelligence Engine")
    print("=" * 48)
    print("Threat Intelligence Engine v1 initialized.")
    print("Mode: IOC Extraction + Local Intelligence")
    print("Status: READY")

