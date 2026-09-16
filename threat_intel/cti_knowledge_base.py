"""
Agentic AI-SOC
Cyber Threat Intelligence Knowledge Base v2
"""

from typing import Any


class CTIKnowledgeBase:

    VERSION = "2.0"

    KNOWLEDGE = [
        {
            "id": "CTI-001",
            "title": "PowerShell Abuse",
            "keywords": ["powershell", "powershell.exe"],
            "mitre_id": "T1059.001",
            "category": "Execution",
            "description": "PowerShell can be abused to execute commands and scripts.",
            "investigation": [
                "Review the complete PowerShell command line.",
                "Identify the parent process.",
                "Check for encoded or obfuscated commands.",
                "Correlate with subsequent network activity."
            ]
        },
        {
            "id": "CTI-002",
            "title": "System Owner/User Discovery",
            "keywords": ["whoami", "user discovery", "system owner"],
            "mitre_id": "T1033",
            "category": "Discovery",
            "description": "Account discovery activity may indicate attacker reconnaissance.",
            "investigation": [
                "Review the account executing the command.",
                "Check for additional discovery commands.",
                "Correlate activity with privilege changes."
            ]
        },
        {
            "id": "CTI-003",
            "title": "Brute Force Activity",
            "keywords": ["failed login", "failed authentication", "brute force"],
            "mitre_id": "T1110",
            "category": "Credential Access",
            "description": "Repeated authentication failures may indicate brute-force activity.",
            "investigation": [
                "Count failed authentication attempts.",
                "Identify the source address.",
                "Check whether a successful login followed.",
                "Review affected accounts."
            ]
        },
        {
            "id": "CTI-004",
            "title": "External Network Communication",
            "keywords": [
                "external ip",
                "network connection",
                "outbound connection",
                "command and control"
            ],
            "mitre_id": "T1071",
            "category": "Command and Control",
            "description": "Unexpected outbound communication may require investigation.",
            "investigation": [
                "Identify the destination address.",
                "Check destination reputation.",
                "Review connection frequency.",
                "Correlate the connection with preceding processes."
            ]
        },
        {
            "id": "CTI-IOC-001",
            "title": "Suspicious C2 IPv4 Address",
            "indicator": "203.0.113.50",
            "indicator_type": "IPv4",
            "classification": "SUSPICIOUS",
            "confidence": 0.90,
            "category": "Command and Control",
            "mitre_id": "T1071",
            "description": "Synthetic CTI identifies this address as a suspicious C2 indicator.",
            "investigation": [
                "Review all connections to this destination.",
                "Identify the process responsible for the connection.",
                "Correlate with preceding execution activity.",
                "Validate the indicator against external CTI sources."
            ]
        },
        {
            "id": "CTI-IOC-002",
            "title": "Known Malicious Botnet IPv4 Address",
            "indicator": "198.51.100.25",
            "indicator_type": "IPv4",
            "classification": "MALICIOUS",
            "confidence": 0.95,
            "category": "Command and Control",
            "mitre_id": "T1071",
            "description": "Synthetic CTI identifies this address as a malicious botnet indicator.",
            "investigation": [
                "Identify all hosts communicating with the indicator.",
                "Review the initiating process and command line.",
                "Investigate possible command-and-control activity.",
                "Consider host containment after analyst validation."
            ]
        },
        {
            "id": "CTI-IOC-003",
            "title": "Malicious Example Domain",
            "indicator": "malicious-example.test",
            "indicator_type": "DOMAIN",
            "classification": "MALICIOUS",
            "confidence": 0.94,
            "category": "Phishing",
            "mitre_id": "T1566",
            "description": "Synthetic CTI identifies this domain as a malicious phishing indicator.",
            "investigation": [
                "Review DNS resolution history.",
                "Identify affected endpoints.",
                "Review email or browser telemetry.",
                "Validate the indicator using trusted CTI sources."
            ]
        }
    ]

    def search(self, query: str) -> list[dict[str, Any]]:

        query = str(query or "").lower().strip()

        if not query:
            return []

        results = []

        for entry in self.KNOWLEDGE:

            searchable = " ".join([
                str(entry.get("title", "")),
                str(entry.get("category", "")),
                str(entry.get("description", "")),
                str(entry.get("mitre_id", "")),
                str(entry.get("indicator", "")),
                str(entry.get("indicator_type", "")),
                str(entry.get("classification", "")),
                " ".join(entry.get("keywords", []))
            ]).lower()

            if query in searchable:
                results.append(entry)

        return results

    def search_indicator(
        self,
        indicator: str
    ) -> list[dict[str, Any]]:

        indicator = str(indicator or "").strip().lower()

        if not indicator:
            return []

        return [
            entry
            for entry in self.KNOWLEDGE
            if str(
                entry.get("indicator", "")
            ).strip().lower() == indicator
        ]

    def search_by_mitre(
        self,
        mitre_id: str
    ) -> list[dict[str, Any]]:

        mitre_id = str(mitre_id or "").strip().lower()

        return [
            entry
            for entry in self.KNOWLEDGE
            if str(
                entry.get("mitre_id", "")
            ).lower() == mitre_id
        ]

    def get_context(
        self,
        queries: list[str]
    ) -> list[dict[str, Any]]:

        results = []
        seen = set()

        for query in queries:

            for entry in self.search(str(query)):

                if entry["id"] not in seen:
                    seen.add(entry["id"])
                    results.append(entry)

        return results

    def get_indicator_context(
        self,
        indicators: list[str]
    ) -> list[dict[str, Any]]:

        results = []
        seen = set()

        for indicator in indicators:

            for entry in self.search_indicator(indicator):

                if entry["id"] not in seen:
                    seen.add(entry["id"])
                    results.append(entry)

        return results


if __name__ == "__main__":

    kb = CTIKnowledgeBase()

    print("Agentic AI-SOC CTI Knowledge Base")
    print("=" * 50)
    print(f"Version: {kb.VERSION}")
    print(f"Knowledge Entries: {len(kb.KNOWLEDGE)}")

    print("\nTest IOC: 203.0.113.50")

    for result in kb.search_indicator("203.0.113.50"):
        print(
            f"- {result['id']} | "
            f"{result['classification']} | "
            f"{result['confidence']}"
        )

    print("\nTest IOC: 198.51.100.25")

    for result in kb.search_indicator("198.51.100.25"):
        print(
            f"- {result['id']} | "
            f"{result['classification']} | "
            f"{result['confidence']}"
        )

    print("\nStatus: READY") 