from typing import Any
from ipaddress import ip_address, ip_network


class DetectionEngine:
    """
    Agentic AI-SOC Detection Engine V4

    Context-aware detection layer.

    Key improvements:
    - Distinguishes legitimate and suspicious PowerShell usage
    - Context-aware system discovery detection
    - RFC1918-aware external IP detection
    - Multi-stage attack correlation
    - Explicit MITRE ATT&CK mappings
    - Correlation-only findings do not create fake ATT&CK mappings
    """

    VERSION = "4.0"

    PRIVATE_NETWORKS = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
    ]

    RULES = {

        "DET-001": {
            "title": "PowerShell Process Activity",
            "severity": "MEDIUM",
            "confidence": 0.82,
            "decision": "SUSPICIOUS",
            "mitre_attack": {
                "technique_id": "T1059.001",
                "technique": "PowerShell",
            },
        },

        "DET-002": {
            "title": "System Discovery Command",
            "severity": "MEDIUM",
            "confidence": 0.86,
            "decision": "SUSPICIOUS",
            "mitre_attack": {
                "technique_id": "T1033",
                "technique": "System Owner/User Discovery",
            },
        },

        "DET-003": {
            "title": "Failed Authentication Attempt",
            "severity": "LOW",
            "confidence": 0.70,
            "decision": "SUSPICIOUS",
            "mitre_attack": {
                "technique_id": "T1110",
                "technique": "Brute Force",
            },
        },

        "DET-004": {
            "title": "External Network Connection",
            "severity": "LOW",
            "confidence": 0.68,
            "decision": "SUSPICIOUS",
            "mitre_attack": {
                "technique_id": "T1071",
                "technique": "Application Layer Protocol",
            },
        },

        "DET-005": {
            "title": "Repeated Failed Authentication",
            "severity": "HIGH",
            "confidence": 0.91,
            "decision": "ATTACK",
            "mitre_attack": {
                "technique_id": "T1110",
                "technique": "Brute Force",
            },
        },

        "DET-006": {
            "title": "Multi-Stage Suspicious Activity",
            "severity": "HIGH",
            "confidence": 0.88,
            "decision": "ATTACK",
            "mitre_attack": None,
        },
    }

    # ---------------------------------------------------------
    # Constructor
    # ---------------------------------------------------------

    def __init__(self):
        pass

    # ---------------------------------------------------------
    # Utility
    # ---------------------------------------------------------

    @staticmethod
    def _text(value: Any) -> str:

        if value is None:
            return ""

        return str(value).strip()

    @classmethod
    def _is_private_ip(
        cls,
        ip: Any,
    ) -> bool:

        if not ip:
            return False

        try:

            address = ip_address(
                str(ip).strip()
            )

            return any(
                address in network
                for network in cls.PRIVATE_NETWORKS
            )

        except ValueError:

            return False

    # ---------------------------------------------------------
    # Finding creation
    # ---------------------------------------------------------

    def _create_finding(
        self,
        rule_id: str,
        event: dict[str, Any],
        reason: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        rule = self.RULES[rule_id]

        finding = {

            "rule_id":
                rule_id,

            "title":
                rule["title"],

            "severity":
                rule["severity"],

            "confidence":
                rule["confidence"],

            "decision":
                rule["decision"],

            "timestamp":
                event.get("timestamp"),

            "host":
                event.get("source"),

            "username":
                event.get("username"),

            "source_ip":
                event.get("source_ip"),

            "destination_ip":
                event.get("destination_ip"),

            "process":
                event.get("process"),

            "command_line":
                event.get("command_line"),

            "message":
                event.get("message"),

            "reason":
                reason,

            "mitre_attack":
                rule["mitre_attack"],
        }

        if extra:
            finding.update(extra)

        return finding

    # ---------------------------------------------------------
    # PowerShell context analysis
    # ---------------------------------------------------------

    def _powershell_context(
        self,
        event: dict[str, Any],
    ) -> tuple[str, float]:

        command = self._text(
            event.get("command_line")
        ).lower()

        # High-risk PowerShell indicators
        malicious_indicators = [
            "-enc",
            "-encodedcommand",
            "invoke-expression",
            "iex ",
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "start-bitstransfer",
            "frombase64string",
            "reflection.assembly",
        ]

        for indicator in malicious_indicators:

            if indicator in command:

                return (
                    "HIGH_RISK",
                    0.95,
                )

        # Administrative / informational commands
        benign_indicators = [
            "get-process",
            "get-service",
            "get-date",
            "get-childitem",
            "get-computerinfo",
            "get-help",
        ]

        for indicator in benign_indicators:

            if indicator in command:

                return (
                    "ADMINISTRATIVE",
                    0.35,
                )

        return (
            "UNKNOWN",
            0.60,
        )

    # ---------------------------------------------------------
    # Discovery context analysis
    # ---------------------------------------------------------

    def _discovery_context(
        self,
        event: dict[str, Any],
    ) -> tuple[str, float]:

        command = self._text(
            event.get("command_line")
        ).lower()

        high_value_discovery = [
            "whoami",
            "net user",
            "net group",
        ]

        low_context_discovery = [
            "ipconfig",
            "systeminfo",
            "tasklist",
        ]

        for indicator in high_value_discovery:

            if indicator in command:

                return (
                    "HIGH_VALUE_DISCOVERY",
                    0.86,
                )

        for indicator in low_context_discovery:

            if indicator in command:

                return (
                    "LOW_VALUE_DISCOVERY",
                    0.65,
                )

        return (
            "UNKNOWN",
            0.50,
        )

    # ---------------------------------------------------------
    # Main analysis
    # ---------------------------------------------------------

    def analyze(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        # =====================================================
        # Event-level detection
        # =====================================================

        for event in events:

            process = self._text(
                event.get("process")
            ).lower()

            command_line = self._text(
                event.get("command_line")
            ).lower()

            event_type = self._text(
                event.get("event_type")
            ).lower()

            destination_ip = self._text(
                event.get("destination_ip")
            )

            # -------------------------------------------------
            # PowerShell
            # -------------------------------------------------

            if (
                "powershell" in process
                or "powershell" in command_line
            ):

                context, context_confidence = (
                    self._powershell_context(
                        event
                    )
                )

                if context == "HIGH_RISK":

                    finding = self._create_finding(
                        "DET-001",
                        event,
                        (
                            "PowerShell execution "
                            "contains high-risk "
                            "command indicators."
                        ),
                        {
                            "decision":
                                "ATTACK",

                            "confidence":
                                context_confidence,

                            "context_classification":
                                context,
                        },
                    )

                elif context == "ADMINISTRATIVE":

                    finding = self._create_finding(
                        "DET-001",
                        event,
                        (
                            "PowerShell activity appears "
                            "consistent with legitimate "
                            "administrative usage."
                        ),
                        {
                            "decision":
                                "SUSPICIOUS",

                            "confidence":
                                context_confidence,

                            "context_classification":
                                context,
                        },
                    )

                else:

                    finding = self._create_finding(
                        "DET-001",
                        event,
                        (
                            "PowerShell execution was "
                            "observed but command intent "
                            "requires contextual validation."
                        ),
                        {
                            "decision":
                                "SUSPICIOUS",

                            "confidence":
                                context_confidence,

                            "context_classification":
                                context,
                        },
                    )

                findings.append(
                    finding
                )

            # -------------------------------------------------
            # Discovery
            # -------------------------------------------------

            discovery_commands = [
                "whoami",
                "ipconfig",
                "systeminfo",
                "tasklist",
                "net user",
                "net group",
            ]

            matched_discovery = None

            for command in discovery_commands:

                if command in command_line:

                    matched_discovery = command
                    break

            if matched_discovery:

                context, context_confidence = (
                    self._discovery_context(
                        event
                    )
                )

                findings.append(
                    self._create_finding(
                        "DET-002",
                        event,
                        (
                            "System discovery command "
                            f"'{matched_discovery}' "
                            "was observed."
                        ),
                        {
                            "context_classification":
                                context,

                            "confidence":
                                context_confidence,
                        },
                    )
                )

            # -------------------------------------------------
            # Failed authentication
            # -------------------------------------------------

            if (
                event.get("event_id") == 4625
                or "failed login" in event_type
                or "failed authentication"
                in event_type
            ):

                findings.append(
                    self._create_finding(
                        "DET-003",
                        event,
                        (
                            "A failed authentication "
                            "attempt was observed."
                        ),
                    )
                )

            # -------------------------------------------------
            # External network connection
            # -------------------------------------------------

            if (
                event.get("event_id") == 5156
                and destination_ip
                and not self._is_private_ip(
                    destination_ip
                )
            ):

                findings.append(
                    self._create_finding(
                        "DET-004",
                        event,
                        (
                            "A connection to an address "
                            "outside RFC1918 private "
                            "IPv4 ranges was observed."
                        ),
                    )
                )

        # =====================================================
        # Repeated authentication
        # =====================================================

        failed_auth_events = [

            event
            for event in events

            if (
                event.get("event_id") == 4625
                or "failed login"
                in self._text(
                    event.get("event_type")
                ).lower()
                or "failed authentication"
                in self._text(
                    event.get("event_type")
                ).lower()
            )
        ]

        if len(failed_auth_events) >= 3:

            reference_event = (
                failed_auth_events[-1]
            )

            findings.append(
                self._create_finding(
                    "DET-005",
                    reference_event,
                    (
                        f"{len(failed_auth_events)} "
                        "failed authentication "
                        "events were observed."
                    ),
                    {
                        "failed_auth_count":
                            len(failed_auth_events),
                    },
                )
            )

        # =====================================================
        # Multi-stage correlation
        # =====================================================

        has_powershell = any(

            (
                "powershell"
                in self._text(
                    event.get("process")
                ).lower()

                or "powershell"
                in self._text(
                    event.get("command_line")
                ).lower()
            )

            for event in events
        )

        has_cmd = any(

            (
                "cmd.exe"
                in self._text(
                    event.get("process")
                ).lower()

                or "cmd.exe"
                in self._text(
                    event.get("command_line")
                ).lower()
            )

            for event in events
        )

        has_discovery = any(

            any(
                command
                in self._text(
                    event.get("command_line")
                ).lower()

                for command in [
                    "whoami",
                    "ipconfig",
                    "systeminfo",
                    "tasklist",
                    "net user",
                    "net group",
                ]
            )

            for event in events
        )

        has_external_network = any(

            (
                event.get("event_id") == 5156
                and self._text(
                    event.get("destination_ip")
                )
                and not self._is_private_ip(
                    event.get(
                        "destination_ip"
                    )
                )
            )

            for event in events
        )

        has_failed_auth = (
            len(failed_auth_events) > 0
        )

        # -----------------------------------------------------
        # High-risk PowerShell
        # -----------------------------------------------------

        has_high_risk_powershell = any(

            finding.get(
                "rule_id"
            ) == "DET-001"

            and finding.get(
                "decision"
            ) == "ATTACK"

            for finding in findings
        )

        # -----------------------------------------------------
        # Multi-stage signal count
        # -----------------------------------------------------

        stage_signals = sum(
            [
                has_powershell,
                has_cmd,
                has_discovery,
                has_failed_auth,
                has_external_network,
            ]
        )

        # Require 3+ independent signals.
        if stage_signals >= 3:

            reference_event = (
                events[-1]
                if events
                else {}
            )

            findings.append(
                self._create_finding(
                    "DET-006",
                    reference_event,
                    (
                        "Multiple security-relevant "
                        "activity types were correlated "
                        "across the event sequence."
                    ),
                    {
                        "correlation_signals":
                            stage_signals,

                        "correlation_type":
                            "MULTI_STAGE",

                        "mitre_mapping_type":
                            "CORRELATION_ONLY",

                        "high_risk_powershell":
                            has_high_risk_powershell,
                    },
                )
            )

        # =====================================================
        # Context enrichment
        # =====================================================

        findings = self._apply_context(
            findings
        )

        return findings

    # ---------------------------------------------------------
    # Context enrichment
    # ---------------------------------------------------------

    def _apply_context(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        for finding in findings:

            rule_id = finding.get(
                "rule_id"
            )

            if rule_id == "DET-001":

                classification = finding.get(
                    "context_classification",
                    "UNKNOWN"
                )

                if classification == "HIGH_RISK":

                    finding["context"] = (
                        "High-risk PowerShell "
                        "indicators were observed."
                    )

                elif classification == "ADMINISTRATIVE":

                    finding["context"] = (
                        "PowerShell command appears "
                        "consistent with legitimate "
                        "administrative activity."
                    )

                else:

                    finding["context"] = (
                        "PowerShell requires "
                        "additional contextual validation."
                    )

            elif rule_id == "DET-002":

                finding["context"] = (
                    "Discovery activity can be "
                    "legitimate or malicious; "
                    "correlation with other evidence "
                    "is required."
                )

            elif rule_id == "DET-003":

                finding["context"] = (
                    "A single failed authentication "
                    "attempt is weak evidence."
                )

            elif rule_id == "DET-004":

                finding["context"] = (
                    "External communication alone "
                    "does not prove command-and-control."
                )

            elif rule_id == "DET-005":

                finding["context"] = (
                    "Repeated authentication failures "
                    "increase confidence in brute-force "
                    "activity."
                )

            elif rule_id == "DET-006":

                finding["context"] = (
                    "This is a correlation signal "
                    "representing multi-stage activity, "
                    "not an independent ATT&CK technique."
                )

        return findings


if __name__ == "__main__":

    sample_events = [

        {
            "timestamp":
                "2026-09-08T10:16:03Z",

            "event_id":
                4688,

            "event_type":
                "Process Creation",

            "source":
                "WS-001",

            "username":
                "alice",

            "process":
                "powershell.exe",

            "command_line":
                "powershell.exe -enc suspicious_payload",

            "message":
                "Suspicious PowerShell execution",
        },

        {
            "timestamp":
                "2026-09-08T10:18:11Z",

            "event_id":
                4688,

            "event_type":
                "Process Creation",

            "source":
                "SRV-DC01",

            "username":
                "alice",

            "process":
                "cmd.exe",

            "command_line":
                "cmd.exe /c whoami",

            "message":
                "System discovery",
        },

        {
            "timestamp":
                "2026-09-08T10:19:34Z",

            "event_id":
                4625,

            "event_type":
                "Failed Login",

            "source":
                "SRV-DC01",

            "username":
                "administrator",

            "source_ip":
                "10.10.20.99",

            "message":
                "Failed authentication",
        },

        {
            "timestamp":
                "2026-09-08T10:20:00Z",

            "event_id":
                5156,

            "event_type":
                "Network Connection",

            "source":
                "WS-001",

            "username":
                "alice",

            "source_ip":
                "10.10.20.15",

            "destination_ip":
                "203.0.113.50",

            "message":
                "External connection",
        },
    ]

    engine = DetectionEngine()

    results = engine.analyze(
        sample_events
    )

    print("=" * 80)
    print(
        "AGENTIC AI-SOC - DETECTION ENGINE V4"
    )
    print("=" * 80)

    print(
        f"Events   : {len(sample_events)}"
    )

    print(
        f"Findings : {len(results)}"
    )

    print()

    for finding in results:

        technique = finding.get(
            "mitre_attack"
        )

        if isinstance(
            technique,
            dict
        ):

            technique_id = (
                technique.get(
                    "technique_id"
                )
            )

        else:

            technique_id = (
                "CORRELATION_ONLY"
            )

        print(
            f"{finding['rule_id']} | "
            f"{finding['title']} | "
            f"{finding['decision']} | "
            f"{finding['severity']} | "
            f"{technique_id}"
        )

    print("=" * 80)
    print(
        "DETECTION ENGINE V4 READY"
    )
    print("=" * 80)