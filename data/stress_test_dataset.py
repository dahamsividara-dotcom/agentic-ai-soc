from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timedelta


BASE_DIR = Path(__file__).resolve().parents[1]

OUTPUT_FILE = BASE_DIR / "data" / "stress_test_scenarios.json"


def event(
    timestamp,
    event_id,
    event_type,
    source,
    username=None,
    source_ip=None,
    destination_ip=None,
    process=None,
    command_line=None,
    message="",
):
    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": event_type,
        "source": source,
        "username": username,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "process": process,
        "command_line": command_line,
        "message": message,
    }


def make_scenario(
    scenario_id,
    name,
    ground_truth,
    expected_techniques,
    expected_risk,
    events,
):
    return {
        "scenario_id": scenario_id,
        "name": name,
        "ground_truth": ground_truth,
        "expected_attack": ground_truth == "MALICIOUS",
        "expected_techniques": expected_techniques,
        "expected_risk": expected_risk,
        "events": events,
    }


def build_scenarios():

    scenarios = []

    # ============================================================
    # 01-05: TEMPORAL CORRELATION TESTS
    # ============================================================

    base = datetime(2026, 9, 11, 9, 0, 0)

    scenarios.append(
        make_scenario(
            "ST01",
            "Temporal Correlation - Rapid Execution to Discovery",
            "MALICIOUS",
            ["T1059.001", "T1033"],
            "HIGH",
            [
                event(
                    (base).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST01",
                    "analyst",
                    "10.30.1.10",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Encoded PowerShell execution",
                ),
                event(
                    (base + timedelta(minutes=2)).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST01",
                    "analyst",
                    "10.30.1.10",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="User discovery after PowerShell execution",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST02",
            "Temporal Correlation - Delayed Multi-Stage Activity",
            "SUSPICIOUS",
            ["T1059.001", "T1033"],
            "MEDIUM",
            [
                event(
                    (base).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST02",
                    "user1",
                    "10.30.1.11",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Service",
                    message="PowerShell activity",
                ),
                event(
                    (base + timedelta(minutes=14)).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST02",
                    "user1",
                    "10.30.1.11",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery command",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST03",
            "Temporal Correlation - Events Outside Correlation Window",
            "SUSPICIOUS",
            ["T1059.001", "T1033"],
            "MEDIUM",
            [
                event(
                    (base).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST03",
                    "user2",
                    "10.30.1.12",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Service",
                    message="PowerShell activity",
                ),
                event(
                    (base + timedelta(minutes=30)).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST03",
                    "user2",
                    "10.30.1.12",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Delayed discovery activity",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST04",
            "Temporal Correlation - Three Stage Sequence",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1071"],
            "CRITICAL",
            [
                event(
                    base.isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST04",
                    "user3",
                    "10.30.1.13",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Obfuscated PowerShell",
                ),
                event(
                    (base + timedelta(minutes=3)).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST04",
                    "user3",
                    "10.30.1.13",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    (base + timedelta(minutes=5)).isoformat() + "Z",
                    5156,
                    "Network Connection",
                    "WS-ST04",
                    "user3",
                    "10.30.1.13",
                    "185.199.108.153",
                    message="External communication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST05",
            "Temporal Correlation - Benign Administrative Sequence",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    base.isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST05",
                    "administrator",
                    "10.30.1.14",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Service",
                    message="Routine administration",
                ),
                event(
                    (base + timedelta(minutes=2)).isoformat() + "Z",
                    4688,
                    "Process Creation",
                    "WS-ST05",
                    "administrator",
                    "10.30.1.14",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Process",
                    message="Routine administration",
                ),
            ],
        )
    )

    # ============================================================
    # 06-10: ENTITY CORRELATION
    # ============================================================

    scenarios.append(
        make_scenario(
            "ST06",
            "Entity Correlation - Same Host Multi-Stage Attack",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T10:00:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST06",
                    "user6",
                    "10.30.2.10",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Encoded execution",
                ),
                event(
                    "2026-09-11T10:02:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST06",
                    "user6",
                    "10.30.2.10",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T10:04:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST06",
                    "user6",
                    "10.30.2.10",
                    "203.0.113.50",
                    message="External connection",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST07",
            "Entity Correlation - Same User Across Hosts",
            "SUSPICIOUS",
            ["T1033", "T1071"],
            "MEDIUM",
            [
                event(
                    "2026-09-11T10:10:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST07A",
                    "user7",
                    "10.30.2.11",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T10:13:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST07B",
                    "user7",
                    "10.30.2.12",
                    "203.0.113.50",
                    message="External connection",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST08",
            "Entity Correlation - Same IP Benign Events",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T10:20:00Z",
                    4624,
                    "Successful Login",
                    "WS-ST08",
                    "employee",
                    "10.30.2.20",
                    message="Normal login",
                ),
                event(
                    "2026-09-11T10:22:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST08",
                    "employee",
                    "10.30.2.20",
                    process="chrome.exe",
                    command_line="chrome.exe",
                    message="Normal browser activity",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST09",
            "Entity Correlation - Host Reuse After Suspicious Activity",
            "MALICIOUS",
            ["T1059.001", "T1033"],
            "HIGH",
            [
                event(
                    "2026-09-11T10:30:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST09",
                    "user9",
                    "10.30.2.30",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Encoded execution",
                ),
                event(
                    "2026-09-11T10:35:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST09",
                    "user9",
                    "10.30.2.30",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST10",
            "Entity Correlation - Different Users Isolated",
            "SUSPICIOUS",
            ["T1033"],
            "LOW",
            [
                event(
                    "2026-09-11T10:40:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST10",
                    "user10a",
                    "10.30.2.40",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery command",
                ),
                event(
                    "2026-09-11T10:42:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST10",
                    "user10b",
                    "10.30.2.40",
                    process="chrome.exe",
                    command_line="chrome.exe",
                    message="Different user normal activity",
                ),
            ],
        )
    )

    # ============================================================
    # 11-15: CTI TESTS
    # ============================================================

    scenarios.append(
        make_scenario(
            "ST11",
            "CTI - Known Suspicious C2 IP",
            "MALICIOUS",
            ["T1071"],
            "HIGH",
            [
                event(
                    "2026-09-11T11:00:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST11",
                    "user11",
                    "10.40.1.11",
                    "203.0.113.50",
                    message="Connection to CTI-listed suspicious IP",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST12",
            "CTI - Known Malicious IP",
            "MALICIOUS",
            ["T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T11:05:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST12",
                    "user12",
                    "10.40.1.12",
                    "198.51.100.25",
                    message="Connection to known malicious destination",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST13",
            "CTI - Unknown External IP",
            "SUSPICIOUS",
            ["T1071"],
            "LOW",
            [
                event(
                    "2026-09-11T11:10:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST13",
                    "user13",
                    "10.40.1.13",
                    "8.8.8.8",
                    message="External DNS-related communication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST14",
            "CTI - Malicious Destination After Execution",
            "MALICIOUS",
            ["T1059.001", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T11:15:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST14",
                    "user14",
                    "10.40.1.14",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Obfuscated execution",
                ),
                event(
                    "2026-09-11T11:17:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST14",
                    "user14",
                    "10.40.1.14",
                    "198.51.100.25",
                    message="Connection to known malicious IP",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST15",
            "CTI - Benign Internal Communication",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T11:20:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST15",
                    "user15",
                    "10.40.1.15",
                    "10.40.1.20",
                    message="Internal server communication",
                ),
            ],
        )
    )

    # ============================================================
    # 16-20: RISK ASSESSMENT TESTS
    # ============================================================

    scenarios.append(
        make_scenario(
            "ST16",
            "Risk - Single Low Severity Event",
            "SUSPICIOUS",
            ["T1110"],
            "LOW",
            [
                event(
                    "2026-09-11T12:00:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST16",
                    "user16",
                    "10.50.1.16",
                    message="Single failed authentication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST17",
            "Risk - Repeated Authentication Failure",
            "MALICIOUS",
            ["T1110"],
            "HIGH",
            [
                event(
                    "2026-09-11T12:05:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST17",
                    "administrator",
                    "10.50.1.17",
                    message="Failed authentication",
                ),
                event(
                    "2026-09-11T12:06:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST17",
                    "administrator",
                    "10.50.1.17",
                    message="Failed authentication",
                ),
                event(
                    "2026-09-11T12:07:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST17",
                    "administrator",
                    "10.50.1.17",
                    message="Failed authentication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST18",
            "Risk - Multiple Weak Signals",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1110", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T12:10:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST18",
                    "user18",
                    "10.50.1.18",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Obfuscated execution",
                ),
                event(
                    "2026-09-11T12:12:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST18",
                    "user18",
                    "10.50.1.18",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T12:14:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST18",
                    "administrator",
                    "10.50.1.18",
                    message="Authentication failures",
                ),
                event(
                    "2026-09-11T12:16:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST18",
                    "user18",
                    "10.50.1.18",
                    "198.51.100.25",
                    message="External malicious destination",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST19",
            "Risk - Benign Multiple Events",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T12:20:00Z",
                    4624,
                    "Successful Login",
                    "WS-ST19",
                    "employee",
                    "10.50.1.19",
                    message="Normal authentication",
                ),
                event(
                    "2026-09-11T12:21:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST19",
                    "employee",
                    "10.50.1.19",
                    process="chrome.exe",
                    command_line="chrome.exe",
                    message="Normal browsing",
                ),
                event(
                    "2026-09-11T12:22:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST19",
                    "employee",
                    "10.50.1.19",
                    "10.50.1.20",
                    message="Internal communication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST20",
            "Risk - Medium Signals Become High Through Correlation",
            "MALICIOUS",
            ["T1033", "T1071"],
            "HIGH",
            [
                event(
                    "2026-09-11T12:25:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST20",
                    "user20",
                    "10.50.1.20",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T12:27:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST20",
                    "user20",
                    "10.50.1.20",
                    "203.0.113.50",
                    message="Suspicious external communication",
                ),
            ],
        )
    )

    # ============================================================
    # 21-25: ADVERSARIAL / NOISE
    # ============================================================

    scenarios.append(
        make_scenario(
            "ST21",
            "Noise - PowerShell With Benign Administrative Flags",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T13:00:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST21",
                    "administrator",
                    "10.60.1.21",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Service",
                    message="Approved administration task",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST22",
            "Noise - Browser External Communication",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T13:05:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST22",
                    "employee",
                    "10.60.1.22",
                    "142.250.72.14",
                    process="chrome.exe",
                    message="Normal web browsing",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST23",
            "Noise - Failed Login Then Successful Login",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T13:10:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST23",
                    "employee",
                    "10.60.1.23",
                    message="Mistyped password",
                ),
                event(
                    "2026-09-11T13:11:00Z",
                    4624,
                    "Successful Login",
                    "SRV-ST23",
                    "employee",
                    "10.60.1.23",
                    message="Successful retry",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST24",
            "Noise - Discovery During IT Audit",
            "SUSPICIOUS",
            ["T1033"],
            "LOW",
            [
                event(
                    "2026-09-11T13:15:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST24",
                    "auditor",
                    "10.60.1.24",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Authorized IT audit",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST25",
            "Noise - PowerShell and Internal Network",
            "BENIGN",
            [],
            "LOW",
            [
                event(
                    "2026-09-11T13:20:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST25",
                    "administrator",
                    "10.60.1.25",
                    process="powershell.exe",
                    command_line="powershell.exe -NoProfile -Command Get-Process",
                    message="Routine management",
                ),
                event(
                    "2026-09-11T13:21:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST25",
                    "administrator",
                    "10.60.1.25",
                    "10.60.1.30",
                    message="Internal management traffic",
                ),
            ],
        )
    )

    # ============================================================
    # 26-30: FULL COMPLEX ATTACK CHAINS
    # ============================================================

    scenarios.append(
        make_scenario(
            "ST26",
            "Complex Attack - Execution Discovery C2",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T14:00:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST26",
                    "user26",
                    "10.70.1.26",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Encoded PowerShell",
                ),
                event(
                    "2026-09-11T14:02:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST26",
                    "user26",
                    "10.70.1.26",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T14:05:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST26",
                    "user26",
                    "10.70.1.26",
                    "198.51.100.25",
                    message="Known malicious destination",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST27",
            "Complex Attack - Brute Force Followed by Discovery",
            "MALICIOUS",
            ["T1110", "T1033"],
            "HIGH",
            [
                event(
                    "2026-09-11T14:10:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST27",
                    "administrator",
                    "10.70.1.27",
                    message="Authentication failure",
                ),
                event(
                    "2026-09-11T14:11:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST27",
                    "administrator",
                    "10.70.1.27",
                    message="Authentication failure",
                ),
                event(
                    "2026-09-11T14:12:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST27",
                    "administrator",
                    "10.70.1.27",
                    message="Authentication failure",
                ),
                event(
                    "2026-09-11T14:14:00Z",
                    4688,
                    "Process Creation",
                    "SRV-ST27",
                    "administrator",
                    "10.70.1.27",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery after repeated authentication failures",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST28",
            "Complex Attack - Distributed Activity",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T14:20:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST28A",
                    "user28",
                    "10.70.1.28",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Execution",
                ),
                event(
                    "2026-09-11T14:23:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST28B",
                    "user28",
                    "10.70.1.29",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery on related host",
                ),
                event(
                    "2026-09-11T14:26:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST28B",
                    "user28",
                    "10.70.1.29",
                    "203.0.113.50",
                    message="External communication",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST29",
            "Complex Attack - Low Confidence Signals",
            "MALICIOUS",
            ["T1033", "T1071"],
            "HIGH",
            [
                event(
                    "2026-09-11T14:30:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST29",
                    "user29",
                    "10.70.1.30",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery activity",
                ),
                event(
                    "2026-09-11T14:32:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST29",
                    "user29",
                    "10.70.1.30",
                    "203.0.113.50",
                    message="Suspicious destination",
                ),
                event(
                    "2026-09-11T14:34:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST29",
                    "administrator",
                    "10.70.1.30",
                    message="Authentication failure",
                ),
            ],
        )
    )

    scenarios.append(
        make_scenario(
            "ST30",
            "Complex Attack - Full Kill Chain Simulation",
            "MALICIOUS",
            ["T1059.001", "T1033", "T1110", "T1071"],
            "CRITICAL",
            [
                event(
                    "2026-09-11T15:00:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST30",
                    "user30",
                    "10.70.1.31",
                    process="powershell.exe",
                    command_line="powershell.exe -EncodedCommand SQBFAFgA",
                    message="Obfuscated execution",
                ),
                event(
                    "2026-09-11T15:02:00Z",
                    4688,
                    "Process Creation",
                    "WS-ST30",
                    "user30",
                    "10.70.1.31",
                    process="cmd.exe",
                    command_line="cmd.exe /c whoami",
                    message="Discovery",
                ),
                event(
                    "2026-09-11T15:04:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST30",
                    "administrator",
                    "10.70.1.31",
                    message="Authentication abuse",
                ),
                event(
                    "2026-09-11T15:05:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST30",
                    "administrator",
                    "10.70.1.31",
                    message="Authentication abuse",
                ),
                event(
                    "2026-09-11T15:06:00Z",
                    4625,
                    "Failed Login",
                    "SRV-ST30",
                    "administrator",
                    "10.70.1.31",
                    message="Authentication abuse",
                ),
                event(
                    "2026-09-11T15:08:00Z",
                    5156,
                    "Network Connection",
                    "WS-ST30",
                    "user30",
                    "10.70.1.31",
                    "198.51.100.25",
                    message="Known malicious external destination",
                ),
            ],
        )
    )

    return scenarios


def main():

    scenarios = build_scenarios()

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            scenarios,
            f,
            indent=2,
        )

    counts = {}

    for scenario in scenarios:
        label = scenario["ground_truth"]
        counts[label] = counts.get(label, 0) + 1

    print("=" * 72)
    print("AGENTIC AI-SOC - STRESS TEST DATASET")
    print("=" * 72)
    print(f"Total scenarios : {len(scenarios)}")

    for label, count in counts.items():
        print(f"{label:<20}: {count}")

    print("=" * 72)
    print(f"Saved to: {OUTPUT_FILE}")
    print("STRESS TEST DATASET READY")


if __name__ == "__main__":
    main() 