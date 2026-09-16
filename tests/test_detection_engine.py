from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine


def main():
    log_file = "data/sample_security_logs.jsonl"

    # Step 1: Ingest logs
    ingestor = LogIngestor()
    events = ingestor.ingest(log_file)

    # Step 2: Analyze events
    detector = DetectionEngine()
    findings = detector.analyze(events)

    print("=" * 60)
    print("AGENTIC AI-SOC - DETECTION PIPELINE TEST")
    print("=" * 60)

    print(f"Events ingested : {len(events)}")
    print(f"Findings        : {len(findings)}")
    print()

    for index, finding in enumerate(findings, start=1):
        mitre = finding["mitre_attack"]

        print(f"[{index}] {finding['title']}")
        print(f"    Rule       : {finding['rule_id']}")
        print(f"    Severity   : {finding['severity']}")
        print(f"    Confidence : {finding['confidence']}")
        print(f"    Host       : {finding['host']}")
        print(f"    User       : {finding['username']}")
        print(f"    Reason     : {finding['reason']}")
        print(
            f"    MITRE      : "
            f"{mitre['technique_id']} - "
            f"{mitre['technique_name']}"
        )
        print()

    print("=" * 60)
    print("DETECTION PIPELINE TEST: PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
