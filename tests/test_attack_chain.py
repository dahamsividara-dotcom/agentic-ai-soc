from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine
from attack_graph.attack_chain_engine import AttackChainEngine


print("=" * 60)
print("AGENTIC AI-SOC - ATTACK CHAIN INTEGRATION TEST")
print("=" * 60)

# Step 1: Ingest security logs
log_path = "data/sample_security_logs.jsonl"

ingestor = LogIngestor()
events = ingestor.ingest(log_path)

print(f"\nLogs ingested : {len(events)}")

# Step 2: Run detection engine
detector = DetectionEngine()
findings = detector.analyze(events)

print(f"Findings      : {len(findings)}")

# Step 3: Build attack chain
chain_engine = AttackChainEngine()
attack_chain = chain_engine.build_chain(findings)

print("\n" + "-" * 60)
print("ATTACK CHAIN ANALYSIS")
print("-" * 60)

print(f"Chain ID      : {attack_chain['chain_id']}")
print(f"Status        : {attack_chain['status']}")
print(f"Risk Score    : {attack_chain['risk_score']}/100")
print(f"Stage Count   : {attack_chain['stage_count']}")

print("\nAttack Stages:")

for index, stage in enumerate(attack_chain["stages"], 1):
    print(
        f"\n[{index}] {stage['stage']}"
        f"\n    Rule       : {stage['rule_id']}"
        f"\n    Severity   : {stage['severity']}"
        f"\n    Confidence : {stage['confidence']}"
        f"\n    Host       : {stage['host']}"
        f"\n    User       : {stage['username']}"
    )

    mitre = stage.get("mitre_attack")

    if mitre:
        print(
            f"    MITRE      : "
            f"{mitre.get('technique_id')} - "
            f"{mitre.get('technique_name')}"
        )

print("\n" + "-" * 60)
print("AI-SOC EXPLANATION")
print("-" * 60)

print(attack_chain["explanation"])

print("\n" + "=" * 60)
print("ATTACK CHAIN INTEGRATION TEST: PASSED")
print("=" * 60)
