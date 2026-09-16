from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine
from attack_graph.attack_chain_engine import AttackChainEngine
from agents.investigation_agent import InvestigationAgent


print("=" * 65)
print("AGENTIC AI-SOC - CTI INVESTIGATION PIPELINE TEST")
print("=" * 65)


# 1. Log ingestion
ingestor = LogIngestor()

events = ingestor.ingest(
    "data/sample_security_logs.jsonl"
)


# 2. Detection
detector = DetectionEngine()

findings = detector.analyze(events)


# 3. Attack-chain reasoning
chain_engine = AttackChainEngine()

attack_chain = chain_engine.build_chain(findings)


# 4. CTI-enriched investigation
investigator = InvestigationAgent()

investigation = investigator.investigate(
    attack_chain
)


print()
print(f"Logs ingested     : {len(events)}")
print(f"Security findings : {len(findings)}")
print(
    f"Attack stages     : "
    f"{len(attack_chain.get('stages', []))}"
)

print("-" * 65)
print("INVESTIGATION RESULT")
print("-" * 65)

print(
    f"Incident Status : "
    f"{investigation['incident_status']}"
)

print(
    f"Confidence      : "
    f"{investigation['confidence']}"
)

print(
    f"Evidence Count  : "
    f"{investigation['evidence_count']}"
)

print(
    f"CTI Matches     : "
    f"{investigation['cti_matches']}"
)

print()
print("THREAT HYPOTHESIS:")
print(investigation["hypothesis"])


print()
print("EVIDENCE:")

for index, evidence in enumerate(
    investigation["evidence"],
    1
):
    print(
        f"[{index}] "
        f"{evidence['stage']} | "
        f"{evidence['severity']} | "
        f"{evidence['host']} | "
        f"{evidence['username']}"
    )


print()
print("CTI CONTEXT:")

for index, context in enumerate(
    investigation["cti_context"],
    1
):
    print(
        f"[{index}] "
        f"{context['id']} | "
        f"{context['title']} | "
        f"{context['mitre_id']} | "
        f"{context['category']}"
    )


print()
print("RECOMMENDATIONS:")

for index, recommendation in enumerate(
    investigation["recommendations"],
    1
):
    print(
        f"[{index}] {recommendation}"
    )


print()
print("=" * 65)
print("CTI INVESTIGATION PIPELINE TEST: PASSED")
print("=" * 65)
