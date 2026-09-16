from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine
from attack_graph.attack_chain_engine import AttackChainEngine
from agents.investigation_agent import InvestigationAgent
from agents.ai_reasoning_agent import AIReasoningAgent


print("=" * 70)
print("AGENTIC AI-SOC - END-TO-END AI REASONING TEST")
print("=" * 70)


# 1. Log Ingestion
ingestor = LogIngestor()

events = ingestor.ingest(
    "data/sample_security_logs.jsonl"
)


# 2. Detection
detector = DetectionEngine()

findings = detector.analyze(events)


# 3. Attack Chain
chain_engine = AttackChainEngine()

attack_chain = chain_engine.build_chain(
    findings
)


# 4. Investigation + CTI
investigator = InvestigationAgent()

investigation = investigator.investigate(
    attack_chain
)


# 5. AI Reasoning
reasoning_agent = AIReasoningAgent()

ai_assessment = reasoning_agent.reason(
    attack_chain,
    investigation
)


print()
print("PIPELINE SUMMARY")
print("-" * 70)

print(f"Logs                : {len(events)}")
print(f"Security Findings   : {len(findings)}")
print(
    f"Attack Stages      : "
    f"{attack_chain['stage_count']}"
)
print(
    f"Relationships      : "
    f"{len(attack_chain.get('relationships', []))}"
)
print(
    f"CTI Matches        : "
    f"{investigation['cti_matches']}"
)


print()
print("FINAL AI ASSESSMENT")
print("-" * 70)

print(
    f"Threat Assessment  : "
    f"{ai_assessment['threat_assessment']}"
)

print(
    f"Risk Score         : "
    f"{ai_assessment['risk_score']}/100"
)

print(
    f"AI Confidence      : "
    f"{ai_assessment['confidence']}"
)

print(
    f"Evidence Count     : "
    f"{ai_assessment['evidence_count']}"
)

print(
    f"MITRE Techniques   : "
    f"{', '.join(ai_assessment['mitre_techniques'])}"
)


print()
print("AI REASONING")
print("-" * 70)
print(ai_assessment["reasoning"])


print()
print("LIMITATIONS")
print("-" * 70)

for limitation in ai_assessment["limitations"]:
    print(f"- {limitation}")


print()
print("=" * 70)
print("END-TO-END AI REASONING TEST: PASSED")
print("=" * 70)
