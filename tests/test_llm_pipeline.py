from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine
from attack_graph.attack_chain_engine import AttackChainEngine
from agents.investigation_agent import InvestigationAgent
from agents.llm_reasoning_engine import LLMReasoningEngine


def main() -> None:
    print("=" * 70)
    print("AGENTIC AI-SOC - LLM REASONING PIPELINE TEST")
    print("=" * 70)

    ingestor = LogIngestor()
    events = ingestor.ingest("data/sample_security_logs.jsonl")

    detector = DetectionEngine()
    findings = detector.analyze(events)

    chain_engine = AttackChainEngine()
    attack_chain = chain_engine.build_chain(findings)

    investigator = InvestigationAgent()
    investigation = investigator.investigate(attack_chain)

    llm = LLMReasoningEngine()

    print(f"Logs              : {len(events)}")
    print(f"Security Findings : {len(findings)}")
    print("Attack Chains     : 1")
    print(f"LLM Provider      : {llm.provider}")
    print(f"LLM Configured    : {llm.is_configured()}")

    print("\nLLM ASSESSMENTS")
    print("-" * 70)

    result = llm.generate(
        attack_chain=attack_chain,
        investigation=investigation,
    )

    print("\nIncident 1")
    print(f"Status       : {result['status']}")
    print(f"Provider     : {result['provider']}")
    print(f"Model        : {result['model']}")
    print(f"Assessment   : {result['assessment']}")

    if result.get("error"):
        print(f"Error        : {result['error']}")


if __name__ == "__main__":
    main()
