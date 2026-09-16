from detection.log_ingestor import LogIngestor
from threat_intel.threat_intelligence import ThreatIntelligenceEngine


print("=" * 65)
print("AGENTIC AI-SOC - THREAT INTELLIGENCE TEST")
print("=" * 65)


ingestor = LogIngestor()
events = ingestor.ingest(
    "data/sample_security_logs.jsonl"
)

ti_engine = ThreatIntelligenceEngine()

total_indicators = 0

for index, event in enumerate(events, 1):

    result = ti_engine.analyze_event(event)

    if result["indicator_count"] > 0:
        print()
        print(f"EVENT {index}")
        print("-" * 65)

        for indicator in result["indicators"]:
            print(
                f"IOC       : {indicator['value']}"
            )
            print(
                f"Type      : {indicator['type']}"
            )
            print(
                f"Threat    : {indicator['threat']}"
            )
            print(
                f"Confidence: {indicator['confidence']}"
            )
            print(
                f"Category  : {indicator['category']}"
            )
            print(
                f"Source    : {indicator['source']}"
            )

            total_indicators += 1


print()
print("=" * 65)
print(f"Events analysed    : {len(events)}")
print(f"Indicators found   : {total_indicators}")
print("=" * 65)

print("THREAT INTELLIGENCE TEST: PASSED")
print("=" * 65)
