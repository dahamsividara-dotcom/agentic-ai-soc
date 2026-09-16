from detection.log_ingestor import LogIngestor


def main():
    log_file = "data/sample_security_logs.jsonl"

    ingestor = LogIngestor()
    events = ingestor.ingest(log_file)

    print("=" * 50)
    print("AGENTIC AI-SOC - LOG INGESTION TEST")
    print("=" * 50)
    print(f"Events ingested: {len(events)}")
    print()

    for index, event in enumerate(events, start=1):
        print(
            f"{index}. "
            f"{event['event_type']} | "
            f"Host: {event['source']} | "
            f"User: {event['username']} | "
            f"Source IP: {event['source_ip']}"
        )

    print()
    print("INGESTION TEST: PASSED")


if __name__ == "__main__":
    main()
