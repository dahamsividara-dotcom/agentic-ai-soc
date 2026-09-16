"""
Agentic AI-SOC - Security Log Ingestion Engine
"""

import csv
import json
from pathlib import Path
from typing import Any


class LogIngestor:
    """Loads and normalizes security logs for the SOC pipeline."""

    SUPPORTED_FORMATS = {".json", ".jsonl", ".csv"}

    def ingest(self, file_path: str) -> list[dict[str, Any]]:
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        if path.suffix.lower() not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format: {path.suffix}. "
                f"Supported: {sorted(self.SUPPORTED_FORMATS)}"
            )

        if path.suffix.lower() == ".csv":
            events = self._read_csv(path)
        elif path.suffix.lower() == ".jsonl":
            events = self._read_jsonl(path)
        else:
            events = self._read_json(path)

        return [self.normalize_event(event) for event in events]

    def _read_csv(self, path: Path) -> list[dict[str, Any]]:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            return list(csv.DictReader(file))

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        events = []

        with path.open("r", encoding="utf-8-sig") as file:
            for line_number, line in enumerate(file, 1):
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)

                except json.JSONDecodeError as error:
                    print(
                        f"[WARNING] Invalid JSON at line "
                        f"{line_number}: {error}"
                    )

        return events

    def _read_json(self, path: Path) -> list[dict[str, Any]]:
        with path.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]

        if isinstance(data, dict):
            if isinstance(data.get("events"), list):
                return [
                    item for item in data["events"]
                    if isinstance(item, dict)
                ]

            return [data]

        raise ValueError("JSON must contain an object or list.")

    def normalize_event(
        self,
        event: dict[str, Any]
    ) -> dict[str, Any]:
        """Convert different security log formats to one SOC schema."""

        return {
            "timestamp": self._get(
                event,
                "timestamp", "time", "@timestamp", "datetime"
            ),
            "event_id": self._get(
                event,
                "event_id", "EventID", "eventId", "id"
            ),
            "event_type": self._get(
                event,
                "event_type", "EventType", "type", "action"
            ),
            "source": self._get(
                event,
                "source", "host", "hostname", "computer"
            ),
            "username": self._get(
                event,
                "username", "user", "UserName", "account"
            ),
            "source_ip": self._get(
                event,
                "source_ip", "src_ip", "src", "SourceIP"
            ),
            "destination_ip": self._get(
                event,
                "destination_ip", "dst_ip", "dst", "DestinationIP"
            ),
            "process": self._get(
                event,
                "process", "ProcessName", "process_name", "Image"
            ),
            "command_line": self._get(
                event,
                "command_line", "CommandLine", "cmdline"
            ),
            "message": self._get(
                event,
                "message", "Message", "description", "details"
            ),
            "raw_event": event
        }

    @staticmethod
    def _get(
        event: dict[str, Any],
        *keys: str
    ) -> Any:
        for key in keys:
            value = event.get(key)

            if value not in (None, ""):
                return value

        return None


if __name__ == "__main__":
    print("Agentic AI-SOC Log Ingestor")
    print("=" * 40)

    ingestor = LogIngestor()

    print("Supported formats:")
    for file_format in sorted(ingestor.SUPPORTED_FORMATS):
        print(f"  - {file_format}")

    print()
    print("Log ingestion engine initialized successfully.")
    print("Status: READY")

