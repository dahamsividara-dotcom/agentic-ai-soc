from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from backend.soc_orchestrator import SOCOrchestrator


BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_FILE = BASE_DIR / "data" / "stress_test_scenarios.json"
TEMP_DIR = BASE_DIR / "data" / "stress_temp"
RESULTS_FILE = BASE_DIR / "data" / "stress_test_evaluation_results.json"


def write_events(events: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def extract_mitre_technique(finding: dict[str, Any]) -> str | None:
    technique = finding.get("mitre_technique")

    if technique:
        return str(technique)

    technique = finding.get("technique")

    if technique:
        return str(technique)

    mitre_attack = finding.get("mitre_attack")

    if isinstance(mitre_attack, dict):
        technique_id = mitre_attack.get("technique_id")

        if technique_id:
            return str(technique_id)

    return None


def binary_metrics(
    y_true: list[bool],
    y_pred: list[bool],
) -> dict[str, float | int]:

    tp = sum(t and p for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))

    accuracy = (tp + tn) / len(y_true) if y_true else 0.0

    precision = tp / (tp + fp) if (tp + fp) else 0.0

    recall = tp / (tp + fn) if (tp + fn) else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
    }


def mitre_metrics(
    expected: list[list[str]],
    predicted: list[list[str]],
) -> dict[str, float]:

    expected_set = {
        technique
        for techniques in expected
        for technique in techniques
    }

    predicted_set = {
        technique
        for techniques in predicted
        for technique in techniques
    }

    true_positive = len(expected_set & predicted_set)

    false_positive = len(predicted_set - expected_set)

    false_negative = len(expected_set - predicted_set)

    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():

    print("=" * 80)
    print("AGENTIC AI-SOC - STRESS TEST EVALUATION")
    print("=" * 80)

    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    print(f"Stress scenarios : {len(scenarios)}")
    print("Evaluation mode  : Unseen research stress-test")
    print("=" * 80)

    TEMP_DIR.mkdir(parents=True, exist_ok=True)

    orchestrator = SOCOrchestrator()

    # ------------------------------------------------------------
    # Disable LLM during quantitative evaluation.
    # LLM reasoning is not part of the classification metric.
    # This keeps the experiment deterministic and fast.
    # ------------------------------------------------------------

    def skip_llm(*args, **kwargs):
        return {
            "status": "SKIPPED_FOR_EVALUATION",
            "provider": orchestrator.llm.provider,
            "model": orchestrator.llm.model,
            "reason": "LLM disabled during quantitative stress-test evaluation.",
        }

    orchestrator.llm.generate = skip_llm

    y_true = []
    y_pred = []

    expected_mitre = []
    predicted_mitre = []

    scenario_results = []

    total_latency = 0.0

    for index, scenario in enumerate(scenarios, start=1):

        scenario_id = scenario["scenario_id"]

        temp_file = TEMP_DIR / f"{scenario_id}.jsonl"

        write_events(
            scenario["events"],
            temp_file,
        )

        start = time.perf_counter()

        result = orchestrator.run(temp_file)

        latency = time.perf_counter() - start

        total_latency += latency

        decision = result.get("decision", {})

        predicted_decision = str(
            decision.get("decision", "BENIGN")
        ).upper()

        ground_truth = str(
            scenario.get("ground_truth", "BENIGN")
        ).upper()

        actual_attack = ground_truth == "MALICIOUS"

        predicted_attack = predicted_decision == "MALICIOUS"

        y_true.append(actual_attack)

        y_pred.append(predicted_attack)

        expected = [
            str(x)
            for x in scenario.get(
                "expected_techniques",
                [],
            )
        ]

        predicted = []

        for finding in result.get("findings", []):

            technique = extract_mitre_technique(
                finding
            )

            if technique:
                predicted.append(technique)

        expected_mitre.append(expected)

        predicted_mitre.append(predicted)

        risk_assessment = result.get(
            "risk_assessment",
            {},
        )

        risk_score = risk_assessment.get(
            "risk_score",
            0,
        )

        risk_level = risk_assessment.get(
            "risk_level",
            "UNKNOWN",
        )

        scenario_result = {
            "scenario_id": scenario_id,
            "name": scenario.get("name"),
            "ground_truth": ground_truth,
            "predicted_decision": predicted_decision,
            "correct": ground_truth == predicted_decision
            if ground_truth in {
                "BENIGN",
                "SUSPICIOUS",
                "MALICIOUS",
            }
            else actual_attack == predicted_attack,
            "expected_attack": actual_attack,
            "predicted_attack": predicted_attack,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "expected_techniques": expected,
            "predicted_techniques": predicted,
            "latency_seconds": latency,
        }

        scenario_results.append(
            scenario_result
        )

        print(
            f"{scenario_id:<6} | "
            f"GT={ground_truth:<10} | "
            f"PRED={predicted_decision:<10} | "
            f"RISK={risk_score:>3} | "
            f"{latency:.4f}s"
        )

    metrics = binary_metrics(
        y_true,
        y_pred,
    )

    mitre = mitre_metrics(
        expected_mitre,
        predicted_mitre,
    )

    average_latency = (
        total_latency / len(scenarios)
        if scenarios
        else 0.0
    )

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    print()
    print("=" * 80)
    print("STRESS TEST FINAL METRICS")
    print("=" * 80)

    print(
        f"Accuracy           : "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Precision          : "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall             : "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1                 : "
        f"{metrics['f1']:.4f}"
    )

    print(
        f"False Positive Rate: "
        f"{metrics['false_positive_rate']:.4f}"
    )

    print(
        f"TP                 : "
        f"{metrics['tp']}"
    )

    print(
        f"TN                 : "
        f"{metrics['tn']}"
    )

    print(
        f"FP                 : "
        f"{metrics['fp']}"
    )

    print(
        f"FN                 : "
        f"{metrics['fn']}"
    )

    print(
        f"MITRE Precision    : "
        f"{mitre['precision']:.4f}"
    )

    print(
        f"MITRE Recall       : "
        f"{mitre['recall']:.4f}"
    )

    print(
        f"MITRE F1           : "
        f"{mitre['f1']:.4f}"
    )

    print(
        f"Average Latency    : "
        f"{average_latency:.6f}s"
    )

    print("=" * 80)

    # ------------------------------------------------------------
    # Save complete results
    # ------------------------------------------------------------

    output = {
        "evaluation": {
            "dataset": "stress_test_scenarios.json",
            "scenario_count": len(scenarios),
            "evaluation_type": "unseen research stress-test",
            "llm_used": False,
        },
        "metrics": {
            **metrics,
            "mitre_precision": mitre["precision"],
            "mitre_recall": mitre["recall"],
            "mitre_f1": mitre["f1"],
            "average_latency_seconds": average_latency,
        },
        "scenario_results": scenario_results,
    }

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            output,
            f,
            indent=2,
        )

    print(
        f"Results saved to: {RESULTS_FILE}"
    )

    print("STRESS TEST EVALUATION COMPLETE")


if __name__ == "__main__":
    main() 