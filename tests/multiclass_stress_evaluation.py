from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from backend.soc_orchestrator import SOCOrchestrator


BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_FILE = BASE_DIR / "data" / "stress_test_scenarios.json"
TEMP_DIR = BASE_DIR / "data" / "multiclass_stress_temp"
RESULTS_FILE = (
    BASE_DIR / "data" / "multiclass_stress_evaluation_results.json"
)

CLASSES = [
    "BENIGN",
    "SUSPICIOUS",
    "MALICIOUS",
]


def write_events(events: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for item in events:
            f.write(json.dumps(item) + "\n")


def safe_divide(a: float, b: float) -> float:
    return a / b if b else 0.0


def extract_mitre_technique(
    finding: dict[str, Any],
) -> str | None:

    value = finding.get("mitre_technique")

    if value:
        return str(value)

    value = finding.get("technique")

    if value:
        return str(value)

    mitre_attack = finding.get("mitre_attack")

    if isinstance(mitre_attack, dict):
        value = mitre_attack.get("technique_id")

        if value:
            return str(value)

    return None


def calculate_multiclass_metrics(
    y_true: list[str],
    y_pred: list[str],
) -> dict[str, Any]:

    matrix = {
        actual: {
            predicted: 0
            for predicted in CLASSES
        }
        for actual in CLASSES
    }

    for actual, predicted in zip(y_true, y_pred):

        if actual not in CLASSES:
            actual = "BENIGN"

        if predicted not in CLASSES:
            predicted = "BENIGN"

        matrix[actual][predicted] += 1

    per_class = {}

    for target in CLASSES:

        tp = matrix[target][target]

        fp = sum(
            matrix[actual][target]
            for actual in CLASSES
            if actual != target
        )

        fn = sum(
            matrix[target][predicted]
            for predicted in CLASSES
            if predicted != target
        )

        support = sum(matrix[target].values())

        precision = safe_divide(
            tp,
            tp + fp,
        )

        recall = safe_divide(
            tp,
            tp + fn,
        )

        f1 = (
            2 * precision * recall
            / (precision + recall)
            if precision + recall
            else 0.0
        )

        per_class[target] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }

    total = len(y_true)

    correct = sum(
        actual == predicted
        for actual, predicted in zip(
            y_true,
            y_pred,
        )
    )

    accuracy = safe_divide(
        correct,
        total,
    )

    macro_precision = sum(
        per_class[c]["precision"]
        for c in CLASSES
    ) / len(CLASSES)

    macro_recall = sum(
        per_class[c]["recall"]
        for c in CLASSES
    ) / len(CLASSES)

    macro_f1 = sum(
        per_class[c]["f1"]
        for c in CLASSES
    ) / len(CLASSES)

    weighted_f1 = safe_divide(
        sum(
            per_class[c]["f1"]
            * per_class[c]["support"]
            for c in CLASSES
        ),
        total,
    )

    return {
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "confusion_matrix": matrix,
        "per_class": per_class,
    }


def calculate_mitre_metrics(
    expected_all: list[list[str]],
    predicted_all: list[list[str]],
) -> dict[str, float]:

    expected = {
        technique
        for techniques in expected_all
        for technique in techniques
    }

    predicted = {
        technique
        for techniques in predicted_all
        for technique in techniques
    }

    tp = len(expected & predicted)

    fp = len(predicted - expected)

    fn = len(expected - predicted)

    precision = safe_divide(
        tp,
        tp + fp,
    )

    recall = safe_divide(
        tp,
        tp + fn,
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
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
    print("AGENTIC AI-SOC - MULTICLASS STRESS EVALUATION")
    print("=" * 80)

    with open(
        DATASET_FILE,
        "r",
        encoding="utf-8",
    ) as f:
        scenarios = json.load(f)

    print(
        f"Stress scenarios : {len(scenarios)}"
    )

    print(
        "Classes           : "
        "BENIGN / SUSPICIOUS / MALICIOUS"
    )

    print(
        "Evaluation mode   : "
        "Unseen research stress-test"
    )

    print("=" * 80)

    TEMP_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    orchestrator = SOCOrchestrator()

    # Disable LLM for deterministic quantitative evaluation.
    def skip_llm(*args, **kwargs):

        return {
            "status": "SKIPPED_FOR_EVALUATION",
            "reason": (
                "LLM disabled during quantitative "
                "multiclass evaluation."
            ),
        }

    orchestrator.llm.generate = skip_llm

    y_true = []
    y_pred = []

    expected_mitre = []
    predicted_mitre = []

    scenario_results = []

    total_latency = 0.0

    for scenario in scenarios:

        scenario_id = scenario["scenario_id"]

        temp_file = (
            TEMP_DIR
            / f"{scenario_id}.jsonl"
        )

        write_events(
            scenario["events"],
            temp_file,
        )

        start = time.perf_counter()

        result = orchestrator.run(
            temp_file
        )

        latency = (
            time.perf_counter()
            - start
        )

        total_latency += latency

        ground_truth = str(
            scenario.get(
                "ground_truth",
                "BENIGN",
            )
        ).upper()

        decision = result.get(
            "decision",
            {},
        )

        predicted = str(
            decision.get(
                "decision",
                "BENIGN",
            )
        ).upper()

        if predicted not in CLASSES:
            predicted = "BENIGN"

        y_true.append(
            ground_truth
        )

        y_pred.append(
            predicted
        )

        expected = [
            str(x)
            for x in scenario.get(
                "expected_techniques",
                [],
            )
        ]

        predicted_techniques = []

        for finding in result.get(
            "findings",
            [],
        ):

            technique = extract_mitre_technique(
                finding
            )

            if technique:
                predicted_techniques.append(
                    technique
                )

        expected_mitre.append(
            expected
        )

        predicted_mitre.append(
            predicted_techniques
        )

        risk = result.get(
            "risk_assessment",
            {},
        )

        risk_score = risk.get(
            "risk_score",
            0,
        )

        risk_level = risk.get(
            "risk_level",
            "UNKNOWN",
        )

        correct = (
            ground_truth == predicted
        )

        scenario_results.append(
            {
                "scenario_id": scenario_id,
                "name": scenario.get(
                    "name"
                ),
                "ground_truth": ground_truth,
                "predicted_decision": predicted,
                "correct": correct,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "expected_techniques": expected,
                "predicted_techniques": (
                    predicted_techniques
                ),
                "latency_seconds": latency,
            }
        )

        status = "OK" if correct else "ERROR"

        print(
            f"{scenario_id:<6} | "
            f"GT={ground_truth:<10} | "
            f"PRED={predicted:<10} | "
            f"RISK={risk_score:>3} | "
            f"{status}"
        )

    metrics = calculate_multiclass_metrics(
        y_true,
        y_pred,
    )

    mitre = calculate_mitre_metrics(
        expected_mitre,
        predicted_mitre,
    )

    average_latency = safe_divide(
        total_latency,
        len(scenarios),
    )

    # ------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------

    print()
    print("=" * 80)
    print("MULTICLASS FINAL METRICS")
    print("=" * 80)

    print(
        f"Accuracy       : "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Macro Precision: "
        f"{metrics['macro_precision']:.4f}"
    )

    print(
        f"Macro Recall   : "
        f"{metrics['macro_recall']:.4f}"
    )

    print(
        f"Macro F1       : "
        f"{metrics['macro_f1']:.4f}"
    )

    print(
        f"Weighted F1    : "
        f"{metrics['weighted_f1']:.4f}"
    )

    print()

    print(
        "Per-Class Performance"
    )

    print("-" * 80)

    for class_name in CLASSES:

        values = metrics[
            "per_class"
        ][class_name]

        print(
            f"{class_name:<12} | "
            f"P={values['precision']:.4f} | "
            f"R={values['recall']:.4f} | "
            f"F1={values['f1']:.4f} | "
            f"Support={values['support']}"
        )

    print()

    print(
        "Confusion Matrix"
    )

    print(
        "Rows = Actual | "
        "Columns = Predicted"
    )

    print(
        f"{'':12}"
        f"{'BENIGN':>12}"
        f"{'SUSPICIOUS':>14}"
        f"{'MALICIOUS':>13}"
    )

    matrix = metrics[
        "confusion_matrix"
    ]

    for actual in CLASSES:

        print(
            f"{actual:<12}"
            f"{matrix[actual]['BENIGN']:>12}"
            f"{matrix[actual]['SUSPICIOUS']:>14}"
            f"{matrix[actual]['MALICIOUS']:>13}"
        )

    print()

    print(
        "MITRE Technique Mapping"
    )

    print(
        f"Precision : "
        f"{mitre['precision']:.4f}"
    )

    print(
        f"Recall    : "
        f"{mitre['recall']:.4f}"
    )

    print(
        f"F1        : "
        f"{mitre['f1']:.4f}"
    )

    print()

    print(
        f"Average Latency : "
        f"{average_latency:.6f}s"
    )

    print("=" * 80)

    output = {
        "evaluation": {
            "dataset": (
                "stress_test_scenarios.json"
            ),
            "scenario_count": len(
                scenarios
            ),
            "classes": CLASSES,
            "evaluation_type": (
                "unseen research stress-test"
            ),
            "llm_used": False,
        },
        "metrics": {
            "accuracy": metrics[
                "accuracy"
            ],
            "macro_precision": metrics[
                "macro_precision"
            ],
            "macro_recall": metrics[
                "macro_recall"
            ],
            "macro_f1": metrics[
                "macro_f1"
            ],
            "weighted_f1": metrics[
                "weighted_f1"
            ],
            "per_class": metrics[
                "per_class"
            ],
            "confusion_matrix": metrics[
                "confusion_matrix"
            ],
            "mitre_precision": mitre[
                "precision"
            ],
            "mitre_recall": mitre[
                "recall"
            ],
            "mitre_f1": mitre[
                "f1"
            ],
            "average_latency_seconds": (
                average_latency
            ),
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
        f"Results saved to: "
        f"{RESULTS_FILE}"
    )

    print(
        "MULTICLASS STRESS "
        "EVALUATION COMPLETE"
    )


if __name__ == "__main__":
    main() 