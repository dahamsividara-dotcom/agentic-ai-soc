import json
import time
from pathlib import Path

from backend.soc_orchestrator import SOCOrchestrator


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    BASE_DIR
    / "data"
    / "holdout_scenarios.json"
)

TEMP_LOG_FILE = (
    BASE_DIR
    / "data"
    / "holdout_temp.jsonl"
)

RESULTS_FILE = (
    BASE_DIR
    / "data"
    / "holdout_evaluation_results.json"
)


# ============================================================
# WRITE EVENTS
# ============================================================

def write_events(events):

    with open(
        TEMP_LOG_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        for event in events:

            file.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                )
                + "\n"
            )


# ============================================================
# MITRE TECHNIQUE EXTRACTION
# ============================================================

def extract_mitre_technique(finding):

    technique = finding.get(
        "mitre_attack"
    )

    if isinstance(
        technique,
        dict,
    ):

        technique_id = technique.get(
            "technique_id"
        )

        if technique_id:

            return technique_id

    return None


# ============================================================
# BINARY CLASSIFICATION
# ============================================================

def is_attack_ground_truth(
    scenario,
):

    return bool(
        scenario.get(
            "expected_attack",
            False,
        )
    )


def is_attack_prediction(
    decision,
):

    predicted_decision = str(
        decision.get(
            "decision",
            "BENIGN",
        )
    ).upper()

    return predicted_decision == "MALICIOUS"


# ============================================================
# SAFE DIVISION
# ============================================================

def safe_divide(
    numerator,
    denominator,
):

    if denominator == 0:

        return 0.0

    return numerator / denominator


# ============================================================
# EVALUATION
# ============================================================

def evaluate():

    print("=" * 80)
    print(
        "AGENTIC AI-SOC - UNSEEN HOLD-OUT EVALUATION"
    )
    print("=" * 80)
    print()

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    if not DATASET_FILE.exists():

        raise FileNotFoundError(
            f"Dataset not found: {DATASET_FILE}"
        )

    with open(
        DATASET_FILE,
        "r",
        encoding="utf-8",
    ) as file:

        scenarios = json.load(
            file
        )

    print(
        f"Dataset : {DATASET_FILE.name}"
    )

    print(
        f"Scenarios: {len(scenarios)}"
    )

    print()

    # --------------------------------------------------------
    # Create orchestrator
    # --------------------------------------------------------

    orchestrator = SOCOrchestrator()

    # --------------------------------------------------------
    # Skip LLM during metric evaluation
    #
    # This keeps the evaluation deterministic and avoids
    # unnecessary local LLM generation for every scenario.
    # --------------------------------------------------------

    orchestrator.llm.generate = (
        lambda **kwargs: {
            "status":
                "EVALUATION_SKIP",

            "message":
                "LLM generation skipped during metric evaluation.",
        }
    )

    results = []

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    # ========================================================
    # MITRE METRICS
    # ========================================================

    mitre_true_positive = 0
    mitre_predicted_total = 0
    mitre_expected_total = 0

    # ========================================================
    # LATENCY
    # ========================================================

    total_latency = 0.0

    # ========================================================
    # SCENARIO LOOP
    # ========================================================

    for scenario in scenarios:

        scenario_id = scenario.get(
            "scenario_id",
            "UNKNOWN",
        )

        ground_truth = str(
            scenario.get(
                "ground_truth",
                "UNKNOWN",
            )
        ).upper()

        expected_attack = (
            is_attack_ground_truth(
                scenario
            )
        )

        expected_techniques = set(
            scenario.get(
                "expected_techniques",
                [],
            )
        )

        events = scenario.get(
            "events",
            [],
        )

        # ----------------------------------------------------
        # Write temporary JSONL
        # ----------------------------------------------------

        write_events(
            events
        )

        # ----------------------------------------------------
        # Run SOC
        # ----------------------------------------------------

        start_time = time.perf_counter()

        result = orchestrator.run(
            str(TEMP_LOG_FILE)
        )

        end_time = time.perf_counter()

        latency = (
            end_time - start_time
        )

        total_latency += latency

        # ----------------------------------------------------
        # Decision
        # ----------------------------------------------------

        decision = result.get(
            "decision",
            {},
        )

        predicted_decision = str(
            decision.get(
                "decision",
                "BENIGN",
            )
        ).upper()

        predicted_attack = (
            is_attack_prediction(
                decision
            )
        )

        # ----------------------------------------------------
        # Binary classification
        # ----------------------------------------------------

        if (
            expected_attack
            and predicted_attack
        ):

            classification = "CORRECT"

            true_positive += 1

        elif (
            not expected_attack
            and not predicted_attack
        ):

            classification = "CORRECT"

            true_negative += 1

        elif (
            not expected_attack
            and predicted_attack
        ):

            classification = "FALSE_POSITIVE"

            false_positive += 1

        else:

            classification = "FALSE_NEGATIVE"

            false_negative += 1

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        findings = result.get(
            "findings",
            [],
        )

        # ----------------------------------------------------
        # Predicted MITRE techniques
        # ----------------------------------------------------

        predicted_techniques = set()

        for finding in findings:

            technique_id = (
                extract_mitre_technique(
                    finding
                )
            )

            if technique_id:

                predicted_techniques.add(
                    technique_id
                )

        # ----------------------------------------------------
        # MITRE matching
        # ----------------------------------------------------

        technique_matches = (
            expected_techniques
            & predicted_techniques
        )

        mitre_true_positive += len(
            technique_matches
        )

        mitre_predicted_total += len(
            predicted_techniques
        )

        mitre_expected_total += len(
            expected_techniques
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

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

        risk_confidence = (
            risk_assessment.get(
                "risk_confidence",
                0.0,
            )
        )

        # ----------------------------------------------------
        # Decision confidence
        # ----------------------------------------------------

        decision_confidence = (
            decision.get(
                "confidence",
                0.0,
            )
        )

        # ----------------------------------------------------
        # Store scenario result
        # ----------------------------------------------------

        scenario_result = {

            "scenario_id":
                scenario_id,

            "name":
                scenario.get(
                    "name"
                ),

            "ground_truth":
                ground_truth,

            "predicted_decision":
                predicted_decision,

            "expected_attack":
                expected_attack,

            "predicted_attack":
                predicted_attack,

            "classification":
                classification,

            "finding_count":
                len(findings),

            "expected_mitre":
                sorted(
                    expected_techniques
                ),

            "predicted_mitre":
                sorted(
                    predicted_techniques
                ),

            "mitre_matches":
                sorted(
                    technique_matches
                ),

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "risk_confidence":
                risk_confidence,

            "decision_confidence":
                decision_confidence,

            "latency_seconds":
                round(
                    latency,
                    6,
                ),
        }

        results.append(
            scenario_result
        )

        # ----------------------------------------------------
        # Scenario output
        # ----------------------------------------------------

        print(
            f"{scenario_id} | "
            f"{scenario.get('name', 'Unknown')}"
        )

        print(
            f"  Ground Truth       : "
            f"{ground_truth}"
        )

        print(
            f"  Final Decision     : "
            f"{predicted_decision}"
        )

        print(
            f"  Expected Attack    : "
            f"{expected_attack}"
        )

        print(
            f"  Classification     : "
            f"{classification}"
        )

        print(
            f"  Findings           : "
            f"{len(findings)}"
        )

        print(
            f"  Expected MITRE     : "
            f"{sorted(expected_techniques)}"
        )

        print(
            f"  Predicted MITRE    : "
            f"{sorted(predicted_techniques)}"
        )

        print(
            f"  MITRE Matches      : "
            f"{len(technique_matches)}"
        )

        print(
            f"  Risk               : "
            f"{risk_score}/100 "
            f"({risk_level})"
        )

        print(
            f"  Risk Confidence    : "
            f"{risk_confidence}"
        )

        print(
            f"  Decision Confidence: "
            f"{decision_confidence}"
        )

        print(
            f"  Latency            : "
            f"{latency:.3f}s"
        )

        print(
            "-" * 80
        )

    # ========================================================
    # CLASSIFICATION METRICS
    # ========================================================

    total_scenarios = len(
        scenarios
    )

    accuracy = safe_divide(
        true_positive
        + true_negative,
        total_scenarios,
    )

    precision = safe_divide(
        true_positive,
        true_positive
        + false_positive,
    )

    recall = safe_divide(
        true_positive,
        true_positive
        + false_negative,
    )

    f1_score = safe_divide(
        2 * precision * recall,
        precision + recall,
    )

    false_positive_rate = safe_divide(
        false_positive,
        false_positive
        + true_negative,
    )

    # ========================================================
    # MITRE METRICS
    # ========================================================

    mitre_precision = safe_divide(
        mitre_true_positive,
        mitre_predicted_total,
    )

    mitre_recall = safe_divide(
        mitre_true_positive,
        mitre_expected_total,
    )

    mitre_f1 = safe_divide(
        2
        * mitre_precision
        * mitre_recall,
        mitre_precision
        + mitre_recall,
    )

    # ========================================================
    # LATENCY
    # ========================================================

    average_latency = safe_divide(
        total_latency,
        total_scenarios,
    )

    # ========================================================
    # FINAL METRICS
    # ========================================================

    metrics = {

        "evaluation_type":
            "UNSEEN_HOLDOUT",

        "dataset":
            DATASET_FILE.name,

        "total_scenarios":
            total_scenarios,

        "true_positive":
            true_positive,

        "true_negative":
            true_negative,

        "false_positive":
            false_positive,

        "false_negative":
            false_negative,

        "accuracy":
            round(
                accuracy,
                4,
            ),

        "precision":
            round(
                precision,
                4,
            ),

        "recall":
            round(
                recall,
                4,
            ),

        "f1_score":
            round(
                f1_score,
                4,
            ),

        "false_positive_rate":
            round(
                false_positive_rate,
                4,
            ),

        "mitre_precision":
            round(
                mitre_precision,
                4,
            ),

        "mitre_recall":
            round(
                mitre_recall,
                4,
            ),

        "mitre_f1":
            round(
                mitre_f1,
                4,
            ),

        "average_latency_seconds":
            round(
                average_latency,
                6,
            ),
    }

    # ========================================================
    # SAVE RESULTS
    # ========================================================

    output = {

        "project":
            "Agentic AI-SOC",

        "version":
            "Holdout Evaluation V1",

        "metrics":
            metrics,

        "scenarios":
            results,
    }

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # ========================================================
    # FINAL DISPLAY
    # ========================================================

    print()
    print("=" * 80)
    print(
        "FINAL AGENTIC AI-SOC HOLD-OUT METRICS"
    )
    print("=" * 80)
    print()

    print(
        f"Total Scenarios        : "
        f"{total_scenarios}"
    )

    print()

    print(
        f"True Positives         : "
        f"{true_positive}"
    )

    print(
        f"True Negatives         : "
        f"{true_negative}"
    )

    print(
        f"False Positives        : "
        f"{false_positive}"
    )

    print(
        f"False Negatives        : "
        f"{false_negative}"
    )

    print()

    print(
        f"Accuracy               : "
        f"{accuracy:.4f}"
    )

    print(
        f"Precision              : "
        f"{precision:.4f}"
    )

    print(
        f"Recall                 : "
        f"{recall:.4f}"
    )

    print(
        f"F1 Score               : "
        f"{f1_score:.4f}"
    )

    print(
        f"False Positive Rate    : "
        f"{false_positive_rate:.4f}"
    )

    print()

    print(
        f"MITRE Precision        : "
        f"{mitre_precision:.4f}"
    )

    print(
        f"MITRE Recall           : "
        f"{mitre_recall:.4f}"
    )

    print(
        f"MITRE F1               : "
        f"{mitre_f1:.4f}"
    )

    print()

    print(
        f"Average Latency        : "
        f"{average_latency:.3f}s"
    )

    print()
    print("=" * 80)
    print(
        "HOLD-OUT EVALUATION COMPLETE"
    )
    print("=" * 80)

    print()

    print(
        "Results saved to:"
    )

    print(
        RESULTS_FILE
    )


if __name__ == "__main__":

    evaluate()