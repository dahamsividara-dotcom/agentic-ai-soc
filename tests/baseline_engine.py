import json
import time
from pathlib import Path

from detection.log_ingestor import LogIngestor


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    BASE_DIR
    / "data"
    / "holdout_scenarios.json"
)

RESULTS_FILE = (
    BASE_DIR
    / "data"
    / "baseline_evaluation_results.json"
)


class RuleBasedBaseline:
    """
    Conventional rule-based SOC baseline.

    This intentionally does NOT use:
    - Attack-chain reasoning
    - CTI enrichment
    - Risk assessment agent
    - AI reasoning
    - LLM reasoning
    - Agentic correlation

    It represents a conventional alert/rule workflow.
    """

    VERSION = "1.0"

    def __init__(self):

        self.ingestor = LogIngestor()

    # ========================================================
    # ANALYZE EVENTS
    # ========================================================

    def analyze(self, events):

        alerts = []

        for event in events:

            process = str(
                event.get(
                    "process",
                    ""
                )
            ).lower()

            command_line = str(
                event.get(
                    "command_line",
                    ""
                )
            ).lower()

            event_type = str(
                event.get(
                    "event_type",
                    ""
                )
            ).lower()

            # ------------------------------------------------
            # Rule 1: PowerShell
            # ------------------------------------------------

            if (
                "powershell" in process
                or "powershell" in command_line
            ):

                alerts.append(
                    {
                        "rule_id":
                            "RB-001",

                        "alert":
                            "PowerShell Activity",

                        "severity":
                            "MEDIUM",

                        "mitre":
                            "T1059.001",
                    }
                )

            # ------------------------------------------------
            # Rule 2: Discovery
            # ------------------------------------------------

            discovery_commands = [
                "whoami",
                "ipconfig",
                "systeminfo",
                "tasklist",
                "net user",
                "net group",
            ]

            for command in discovery_commands:

                if command in command_line:

                    alerts.append(
                        {
                            "rule_id":
                                "RB-002",

                            "alert":
                                "System Discovery",

                            "severity":
                                "MEDIUM",

                            "mitre":
                                "T1033",
                        }
                    )

                    break

            # ------------------------------------------------
            # Rule 3: Failed login
            # ------------------------------------------------

            if (
                event.get("event_id") == 4625
                or "failed login" in event_type
                or "failed authentication"
                in event_type
            ):

                alerts.append(
                    {
                        "rule_id":
                            "RB-003",

                        "alert":
                            "Failed Authentication",

                        "severity":
                            "LOW",

                        "mitre":
                            "T1110",
                    }
                )

            # ------------------------------------------------
            # Rule 4: External network
            # ------------------------------------------------

            destination_ip = str(
                event.get(
                    "destination_ip",
                    ""
                )
            )

            if (
                event.get("event_id") == 5156
                and destination_ip
                and not self._is_private_ip(
                    destination_ip
                )
            ):

                alerts.append(
                    {
                        "rule_id":
                            "RB-004",

                        "alert":
                            "External Network Connection",

                        "severity":
                            "LOW",

                        "mitre":
                            "T1071",
                    }
                )

        # ----------------------------------------------------
        # Repeated authentication rule
        # ----------------------------------------------------

        failed_count = sum(

            1

            for event in events

            if (
                event.get("event_id") == 4625
                or "failed login"
                in str(
                    event.get(
                        "event_type",
                        ""
                    )
                ).lower()
            )
        )

        if failed_count >= 3:

            alerts.append(
                {
                    "rule_id":
                        "RB-005",

                    "alert":
                        "Repeated Failed Authentication",

                    "severity":
                        "HIGH",

                    "mitre":
                        "T1110",
                }
            )

        return alerts

    # ========================================================
    # PRIVATE IP CHECK
    # ========================================================

    @staticmethod
    def _is_private_ip(ip):

        private_prefixes = (
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
        )

        return str(ip).startswith(
            private_prefixes
        )

    # ========================================================
    # FINAL DECISION
    # ========================================================

    def decide(self, alerts):

        if not alerts:

            return "BENIGN"

        # Conventional rule-based SOC:
        # any alert becomes an incident candidate.
        #
        # Multiple alerts / high severity
        # become MALICIOUS.

        high_alerts = sum(
            1
            for alert in alerts
            if alert.get(
                "severity"
            ) == "HIGH"
        )

        if high_alerts > 0:

            return "MALICIOUS"

        if len(alerts) >= 2:

            return "MALICIOUS"

        return "SUSPICIOUS"


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
        "AGENTIC AI-SOC - RULE-BASED BASELINE"
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
        f"Dataset   : "
        f"{DATASET_FILE.name}"
    )

    print(
        f"Scenarios : "
        f"{len(scenarios)}"
    )

    print()

    baseline = RuleBasedBaseline()

    results = []

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    tp = 0
    tn = 0
    fp = 0
    fn = 0

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

        expected_attack = bool(
            scenario.get(
                "expected_attack",
                False,
            )
        )

        events = scenario.get(
            "events",
            [],
        )

        # ----------------------------------------------------
        # Run baseline
        # ----------------------------------------------------

        start = time.perf_counter()

        alerts = baseline.analyze(
            events
        )

        predicted_decision = (
            baseline.decide(
                alerts
            )
        )

        end = time.perf_counter()

        latency = end - start

        total_latency += latency

        predicted_attack = (
            predicted_decision
            == "MALICIOUS"
        )

        # ----------------------------------------------------
        # Classification
        # ----------------------------------------------------

        if (
            expected_attack
            and predicted_attack
        ):

            classification = "CORRECT"

            tp += 1

        elif (
            not expected_attack
            and not predicted_attack
        ):

            classification = "CORRECT"

            tn += 1

        elif (
            not expected_attack
            and predicted_attack
        ):

            classification = "FALSE_POSITIVE"

            fp += 1

        else:

            classification = "FALSE_NEGATIVE"

            fn += 1

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------

        predicted_mitre = sorted(
            set(
                alert["mitre"]
                for alert in alerts
                if alert.get("mitre")
            )
        )

        expected_mitre = sorted(
            set(
                scenario.get(
                    "expected_techniques",
                    [],
                )
            )
        )

        matches = sorted(
            set(predicted_mitre)
            & set(expected_mitre)
        )

        results.append(
            {
                "scenario_id":
                    scenario_id,

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

                "alert_count":
                    len(alerts),

                "expected_mitre":
                    expected_mitre,

                "predicted_mitre":
                    predicted_mitre,

                "mitre_matches":
                    matches,

                "latency_seconds":
                    round(
                        latency,
                        6,
                    ),
            }
        )

        # ----------------------------------------------------
        # Output
        # ----------------------------------------------------

        print(
            f"{scenario_id} | "
            f"{ground_truth:<18} | "
            f"{predicted_decision:<10} | "
            f"{classification}"
        )

    # ========================================================
    # METRICS
    # ========================================================

    total = len(
        scenarios
    )

    accuracy = safe_divide(
        tp + tn,
        total,
    )

    precision = safe_divide(
        tp,
        tp + fp,
    )

    recall = safe_divide(
        tp,
        tp + fn,
    )

    f1 = safe_divide(
        2 * precision * recall,
        precision + recall,
    )

    fpr = safe_divide(
        fp,
        fp + tn,
    )

    # --------------------------------------------------------
    # MITRE metrics
    # --------------------------------------------------------

    mitre_tp = 0
    mitre_predicted = 0
    mitre_expected = 0

    for result in results:

        mitre_tp += len(
            result[
                "mitre_matches"
            ]
        )

        mitre_predicted += len(
            result[
                "predicted_mitre"
            ]
        )

        mitre_expected += len(
            result[
                "expected_mitre"
            ]
        )

    mitre_precision = safe_divide(
        mitre_tp,
        mitre_predicted,
    )

    mitre_recall = safe_divide(
        mitre_tp,
        mitre_expected,
    )

    mitre_f1 = safe_divide(
        2
        * mitre_precision
        * mitre_recall,
        mitre_precision
        + mitre_recall,
    )

    average_latency = safe_divide(
        total_latency,
        total,
    )

    # ========================================================
    # RESULT OBJECT
    # ========================================================

    metrics = {

        "system":
            "Rule-Based SOC Baseline",

        "version":
            "1.0",

        "total_scenarios":
            total,

        "true_positive":
            tp,

        "true_negative":
            tn,

        "false_positive":
            fp,

        "false_negative":
            fn,

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
                f1,
                4,
            ),

        "false_positive_rate":
            round(
                fpr,
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

    output = {

        "evaluation_type":
            "BASELINE_HOLDOUT",

        "dataset":
            DATASET_FILE.name,

        "metrics":
            metrics,

        "scenarios":
            results,
    }

    # ========================================================
    # SAVE
    # ========================================================

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
        )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    print()
    print("=" * 80)
    print(
        "FINAL RULE-BASED BASELINE METRICS"
    )
    print("=" * 80)
    print()

    print(
        f"Total Scenarios        : {total}"
    )

    print(
        f"True Positives         : {tp}"
    )

    print(
        f"True Negatives         : {tn}"
    )

    print(
        f"False Positives        : {fp}"
    )

    print(
        f"False Negatives        : {fn}"
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
        f"{f1:.4f}"
    )

    print(
        f"False Positive Rate    : "
        f"{fpr:.4f}"
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
        "RULE-BASED BASELINE COMPLETE"
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