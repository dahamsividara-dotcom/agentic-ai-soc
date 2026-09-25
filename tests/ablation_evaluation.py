from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from backend.soc_orchestrator import SOCOrchestrator
from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine
from attack_graph.attack_chain_engine import AttackChainEngine
from agents.investigation_agent import InvestigationAgent
from agents.risk_assessment_agent import RiskAssessmentAgent
from agents.decision_agent import DecisionAgent
from agents.ai_reasoning_agent import AIReasoningAgent


BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_FILE = BASE_DIR / "data" / "holdout_scenarios.json"
TEMP_LOG_FILE = BASE_DIR / "data" / "ablation_temp.jsonl"
RESULTS_FILE = BASE_DIR / "data" / "ablation_evaluation_results.json"


# ============================================================
# FILE HELPERS
# ============================================================

def load_dataset() -> list[dict[str, Any]]:
    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def write_events(events: list[dict[str, Any]]) -> None:
    with open(TEMP_LOG_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


# ============================================================
# BINARY CLASSIFICATION METRICS
# ============================================================

def binary_metrics(
    y_true: list[bool],
    y_pred: list[bool],
) -> dict[str, float | int]:

    tp = sum(t and p for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))

    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    if precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0

    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }


# ============================================================
# MITRE HELPERS
# ============================================================

def normalize_mitre_id(value: Any) -> str | None:
    """
    Normalize MITRE ATT&CK technique values.

    Examples:
        T1059.001
        t1059.001
        T1059.001 - PowerShell
        Technique: T1059.001
    """

    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    upper = text.upper()

    # Direct ID extraction
    import re

    match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", upper)

    if match:
        return match.group(0)

    return None


def extract_mitre_from_finding(
    finding: dict[str, Any],
) -> list[str]:

    techniques: set[str] = set()

    candidate_keys = [
        "mitre_technique",
        "mitre_techniques",
        "technique",
        "techniques",
        "mitre_id",
        "mitre_ids",
        "attack_technique",
        "attack_techniques",
    ]

    for key in candidate_keys:
        value = finding.get(key)

        if value is None:
            continue

        if isinstance(value, list):
            values = value
        else:
            values = [value]

        for item in values:
            technique = normalize_mitre_id(item)

            if technique:
                techniques.add(technique)

    return sorted(techniques)


def extract_mitre_from_stage(
    stage: dict[str, Any],
) -> list[str]:

    techniques: set[str] = set()

    candidate_keys = [
        "mitre_technique",
        "mitre_techniques",
        "technique",
        "techniques",
        "mitre_id",
        "mitre_ids",
        "attack_technique",
        "attack_techniques",
    ]

    for key in candidate_keys:
        value = stage.get(key)

        if value is None:
            continue

        if isinstance(value, list):
            values = value
        else:
            values = [value]

        for item in values:
            technique = normalize_mitre_id(item)

            if technique:
                techniques.add(technique)

    return sorted(techniques)


def extract_predicted_mitre(
    result: dict[str, Any],
) -> list[str]:
    """
    Extract predicted MITRE techniques from all available
    output locations.

    Priority:
      1. Findings
      2. Attack-chain stages
      3. AI reasoning
    """

    techniques: set[str] = set()

    # --------------------------------------------------------
    # 1. Findings
    # --------------------------------------------------------

    findings = result.get("findings", [])

    if isinstance(findings, list):
        for finding in findings:

            if not isinstance(finding, dict):
                continue

            for technique in extract_mitre_from_finding(finding):
                techniques.add(technique)

    # --------------------------------------------------------
    # 2. Attack-chain stages
    # --------------------------------------------------------

    attack_chain = result.get("attack_chain", {})

    if isinstance(attack_chain, dict):

        stages = attack_chain.get("stages", [])

        if isinstance(stages, list):

            for stage in stages:

                if not isinstance(stage, dict):
                    continue

                for technique in extract_mitre_from_stage(stage):
                    techniques.add(technique)

    # --------------------------------------------------------
    # 3. AI reasoning fallback
    # --------------------------------------------------------

    ai_reasoning = result.get("ai_reasoning", {})

    if isinstance(ai_reasoning, dict):

        mitre = ai_reasoning.get("mitre_techniques", [])

        if isinstance(mitre, list):
            values = mitre
        else:
            values = [mitre]

        for value in values:

            technique = normalize_mitre_id(value)

            if technique:
                techniques.add(technique)

    return sorted(techniques)


def mitre_metrics(
    scenarios: list[dict[str, Any]],
    scenario_results: list[dict[str, Any]],
) -> dict[str, float]:

    predicted_total = 0
    correct = 0
    expected_total = 0

    for scenario, result in zip(
        scenarios,
        scenario_results,
    ):

        expected_values = scenario.get(
            "expected_techniques",
            [],
        )

        expected: set[str] = set()

        if isinstance(expected_values, list):
            values = expected_values
        else:
            values = [expected_values]

        for value in values:

            technique = normalize_mitre_id(value)

            if technique:
                expected.add(technique)

        predicted_values = result.get(
            "predicted_mitre",
            [],
        )

        predicted: set[str] = set()

        if isinstance(predicted_values, list):
            values = predicted_values
        else:
            values = [predicted_values]

        for value in values:

            technique = normalize_mitre_id(value)

            if technique:
                predicted.add(technique)

        predicted_total += len(predicted)
        expected_total += len(expected)

        correct += len(
            expected.intersection(predicted)
        )

    precision = (
        correct / predicted_total
        if predicted_total
        else 0.0
    )

    recall = (
        correct / expected_total
        if expected_total
        else 0.0
    )

    if precision + recall:
        f1 = (
            2 * precision * recall
            / (precision + recall)
        )
    else:
        f1 = 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "correct": correct,
        "predicted_total": predicted_total,
        "expected_total": expected_total,
    }


# ============================================================
# ABLATION CONFIGURATION
# ============================================================

ABLATIONS = [

    {
        "id": "FULL",
        "name": "Full Agentic AI-SOC",
        "description": (
            "Complete multi-agent architecture"
        ),
    },

    {
        "id": "NO_ATTACK_CHAIN",
        "name": "Without Attack-Chain Reasoning",
        "description": (
            "Removes temporal/entity attack-chain "
            "correlation"
        ),
    },

    {
        "id": "NO_CTI",
        "name": "Without CTI",
        "description": (
            "Removes Cyber Threat Intelligence enrichment"
        ),
    },

    {
        "id": "NO_CONTEXT",
        "name": "Without Context-Aware Detection",
        "description": (
            "Uses a simplified rule-based detection layer"
        ),
    },

    {
        "id": "NO_RISK",
        "name": "Without Dynamic Risk Assessment",
        "description": (
            "Uses static attack-chain risk instead "
            "of dynamic risk"
        ),
    },
]


# ============================================================
# SIMPLE DETECTION ENGINE
# ============================================================

class SimpleDetectionEngine:
    """
    Ablation detector.

    Represents a conventional rule-focused detector
    without context-aware reasoning.
    """

    VERSION = "ABLATION-1.0"

    def analyze(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        findings = []

        for event in events:

            event_type = str(
                event.get(
                    "event_type",
                    "",
                )
            ).lower()

            process = str(
                event.get(
                    "process",
                    "",
                )
            ).lower()

            command = str(
                event.get(
                    "command_line",
                    "",
                )
            ).lower()

            finding = None

            # ------------------------------------------------
            # PowerShell
            # ------------------------------------------------

            if (
                "powershell" in process
                or "powershell" in command
            ):

                finding = {
                    "rule_id": "AB-001",
                    "rule_name": "PowerShell Activity",
                    "decision": "SUSPICIOUS",
                    "severity": "MEDIUM",
                    "confidence": 0.70,
                    "mitre_technique": "T1059.001",
                    "event": event,
                }

            # ------------------------------------------------
            # Discovery
            # ------------------------------------------------

            elif (
                "whoami" in command
                or "ipconfig" in command
                or "systeminfo" in command
                or "tasklist" in command
                or "net user" in command
                or "net group" in command
            ):

                finding = {
                    "rule_id": "AB-002",
                    "rule_name": "Discovery Command",
                    "decision": "SUSPICIOUS",
                    "severity": "MEDIUM",
                    "confidence": 0.75,
                    "mitre_technique": "T1033",
                    "event": event,
                }

            # ------------------------------------------------
            # Failed authentication
            # ------------------------------------------------

            elif (
                "failed login" in event_type
                or "failed authentication" in event_type
            ):

                finding = {
                    "rule_id": "AB-003",
                    "rule_name": "Failed Authentication",
                    "decision": "SUSPICIOUS",
                    "severity": "LOW",
                    "confidence": 0.65,
                    "mitre_technique": "T1110",
                    "event": event,
                }

            # ------------------------------------------------
            # Network connection
            # ------------------------------------------------

            elif (
                "network connection" in event_type
            ):

                finding = {
                    "rule_id": "AB-004",
                    "rule_name": "Network Connection",
                    "decision": "SUSPICIOUS",
                    "severity": "LOW",
                    "confidence": 0.60,
                    "mitre_technique": "T1071",
                    "event": event,
                }

            if finding:
                findings.append(finding)

        return findings


# ============================================================
# NO-CTI INVESTIGATION AGENT
# ============================================================

class NoCTIInvestigationAgent:
    """
    Investigation agent without CTI enrichment.
    """

    VERSION = "ABLATION-1.0"

    def investigate(
        self,
        attack_chain: dict[str, Any],
    ) -> dict[str, Any]:

        stages = attack_chain.get(
            "stages",
            [],
        )

        evidence = []

        for stage in stages:

            evidence.append(
                {
                    "stage": stage.get("stage"),
                    "status": stage.get("status"),
                    "confidence": stage.get("confidence"),
                    "evidence": stage.get(
                        "evidence",
                        [],
                    ),
                }
            )

        confidences = [
            float(
                stage.get(
                    "confidence",
                    0.0,
                )
            )
            for stage in stages
            if stage.get("confidence") is not None
        ]

        confidence = (
            sum(confidences) / len(confidences)
            if confidences
            else 0.0
        )

        return {
            "agent": "Investigation Agent",
            "version": self.VERSION,
            "incident_status": attack_chain.get(
                "status",
                "NO_INCIDENT",
            ),
            "hypothesis": (
                "Investigation based only on "
                "security event evidence without "
                "CTI enrichment."
            ),
            "confidence": round(
                confidence,
                4,
            ),
            "evidence_count": len(evidence),
            "cti_matches": [],
            "cti_context": [],
            "evidence": evidence,
            "recommendations": [
                (
                    "Validate suspicious activity "
                    "against additional telemetry."
                ),
                (
                    "Review affected hosts and "
                    "user accounts."
                ),
            ],
        }


# ============================================================
# NO ATTACK-CHAIN ENGINE
# ============================================================

class NoAttackChainEngine:
    """
    Ablation engine that preserves individual
    findings but removes temporal/entity correlation.
    """

    VERSION = "ABLATION-1.0"

    def build_chain(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:

        stages = []

        for index, finding in enumerate(findings):

            stages.append(
                {
                    "stage_id": (
                        f"STAGE-{index + 1:03d}"
                    ),
                    "stage": self._map_stage(
                        finding
                    ),
                    "mitre_technique": (
                        finding.get(
                            "mitre_technique"
                        )
                    ),
                    "status": "OBSERVED",
                    "confidence": float(
                        finding.get(
                            "confidence",
                            0.0,
                        )
                    ),
                    "evidence": [finding],
                }
            )

        risk = self._simple_risk(
            findings
        )

        return {
            "chain_id": "ABLATION-CHAIN-001",
            "status": (
                "ACTIVE"
                if findings
                else "NO_INCIDENT"
            ),
            "risk_score": risk,
            "risk_level": self._risk_level(
                risk
            ),
            "stages": stages,
            "relationships": [],
            "relationship_count": 0,
            "strong_relationship_count": 0,
            "uncertainty": [
                "Temporal correlation disabled.",
                "Entity correlation disabled.",
                "Attack-chain reasoning disabled.",
            ],
            "explanation": (
                "Independent security findings "
                "without temporal/entity "
                "attack-chain correlation."
            ),
        }

    @staticmethod
    def _map_stage(
        finding: dict[str, Any],
    ) -> str:

        technique = finding.get(
            "mitre_technique"
        )

        mapping = {
            "T1059.001": "Execution",
            "T1033": "Discovery",
            "T1110": "Credential Access",
            "T1071": "Network Activity",
        }

        return mapping.get(
            technique,
            "Unknown",
        )

    @staticmethod
    def _simple_risk(
        findings: list[dict[str, Any]],
    ) -> int:

        score = 0

        weights = {
            "LOW": 10,
            "MEDIUM": 20,
            "HIGH": 35,
            "CRITICAL": 50,
        }

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "LOW",
                )
            ).upper()

            confidence = float(
                finding.get(
                    "confidence",
                    0.0,
                )
            )

            score += int(
                weights.get(
                    severity,
                    10,
                )
                * confidence
            )

        return min(
            score,
            100,
        )

    @staticmethod
    def _risk_level(
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"


# ============================================================
# ABLATION ORCHESTRATOR
# ============================================================

class AblationOrchestrator:

    def __init__(
        self,
        mode: str,
    ):

        self.mode = mode

        self.ingestor = LogIngestor()

        # ----------------------------------------------------
        # Detection
        # ----------------------------------------------------

        if mode == "NO_CONTEXT":
            self.detector = SimpleDetectionEngine()
        else:
            self.detector = DetectionEngine()

        # ----------------------------------------------------
        # Attack chain
        # ----------------------------------------------------

        if mode == "NO_ATTACK_CHAIN":
            self.chain_engine = NoAttackChainEngine()
        else:
            self.chain_engine = AttackChainEngine()

        # ----------------------------------------------------
        # CTI
        # ----------------------------------------------------

        if mode == "NO_CTI":
            self.investigator = (
                NoCTIInvestigationAgent()
            )
        else:
            self.investigator = InvestigationAgent()

        self.risk_assessor = (
            RiskAssessmentAgent()
        )

        self.decision_agent = (
            DecisionAgent()
        )

        self.ai_reasoner = (
            AIReasoningAgent()
        )

    def run(
        self,
        log_file: Path,
    ) -> dict[str, Any]:

        # ----------------------------------------------------
        # 1. Ingest
        # ----------------------------------------------------

        events = self.ingestor.ingest(
            log_file
        )

        # ----------------------------------------------------
        # 2. Detection
        # ----------------------------------------------------

        findings = self.detector.analyze(
            events
        )

        # ----------------------------------------------------
        # 3. Attack-chain reasoning
        # ----------------------------------------------------

        attack_chain = (
            self.chain_engine.build_chain(
                findings
            )
        )

        # ----------------------------------------------------
        # 4. Investigation / CTI
        # ----------------------------------------------------

        investigation = (
            self.investigator.investigate(
                attack_chain
            )
        )

        # ----------------------------------------------------
        # 5. Risk assessment
        # ----------------------------------------------------

        if self.mode == "NO_RISK":

            risk_assessment = {
                "agent": "Static Risk Assessment",
                "version": "ABLATION-1.0",
                "risk_score": attack_chain.get(
                    "risk_score",
                    0,
                ),
                "risk_level": attack_chain.get(
                    "risk_level",
                    "LOW",
                ),
                "confidence": 0.60,
                "evidence_score": 0,
                "temporal_score": 0,
                "entity_score": 0,
                "mitre_score": 0,
                "cti_score": 0,
                "uncertainty_penalty": 0,
            }

        else:

            risk_assessment = (
                self.risk_assessor.assess(
                    findings=findings,
                    attack_chain=attack_chain,
                    investigation=investigation,
                )
            )

        # ----------------------------------------------------
        # 6. Decision
        # ----------------------------------------------------

        decision = self.decision_agent.decide(
            findings=findings,
            risk_assessment=risk_assessment,
            attack_chain=attack_chain,
        )

        # ----------------------------------------------------
        # 7. AI reasoning
        # ----------------------------------------------------

        reasoning = self.ai_reasoner.reason(
            attack_chain,
            investigation,
            risk_assessment=risk_assessment,
        )

        return {
            "events": events,
            "findings": findings,
            "attack_chain": attack_chain,
            "investigation": investigation,
            "risk_assessment": risk_assessment,
            "decision": decision,
            "ai_reasoning": reasoning,
        }


# ============================================================
# SINGLE ABLATION EVALUATION
# ============================================================

def evaluate_ablation(
    config: dict[str, Any],
    scenarios: list[dict[str, Any]],
) -> dict[str, Any]:

    mode = config["id"]

    print()
    print("=" * 72)
    print(
        f"ABLATION: {config['name']}"
    )
    print(
        f"MODE    : {mode}"
    )
    print("=" * 72)

    orchestrator = AblationOrchestrator(
        mode
    )

    y_true = []
    y_pred = []

    scenario_results = []

    total_latency = 0.0

    for scenario in scenarios:

        scenario_id = scenario.get(
            "scenario_id",
            scenario.get(
                "id",
                "UNKNOWN",
            ),
        )

        ground_truth = str(
            scenario.get(
                "ground_truth",
                scenario.get(
                    "label",
                    "BENIGN",
                ),
            )
        ).upper()

        events = scenario.get(
            "events",
            [],
        )

        write_events(events)

        start = time.perf_counter()

        result = orchestrator.run(
            TEMP_LOG_FILE
        )

        latency = (
            time.perf_counter()
            - start
        )

        total_latency += latency

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

        # ----------------------------------------------------
        # Binary attack classification
        # ----------------------------------------------------

        predicted_attack = (
            predicted_decision
            == "MALICIOUS"
        )

        true_attack = (
            ground_truth
            == "MALICIOUS"
        )

        y_true.append(
            true_attack
        )

        y_pred.append(
            predicted_attack
        )

        # ----------------------------------------------------
        # MITRE extraction
        # ----------------------------------------------------

        predicted_mitre = (
            extract_predicted_mitre(
                result
            )
        )

        expected_mitre = []

        expected_values = scenario.get(
            "expected_techniques",
            [],
        )

        if isinstance(
            expected_values,
            list,
        ):
            for value in expected_values:

                technique = (
                    normalize_mitre_id(
                        value
                    )
                )

                if technique:
                    expected_mitre.append(
                        technique
                    )

        # ----------------------------------------------------
        # Scenario result
        # ----------------------------------------------------

        scenario_result = {
            "scenario_id": scenario_id,
            "ground_truth": ground_truth,
            "predicted_decision": (
                predicted_decision
            ),
            "binary_true_attack": (
                true_attack
            ),
            "binary_predicted_attack": (
                predicted_attack
            ),
            "correct": (
                ground_truth
                == predicted_decision
                or (
                    ground_truth
                    in {
                        "SUSPICIOUS",
                        "BENIGN_WITH_NOISE",
                    }
                    and predicted_decision
                    == "BENIGN"
                )
            ),
            "expected_mitre": sorted(
                set(expected_mitre)
            ),
            "predicted_mitre": predicted_mitre,
            "mitre_correct": sorted(
                set(expected_mitre)
                .intersection(
                    set(predicted_mitre)
                )
            ),
            "latency_seconds": round(
                latency,
                6,
            ),
        }

        scenario_results.append(
            scenario_result
        )

    # --------------------------------------------------------
    # Classification metrics
    # --------------------------------------------------------

    metrics = binary_metrics(
        y_true,
        y_pred,
    )

    # --------------------------------------------------------
    # MITRE metrics
    # --------------------------------------------------------

    mitre = mitre_metrics(
        scenarios,
        scenario_results,
    )

    average_latency = (
        total_latency
        / len(scenarios)
        if scenarios
        else 0.0
    )

    result = {
        "ablation_id": mode,
        "name": config["name"],
        "description": config["description"],

        "dataset": {
            "file": str(
                DATASET_FILE
            ),
            "scenario_count": len(
                scenarios
            ),
            "evaluation_type": (
                "Unseen holdout dataset"
            ),
        },

        "metrics": metrics,

        "mitre_metrics": mitre,

        "average_latency_seconds": round(
            average_latency,
            6,
        ),

        "scenario_results": scenario_results,
    }

    # --------------------------------------------------------
    # Console output
    # --------------------------------------------------------

    print(
        f"Accuracy   : "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Precision  : "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall     : "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1         : "
        f"{metrics['f1']:.4f}"
    )

    print(
        f"FP         : "
        f"{metrics['FP']}"
    )

    print(
        f"FN         : "
        f"{metrics['FN']}"
    )

    print(
        f"MITRE Precision : "
        f"{mitre['precision']:.4f}"
    )

    print(
        f"MITRE Recall    : "
        f"{mitre['recall']:.4f}"
    )

    print(
        f"MITRE F1        : "
        f"{mitre['f1']:.4f}"
    )

    print(
        f"MITRE Correct    : "
        f"{mitre['correct']}"
    )

    print(
        f"MITRE Predicted  : "
        f"{mitre['predicted_total']}"
    )

    print(
        f"MITRE Expected   : "
        f"{mitre['expected_total']}"
    )

    print(
        f"Latency          : "
        f"{average_latency:.6f}s"
    )

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    scenarios = load_dataset()

    print("=" * 72)
    print(
        "AGENTIC AI-SOC - ABLATION STUDY"
    )
    print("=" * 72)

    print(
        f"Holdout scenarios : "
        f"{len(scenarios)}"
    )

    print(
        "Evaluation mode   : "
        "Unseen holdout dataset"
    )

    print("=" * 72)

    all_results = []

    # --------------------------------------------------------
    # Run every ablation
    # --------------------------------------------------------

    for config in ABLATIONS:

        result = evaluate_ablation(
            config,
            scenarios,
        )

        all_results.append(
            result
        )

    # --------------------------------------------------------
    # Summary table
    # --------------------------------------------------------

    print()
    print("=" * 125)
    print(
        "ABLATION STUDY SUMMARY"
    )
    print("=" * 125)

    print(
        f"{'Variant':<38}"
        f"{'Accuracy':>10}"
        f"{'Precision':>11}"
        f"{'Recall':>10}"
        f"{'F1':>10}"
        f"{'FP':>7}"
        f"{'FN':>7}"
        f"{'MITRE F1':>12}"
    )

    print("-" * 125)

    for result in all_results:

        metrics = result[
            "metrics"
        ]

        mitre = result[
            "mitre_metrics"
        ]

        print(
            f"{result['name'][:37]:<38}"
            f"{metrics['accuracy']:>10.4f}"
            f"{metrics['precision']:>11.4f}"
            f"{metrics['recall']:>10.4f}"
            f"{metrics['f1']:>10.4f}"
            f"{metrics['FP']:>7}"
            f"{metrics['FN']:>7}"
            f"{mitre['f1']:>12.4f}"
        )

    print("=" * 125)

    # --------------------------------------------------------
    # Component impact
    # --------------------------------------------------------

    full = next(
        result
        for result in all_results
        if result["ablation_id"]
        == "FULL"
    )

    full_f1 = full[
        "metrics"
    ]["f1"]

    full_accuracy = full[
        "metrics"
    ]["accuracy"]

    full_recall = full[
        "metrics"
    ]["recall"]

    full_mitre_f1 = full[
        "mitre_metrics"
    ]["f1"]

    component_impact = {}

    for result in all_results:

        if result[
            "ablation_id"
        ] == "FULL":
            continue

        f1 = result[
            "metrics"
        ]["f1"]

        accuracy = result[
            "metrics"
        ]["accuracy"]

        recall = result[
            "metrics"
        ]["recall"]

        mitre_f1 = result[
            "mitre_metrics"
        ]["f1"]

        component_impact[
            result["ablation_id"]
        ] = {

            "variant": result[
                "name"
            ],

            "full_system_accuracy":
                full_accuracy,

            "ablation_accuracy":
                accuracy,

            "accuracy_drop":
                round(
                    full_accuracy
                    - accuracy,
                    4,
                ),

            "full_system_recall":
                full_recall,

            "ablation_recall":
                recall,

            "recall_drop":
                round(
                    full_recall
                    - recall,
                    4,
                ),

            "full_system_f1":
                full_f1,

            "ablation_f1":
                f1,

            "f1_drop":
                round(
                    full_f1
                    - f1,
                    4,
                ),

            "full_system_mitre_f1":
                full_mitre_f1,

            "ablation_mitre_f1":
                mitre_f1,

            "mitre_f1_drop":
                round(
                    full_mitre_f1
                    - mitre_f1,
                    4,
                ),
        }

    # --------------------------------------------------------
    # Final output
    # --------------------------------------------------------

    final_output = {

        "study":
            "Agentic AI-SOC Ablation Study",

        "purpose":
            (
                "Evaluate the contribution of "
                "individual Agentic AI-SOC components "
                "using an unseen holdout dataset."
            ),

        "dataset": {

            "file":
                str(DATASET_FILE),

            "scenario_count":
                len(scenarios),

            "evaluation_type":
                "Unseen holdout dataset",
        },

        "metrics": {

            "classification":
                [
                    "Accuracy",
                    "Precision",
                    "Recall",
                    "F1",
                    "False Positive Rate",
                ],

            "mitre":
                [
                    "MITRE Precision",
                    "MITRE Recall",
                    "MITRE F1",
                ],

            "latency":
                "Average processing latency per scenario",
        },

        "variants":
            all_results,

        "component_impact":
            component_impact,
    }

    with open(
        RESULTS_FILE,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            final_output,
            f,
            indent=2,
        )

    print()
    print(
        f"Results saved to: "
        f"{RESULTS_FILE}"
    )

    print(
        "ABLATION STUDY COMPLETE"
    )


if __name__ == "__main__":
    main()