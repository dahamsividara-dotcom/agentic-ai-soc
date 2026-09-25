from detection.log_ingestor import LogIngestor
from detection.detection_engine import DetectionEngine

from attack_graph.attack_chain_engine import AttackChainEngine

from agents.investigation_agent import InvestigationAgent
from agents.risk_assessment_agent import RiskAssessmentAgent
from agents.decision_agent import DecisionAgent
from agents.ai_reasoning_agent import AIReasoningAgent
from agents.llm_reasoning_engine import LLMReasoningEngine

from response.response_agent import ResponseAgent


class SOCOrchestrator:
    """
    Agentic AI-SOC Orchestrator

    Coordinates the complete SOC investigation pipeline:

    Security Logs
        ↓
    Log Ingestion
        ↓
    Detection
        ↓
    Attack-Chain Construction
        ↓
    Investigation + CTI
        ↓
    Dynamic Risk Assessment
        ↓
    Security Decision
        ↓
    Evidence-Grounded AI Reasoning
        ↓
    Local LLM Reasoning
        ↓
    Incident Response Recommendation

    Dynamic Risk Assessment is the authoritative
    quantitative risk source for downstream agents.

    Automatic destructive actions are disabled.
    Human approval is required for response actions.
    """

    VERSION = "1.3"

    def __init__(self):

        self.ingestor = LogIngestor()

        self.detector = DetectionEngine()

        self.chain_engine = AttackChainEngine()

        self.investigator = InvestigationAgent()

        self.risk_assessor = RiskAssessmentAgent()

        self.decision_agent = DecisionAgent()

        self.ai_reasoner = AIReasoningAgent()

        self.llm = LLMReasoningEngine()

        self.response_agent = ResponseAgent()

    def run(self, log_file):
        """
        Execute the complete Agentic AI-SOC pipeline.
        """

        # =========================================================
        # 1. LOG INGESTION
        # =========================================================

        events = self.ingestor.ingest(
            log_file
        )

        # =========================================================
        # 2. DETECTION ENGINE
        # =========================================================

        findings = self.detector.analyze(
            events
        )

        # =========================================================
        # 3. ATTACK-CHAIN REASONING
        # =========================================================

        attack_chain = self.chain_engine.build_chain(
            findings
        )

        # =========================================================
        # 4. INVESTIGATION + THREAT INTELLIGENCE
        # =========================================================

        investigation = self.investigator.investigate(
            attack_chain
        )

        # =========================================================
        # 5. DYNAMIC RISK ASSESSMENT
        # =========================================================

        risk_assessment = self.risk_assessor.assess(
            findings=findings,
            attack_chain=attack_chain,
            investigation=investigation,
        )

        # =========================================================
        # 6. SECURITY DECISION
        # =========================================================

        decision = self.decision_agent.decide(
            findings=findings,
            risk_assessment=risk_assessment,
            attack_chain=attack_chain,
            investigation=investigation,
        )

        # =========================================================
        # 7. EVIDENCE-GROUNDED AI REASONING
        #
        # IMPORTANT:
        # Dynamic risk assessment is passed explicitly so that
        # AI Reasoning uses the same authoritative risk result.
        # =========================================================

        reasoning = self.ai_reasoner.reason(
            attack_chain=attack_chain,
            investigation=investigation,
            risk_assessment=risk_assessment,
        )

        # =========================================================
        # 8. LOCAL LLM REASONING
        # =========================================================

        llm_result = self.llm.generate(
            attack_chain=attack_chain,
            investigation=investigation,
            risk_assessment=risk_assessment,
        )

        # =========================================================
        # 9. INCIDENT RESPONSE RECOMMENDATION
        # =========================================================

        response = self.response_agent.recommend(
            events=events,
            findings=findings,
            attack_chain=attack_chain,
            investigation=investigation,
            risk_assessment=risk_assessment,
            decision=decision,
            reasoning=reasoning,
        )

        # =========================================================
        # 10. FINAL SOC RESULT
        # =========================================================

        return {
            "system": "Agentic AI-SOC",

            "orchestrator_version": self.VERSION,

            "events": events,

            "findings": findings,

            "attack_chain": attack_chain,

            "investigation": investigation,

            "risk_assessment": risk_assessment,

            "decision": decision,

            "ai_reasoning": reasoning,

            "llm_reasoning": llm_result,

            "response": response,
        }


if __name__ == "__main__":

    print(
        "Agentic AI-SOC Orchestrator"
    )

    print(
        f"Version: {SOCOrchestrator.VERSION}"
    )

    print(
        "Status: READY"
    ) 