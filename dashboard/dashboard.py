import re
import streamlit as st
import requests


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Agentic AI-SOC",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# BACKEND CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8001"


# ============================================================
# API FUNCTION
# ============================================================

def run_analysis():
    try:
        response = requests.post(
            f"{API_URL}/analyze",
            timeout=600
        )

        response.raise_for_status()

        return response.json()

    except Exception as e:
        st.error(f"Backend connection failed: {e}")
        return None


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Agentic AI-SOC")

st.caption(
    "Agentic AI Security Operations Center — "
    "Threat Hunting & Incident Response"
)

st.divider()


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Security Logs",
    type="primary"
):

    with st.spinner(
        "Running detection agents and AI reasoning..."
    ):

        data = run_analysis()

    if data:

        st.session_state["soc_data"] = data

        st.success(
            "Analysis completed successfully."
        )


# ============================================================
# LOAD SESSION DATA
# ============================================================

data = st.session_state.get("soc_data")


if not data:

    st.info(
        "Click **Analyze Security Logs** "
        "to start the SOC investigation."
    )

    st.stop()


# ============================================================
# EXTRACT DATA
# ============================================================

attack_chain = data.get(
    "attack_chain",
    {}
)

investigation = data.get(
    "investigation",
    {}
)

ai_reasoning = data.get(
    "ai_reasoning",
    {}
)

llm_reasoning = data.get(
    "llm_reasoning",
    {}
)

response_data = data.get(
    "response",
    {}
)

risk_assessment = data.get(
    "risk_assessment",
    {}
)

decision_data = data.get(
    "decision",
    {}
)

findings = data.get(
    "findings",
    []
)


# ============================================================
# AUTHORITATIVE RISK
# ============================================================

risk_score = risk_assessment.get(
    "risk_score",
    0
)

threat_level = risk_assessment.get(
    "risk_level",
    "UNKNOWN"
)

risk_confidence = risk_assessment.get(
    "confidence",
    0.0
)


# ============================================================
# FINDINGS / STAGES
# ============================================================

finding_count = len(findings) if isinstance(
    findings,
    list
) else 0

stage_count = attack_chain.get(
    "stage_count",
    0
)


# ============================================================
# INCIDENT OVERVIEW
# ============================================================

st.subheader("🚨 Incident Overview")


c1, c2, c3, c4 = st.columns(4)


c1.metric(
    "Risk Score",
    f"{risk_score}/100"
)

c2.metric(
    "Threat Level",
    threat_level
)

c3.metric(
    "Findings",
    finding_count
)

c4.metric(
    "Attack Stages",
    stage_count
)


# ============================================================
# FINAL SECURITY DECISION
# ============================================================

st.divider()

st.subheader("🎯 Security Decision")


decision = decision_data.get(
    "decision",
    "UNKNOWN"
)

decision_confidence = decision_data.get(
    "confidence",
    0.0
)

dc1, dc2, dc3, dc4 = st.columns(4)


dc1.metric(
    "Final Decision",
    decision
)

dc2.metric(
    "Risk",
    f"{risk_score}/100"
)

dc3.metric(
    "Risk Level",
    threat_level
)

dc4.metric(
    "Decision Confidence",
    f"{decision_confidence:.2f}"
)


if decision == "MALICIOUS":

    st.error(
        "🚨 Security Decision: MALICIOUS — "
        "Human analyst validation is required before response actions."
    )

elif decision == "SUSPICIOUS":

    st.warning(
        "⚠️ Security Decision: SUSPICIOUS — "
        "Further investigation is recommended."
    )

else:

    st.success(
        "✅ Security Decision: BENIGN"
    )


# ============================================================
# RISK ASSESSMENT
# ============================================================

st.divider()

st.subheader(
    "📊 Evidence-Weighted Risk Assessment"
)


rc1, rc2, rc3 = st.columns(3)


rc1.metric(
    "Dynamic Risk",
    f"{risk_score}/100"
)

rc2.metric(
    "Risk Level",
    threat_level
)

rc3.metric(
    "Risk Confidence",
    f"{risk_confidence:.2f}"
)


components = risk_assessment.get(
    "components",
    {}
)


if components:

    st.markdown(
        "**Risk Score Breakdown**"
    )

    st.write(
        f"• Evidence Score: "
        f"{components.get('evidence_score', 0)}"
    )

    st.write(
        f"• Temporal Correlation: "
        f"{components.get('temporal_score', 0)}"
    )

    st.write(
        f"• Entity Correlation: "
        f"{components.get('entity_score', 0)}"
    )

    st.write(
        f"• MITRE Coverage: "
        f"{components.get('mitre_score', 0)}"
    )

    st.write(
        f"• CTI Score: "
        f"{components.get('cti_score', 0)}"
    )

    st.write(
        f"• Context Modifier: "
        f"{components.get('context_modifier', 0)}"
    )

    st.write(
        f"• Uncertainty Penalty: "
        f"-{components.get('uncertainty_penalty', 0)}"
    )


st.caption(
    risk_assessment.get(
        "method",
        "Evidence-Weighted Dynamic Risk Scoring"
    )
)


# ============================================================
# ATTACK CHAIN + AI ASSESSMENT
# ============================================================

st.divider()

left, right = st.columns(2)


# ============================================================
# ATTACK CHAIN
# ============================================================

with left:

    st.subheader(
        "🔗 Attack Chain"
    )

    stages = attack_chain.get(
        "stages",
        []
    )

    for i, stage in enumerate(
        stages,
        1
    ):

        stage_name = stage.get(
            "stage",
            "Unknown"
        )

        rule_id = stage.get(
            "rule_id",
            "N/A"
        )

        host = stage.get(
            "host",
            "Unknown"
        )

        user = stage.get(
            "username",
            "Unknown"
        )

        classification = stage.get(
            "classification",
            "UNKNOWN"
        )

        st.markdown(
            f"""
**{i}. {stage_name}**

`{rule_id}` · Host: `{host}` · User: `{user}`

Classification: `{classification}`
"""
        )

        if i < len(stages):

            st.markdown(
                "⬇️"
            )


# ============================================================
# AI SECURITY ASSESSMENT
# ============================================================

with right:

    st.subheader(
        "🧠 AI Security Assessment"
    )

    # --------------------------------------------------------
    # Authoritative AI Reasoning Result
    # --------------------------------------------------------

    ai_risk = ai_reasoning.get(
        "risk_score",
        risk_score
    )

    ai_level = ai_reasoning.get(
        "risk_level",
        threat_level
    )

    ai_confidence = ai_reasoning.get(
        "confidence",
        0.0
    )

    st.markdown(
        "**Authoritative AI Risk Assessment**"
    )

    ac1, ac2, ac3 = st.columns(3)

    ac1.metric(
        "Risk Score",
        f"{ai_risk}/100"
    )

    ac2.metric(
        "Risk Level",
        ai_level
    )

    ac3.metric(
        "Confidence",
        f"{ai_confidence:.2f}"
    )


    st.divider()


    # --------------------------------------------------------
    # LLM Assessment
    # --------------------------------------------------------

    st.markdown(
        "**LLM Evidence-Grounded Assessment**"
    )

    assessment = llm_reasoning.get(
        "assessment",
        "No LLM assessment available."
    )


    # --------------------------------------------------------
    # Normalize obvious risk-label mismatch in UI
    # --------------------------------------------------------

    authoritative_label = str(
        threat_level
    ).upper()

    authoritative_score = str(
        risk_score
    )


    # Example:
    # "incident is CRITICAL with a risk score of 68
    # and risk level of HIGH"
    #
    # Replace only the contradictory label using
    # the authoritative Dynamic Risk Assessment.

    mismatch_pattern = re.compile(
        r"(incident\s+is\s+)"
        r"(LOW|MEDIUM|HIGH|CRITICAL)"
        r"(\s+with\s+a\s+risk\s+score\s+of\s+)"
        r"(\d+)"
        r"(\s+and\s+risk\s+level\s+of\s+)"
        r"(LOW|MEDIUM|HIGH|CRITICAL)",
        re.IGNORECASE
    )


    def normalize_risk_text(match):

        score_from_llm = match.group(4)

        if score_from_llm == authoritative_score:

            return (
                f"{match.group(1)}"
                f"{authoritative_label}"
                f"{match.group(3)}"
                f"{authoritative_score}"
                f"{match.group(5)}"
                f"{authoritative_label}"
            )

        return match.group(0)


    assessment = mismatch_pattern.sub(
        normalize_risk_text,
        assessment
    )


    st.write(
        assessment
    )


    st.markdown(
        f"**LLM:** "
        f"`{llm_reasoning.get('model', 'N/A')}`"
    )

    st.markdown(
        f"**Status:** "
        f"`{llm_reasoning.get('status', 'N/A')}`"
    )


# ============================================================
# MITRE ATT&CK + CTI
# ============================================================

st.divider()

c1, c2 = st.columns(2)


# ============================================================
# MITRE ATT&CK
# ============================================================

with c1:

    st.subheader(
        "🎯 MITRE ATT&CK"
    )

    techniques = set()


    for stage in stages:

        mitre = stage.get(
            "mitre_attack"
        )


        if isinstance(
            mitre,
            dict
        ):

            technique_id = mitre.get(
                "technique_id"
            )

            # Backend uses "technique"
            # NOT "technique_name"

            technique_name = mitre.get(
                "technique"
            )


            if technique_id:

                if technique_name:

                    techniques.add(
                        f"{technique_id}: "
                        f"{technique_name}"
                    )

                else:

                    techniques.add(
                        f"{technique_id}"
                    )


    if techniques:

        for technique in sorted(
            techniques
        ):

            st.write(
                f"• {technique}"
            )

    else:

        st.write(
            "No MITRE techniques identified."
        )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

with c2:

    st.subheader(
        "🧬 Threat Intelligence"
    )


    cti_matches = investigation.get(
        "cti_context",
        []
    )


    if (
        isinstance(
            cti_matches,
            list
        )
        and cti_matches
    ):

        for match in cti_matches:

            if isinstance(
                match,
                dict
            ):

                title = match.get(
                    "title",
                    "CTI Match"
                )

                mitre_id = match.get(
                    "mitre_id",
                    "N/A"
                )

                st.write(
                    f"• **{title}** — "
                    f"`{mitre_id}`"
                )

    else:

        st.write(
            "No CTI matches."
        )


# ============================================================
# INCIDENT RESPONSE
# ============================================================

st.divider()

st.subheader(
    "🛡️ Incident Response"
)


response_status = response_data.get(
    "response_status",
    "UNKNOWN"
)

response_risk = response_data.get(
    "risk_score",
    risk_score
)

response_level = response_data.get(
    "risk_level",
    threat_level
)

final_decision = response_data.get(
    "final_decision",
    decision
)


st.warning(
    f"Response Status: **{response_status}**"
)


st.write(
    f"Final Decision: **{final_decision}**"
)

st.write(
    f"Risk: **{response_risk}/100 — "
    f"{response_level}**"
)


actions = response_data.get(
    "actions",
    []
)


if actions:

    for action in actions:

        if isinstance(
            action,
            dict
        ):

            action_id = action.get(
                "action_id",
                "N/A"
            )

            action_type = action.get(
                "action",
                "Unknown"
            )

            description = action.get(
                "reason",
                action.get(
                    "description",
                    ""
                )
            )


            st.markdown(
                f"**{action_id} — "
                f"{action_type}**"
            )

            st.write(
                description
            )


# ============================================================
# EVIDENCE & UNCERTAINTY
# ============================================================

st.divider()

st.subheader(
    "⚠️ Evidence & Uncertainty"
)


uncertainty = attack_chain.get(
    "uncertainty",
    {}
)


if isinstance(
    uncertainty,
    dict
):

    st.write(
        f"**Level:** "
        f"{uncertainty.get('level', 'UNKNOWN')}"
    )


    reasons = uncertainty.get(
        "reasons",
        []
    )


    for reason in reasons:

        st.write(
            f"• {reason}"
        )


# ============================================================
# LLM GROUNDING
# ============================================================

grounding = llm_reasoning.get(
    "evidence_grounding",
    {}
)


if grounding:

    guard_status = grounding.get(
        "guard_status",
        "UNKNOWN"
    )

    grounded = grounding.get(
        "grounded",
        False
    )


    if guard_status == "PASSED":

        st.success(
            f"LLM Evidence Grounding: "
            f"**{guard_status}**"
        )

    else:

        st.warning(
            f"LLM Evidence Grounding: "
            f"**{guard_status}**"
        )


    if grounding.get(
        "warnings"
    ):

        st.markdown(
            "**Grounding Warnings**"
        )

        for warning in grounding.get(
            "warnings",
            []
        ):

            st.write(
                f"• {warning}"
            )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Agentic AI-SOC | "
    "Evidence-grounded AI-assisted security operations"
) 