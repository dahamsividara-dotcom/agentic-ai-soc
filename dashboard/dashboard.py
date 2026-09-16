import streamlit as st
import requests

st.set_page_config(
    page_title="Agentic AI-SOC",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000"


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


st.title("🛡️ Agentic AI-SOC")
st.caption("Agentic AI Security Operations Center — Threat Hunting & Incident Response")

st.divider()

if st.button("🔍 Analyze Security Logs", type="primary"):
    with st.spinner("Running detection agents and AI reasoning..."):
        data = run_analysis()

    if data:
        st.session_state["soc_data"] = data
        st.success("Analysis completed successfully.")

data = st.session_state.get("soc_data")

if not data:
    st.info("Click **Analyze Security Logs** to start the SOC investigation.")
    st.stop()

attack_chain = data.get("attack_chain", {})
investigation = data.get("investigation", {})
ai_reasoning = data.get("ai_reasoning", {})
llm_reasoning = data.get("llm_reasoning", {})
response_data = data.get("response", {})
risk_assessment = data.get("risk_assessment", {})

risk_score = risk_assessment.get("risk_score", 0)
threat_level = risk_assessment.get("risk_level", "UNKNOWN")

finding_count = data.get("findings", 0)
if isinstance(finding_count, list):
    finding_count = len(finding_count)

stage_count = attack_chain.get("stage_count", 0)

st.subheader("🚨 Incident Overview")

c1, c2, c3, c4 = st.columns(4)


st.subheader("📊 Evidence-Weighted Risk Assessment")

risk_score_v2 = risk_assessment.get("risk_score", 0)

risk_level_v2 = risk_assessment.get("risk_level", "UNKNOWN")

risk_confidence = risk_assessment.get("confidence", 0.0)

rc1, rc2, rc3 = st.columns(3)

rc1.metric("Dynamic Risk", f"{risk_score_v2}/100")
rc2.metric("Risk Level", risk_level_v2)
rc3.metric("Risk Confidence", f"{risk_confidence:.2f}")

components = risk_assessment.get("components", {})

if components:
    st.markdown("**Risk Score Breakdown**")
    st.write(f"• Evidence Score: {components.get("evidence_score", 0)}")
    st.write(f"• Temporal Correlation: {components.get("temporal_score", 0)}")
    st.write(f"• Entity Correlation: {components.get("entity_score", 0)}")
    st.write(f"• MITRE Coverage: {components.get("mitre_score", 0)}")
    st.write(f"• CTI Score: {components.get("cti_score", 0)}")
    st.write(f"• Uncertainty Penalty: -{components.get("uncertainty_penalty", 0)}")

st.caption(risk_assessment.get("method", "Evidence-Weighted Dynamic Risk Scoring"))

st.divider()
c1.metric("Risk Score", f"{risk_score}/100")
c2.metric("Threat Level", threat_level)
c3.metric("Findings", finding_count)
c4.metric("Attack Stages", stage_count)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("🔗 Attack Chain")

    stages = attack_chain.get("stages", [])

    for i, stage in enumerate(stages, 1):
        stage_name = stage.get("stage", "Unknown")
        rule_id = stage.get("rule_id", "N/A")
        host = stage.get("host", "Unknown")
        user = stage.get("username", "Unknown")

        st.markdown(
            f"""
**{i}. {stage_name}**

`{rule_id}` · Host: `{host}` · User: `{user}`
"""
        )

        if i < len(stages):
            st.markdown("⬇️")

with right:
    st.subheader("🧠 AI Security Assessment")

    assessment = llm_reasoning.get(
        "assessment",
        "No LLM assessment available."
    )

    st.write(assessment)

    st.markdown(
        f"**LLM:** `{llm_reasoning.get('model', 'N/A')}`"
    )

    st.markdown(
        f"**Status:** `{llm_reasoning.get('status', 'N/A')}`"
    )

st.divider()

c1, c2 = st.columns(2)

with c1:
    st.subheader("🎯 MITRE ATT&CK")

    techniques = set()

    for stage in stages:
        mitre = stage.get("mitre_attack", {})

        if isinstance(mitre, dict):
            technique_id = mitre.get("technique_id")
            technique_name = mitre.get("technique_name")

            if technique_id:
                techniques.add(
                    f"{technique_id}: {technique_name}"
                )

    if techniques:
        for technique in sorted(techniques):
            st.write(f"• {technique}")
    else:
        st.write("No MITRE techniques identified.")

with c2:
    st.subheader("🧬 Threat Intelligence")

    cti_matches = investigation.get("cti_context", [])

    if isinstance(cti_matches, list) and cti_matches:
        for match in cti_matches:
            if isinstance(match, dict):
                title = match.get("title", "CTI Match")
                mitre_id = match.get("mitre_id", "N/A")

                st.write(
                    f"• **{title}** — `{mitre_id}`"
                )
    else:
        st.write("No CTI matches.")

st.divider()

st.subheader("🛡️ Incident Response")

response_status = response_data.get(
    "response_status",
    "UNKNOWN"
)

st.warning(
    f"Response Status: **{response_status}**"
)

actions = response_data.get("actions", [])

if actions:
    for action in actions:
        if isinstance(action, dict):
            action_id = action.get("action_id", "N/A")
            action_type = action.get("action", "Unknown")
            description = action.get(
                "reason",
                action.get("description", "")
            )

            st.markdown(
                f"**{action_id} — {action_type}**"
            )

            st.write(description)

st.divider()

st.subheader("⚠️ Evidence & Uncertainty")

uncertainty = attack_chain.get(
    "uncertainty",
    {}
)

if isinstance(uncertainty, dict):
    st.write(
        f"**Level:** {uncertainty.get('level', 'UNKNOWN')}"
    )

    reasons = uncertainty.get("reasons", [])

    for reason in reasons:
        st.write(f"• {reason}")

grounding = llm_reasoning.get(
    "evidence_grounding",
    {}
)

if grounding:
    st.write(
        f"**LLM Evidence Grounding:** "
        f"`{grounding.get('guard_status', 'UNKNOWN')}`"
    )

st.divider()

st.caption(
    "Agentic AI-SOC | Evidence-grounded AI-assisted security operations"
)
