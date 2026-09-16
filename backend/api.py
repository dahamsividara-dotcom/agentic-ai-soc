from fastapi import FastAPI, HTTPException

from backend.soc_orchestrator import SOCOrchestrator


app = FastAPI(
    title="Agentic AI-SOC",
    description="Agentic AI Security Operations Center",
    version="1.1.0"
)


orchestrator = SOCOrchestrator()


@app.get("/")
def root():
    return {
        "system": "Agentic AI-SOC",
        "status": "ONLINE",
        "version": "1.1.0"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy",
        "orchestrator_version": orchestrator.VERSION,
        "decision_agent_version": orchestrator.decision_agent.VERSION,
        "llm_provider": orchestrator.llm.provider,
        "llm_model": orchestrator.llm.model,
        "llm_configured": orchestrator.llm.is_configured()
    }


@app.post("/analyze")
def analyze():

    try:

        result = orchestrator.run(
            "data/sample_security_logs.jsonl"
        )

        return {
            "status": "success",

            "system": result.get(
                "system",
                "Agentic AI-SOC"
            ),

            "orchestrator_version": result.get(
                "orchestrator_version"
            ),

            "events": result["events"],

            "findings": result["findings"],

            "attack_chain": result["attack_chain"],

            "investigation": result["investigation"],

            "risk_assessment": result["risk_assessment"],

            # IMPORTANT:
            # Final Decision Agent output is now
            # exposed to the API and dashboard.
            "decision": result["decision"],

            "ai_reasoning": result["ai_reasoning"],

            "llm_reasoning": result["llm_reasoning"],

            "response": result["response"]
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.api:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    ) 