"""
FastAPI app for the Robust Multilingual Security Gateway (Final Lab).

Endpoints
---------
  GET  /                 health / info
  POST /analyze          FINAL-LAB pipeline -> auditable AnalyzeResponse
  POST /batch-analyze    run /analyze over a list of prompts
  GET  /config           current thresholds (from config/gateway_config.yaml)
  POST /midterm/analyze  the ORIGINAL midterm pipeline, unchanged, so the
                         previous lab is still demonstrably runnable

The final pipeline lives in app/gateway.py (SecurityGateway). The midterm
endpoint keeps the original modules so nothing from the lab-mid is broken.
"""
import time

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config_loader import CONFIG
from app.gateway import SecurityGateway
from app.models import AnalyzeRequest, AnalyzeResponse, GatewayRequest, GatewayResponse

# Midterm modules — imported only for the backward-compatible endpoint.
from app.injection_detector import InjectionDetector
from app.policy_engine import PolicyEngine as MidtermPolicyEngine
from app.presidio_analyzer import PresidioAnalyzerWrapper

app = FastAPI(
    title="Robust Multilingual LLM Security Gateway",
    description="CSC 262 Lab Final — hybrid injection detection, multilingual "
                "robustness, Presidio PII anonymization, auditable policy.",
    version="2.0.0",
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── Final-lab gateway (built once, reused) ───────────────────────────────────
gateway = SecurityGateway(audit=True)

# ── Midterm pipeline (kept for the backward-compatible endpoint) ─────────────
_mid_detector = InjectionDetector()
_mid_presidio = PresidioAnalyzerWrapper()
_mid_policy = MidtermPolicyEngine()


@app.get("/")
def root():
    return {
        "message": "Robust Multilingual LLM Security Gateway is running",
        "status": "ok",
        "version": "2.0.0",
        "pipeline": ["language_detection", "rule_detector", "semantic_detector",
                     "presidio", "policy_engine", "audit_log"],
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    """Final-lab pipeline: returns one auditable ALLOW / MASK / BLOCK decision."""
    return gateway.analyze(request.user_input, input_id=request.input_id)


@app.post("/batch-analyze")
def batch_analyze(requests_list: list[AnalyzeRequest]):
    """Analyze many prompts at once (useful for quick evaluation)."""
    return [gateway.analyze(r.user_input, input_id=r.input_id)
            for r in requests_list]


@app.get("/config")
def get_config():
    """Return the active gateway configuration / thresholds."""
    return {
        "detection": CONFIG["detection"],
        "risk_formula": CONFIG["risk_formula"],
        "policy": CONFIG["policy"],
        "language": CONFIG["language"],
    }


@app.post("/midterm/analyze", response_model=GatewayResponse)
def midterm_analyze(request: GatewayRequest):
    """
    The ORIGINAL lab-mid pipeline, kept verbatim so the previous lab still
    runs exactly as before:
        Injection Detection -> Presidio -> Policy Decision
    """
    total_start = time.time()

    t1 = time.time()
    injection_result = _mid_detector.analyze(request.user_input)
    inj_ms = round((time.time() - t1) * 1000, 2)

    t2 = time.time()
    pii_result = _mid_presidio.analyze(request.user_input)
    pii_ms = round((time.time() - t2) * 1000, 2)

    t3 = time.time()
    policy_result = _mid_policy.decide(
        user_input=request.user_input,
        injection_result=injection_result,
        pii_result=pii_result,
    )
    pol_ms = round((time.time() - t3) * 1000, 2)

    return GatewayResponse(
        original_input=request.user_input,
        decision=policy_result["decision"],
        processed_output=policy_result["processed_output"],
        injection_score=injection_result["score"],
        injection_risk_level=injection_result["risk_level"],
        injection_flags=injection_result["flags"],
        injection_details=injection_result.get("details", {}),
        pii_entities=pii_result["entities"],
        masked_text=policy_result.get("masked_text"),
        latency_ms={
            "injection_detection": inj_ms,
            "presidio_analysis": pii_ms,
            "policy_decision": pol_ms,
            "total": round((time.time() - total_start) * 1000, 2),
        },
    )


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
