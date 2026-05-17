"""
SecurityGateway — the end-to-end final-lab pipeline.

    User Input
      -> Preprocessing & Language Detection   (utils/language.py)
      -> Rule-Based Injection Detector        (detectors/rule_detector.py)
      -> Semantic / ML Injection Detector     (detectors/semantic_detector.py)
      -> Presidio Analyzer & Anonymizer       (pii/presidio_custom.py)
      -> Policy Engine                        (policy/policy_engine.py)
      -> Audit Log                            (utils/logging.py)
      -> Safe Output

Both the FastAPI app (app/main.py) and the evaluation script (run_evaluation.py)
use this single class, so the API and the reported metrics are guaranteed to
come from exactly the same code path.
"""
import time
import uuid

from app.config_loader import CONFIG
from app.detectors.hybrid import HybridDetector
from app.pii.presidio_custom import PresidioCustomAnalyzer
from app.policy.policy_engine import PolicyEngine
from app.utils.language import detect_language, normalize_text
from app.utils.logging import AuditLogger


class SecurityGateway:
    """Pre-model security gateway returning one auditable decision per request."""

    def __init__(self, audit: bool = True):
        # Components are constructed once and reused for every request.
        self.detector = HybridDetector()
        self.pii = PresidioCustomAnalyzer()
        self.policy = PolicyEngine()
        self.audit_logger = AuditLogger(enabled=audit)
        self.config = CONFIG
        self._warmup()

    def _warmup(self):
        """
        Prime lazy-loaded libraries (langdetect profiles, sklearn predict path)
        so the first real request is not penalised by a one-off cold start.
        """
        try:
            detect_language("warmup text for language detection")
            self.detector.analyze("warmup")
            self.pii.analyze("warmup")
        except Exception:
            pass

    def analyze(self, user_input: str, input_id: str = None) -> dict:
        """Run the full pipeline and return the final-lab JSON response."""
        input_id = input_id or f"req_{uuid.uuid4().hex[:8]}"
        t_total = time.perf_counter()

        # ── Stage 1: preprocessing + language detection ─────────────────────
        t0 = time.perf_counter()
        clean = normalize_text(user_input)
        lang = detect_language(clean)
        t_lang = (time.perf_counter() - t0) * 1000

        # ── Stage 2 + 3: hybrid injection detection (rule + semantic) ───────
        t0 = time.perf_counter()
        detection = self.detector.analyze(clean)
        t_detect = (time.perf_counter() - t0) * 1000

        # ── Stage 4: Presidio PII analysis + anonymization ──────────────────
        t0 = time.perf_counter()
        pii = self.pii.analyze(user_input)
        t_pii = (time.perf_counter() - t0) * 1000

        # ── Stage 5: policy decision ────────────────────────────────────────
        t0 = time.perf_counter()
        decision = self.policy.decide(user_input, detection, pii)
        t_policy = (time.perf_counter() - t0) * 1000

        total_ms = round((time.perf_counter() - t_total) * 1000, 2)

        # Compact PII entity view for the response (type / text / score).
        pii_entities = [
            {"type": e["entity_type"],
             "text": e.get("matched_text", ""),
             "score": round(e.get("score", 0.0), 4)}
            for e in pii["entities"] if "matched_text" in e
        ]

        response = {
            "input_id": input_id,
            "language": lang["language"],
            "is_mixed_language": lang["is_mixed"],
            "rule_score": detection["rule_score"],
            "semantic_score": detection["semantic_score"],
            "injection_risk": detection["injection_risk"],
            "pii_entities": pii_entities,
            "final_risk": decision["final_risk"],
            "decision": decision["decision"],
            "safe_text": decision["safe_text"],
            "reason_codes": decision["reason_codes"],
            "reason": decision["reason"],
            "obfuscated": detection["obfuscated"],
            "multilingual": detection["multilingual"],
            "latency_ms": total_ms,
            "latency_breakdown_ms": {
                "language_detection": round(t_lang, 2),
                "injection_detection": round(t_detect, 2),
                "presidio_analysis": round(t_pii, 2),
                "policy_decision": round(t_policy, 2),
                "total": total_ms,
            },
        }

        # ── Stage 6: audit log ──────────────────────────────────────────────
        self.audit_logger.log({
            "input_id": input_id,
            "language": lang["language"],
            "rule_score": detection["rule_score"],
            "semantic_score": detection["semantic_score"],
            "injection_risk": detection["injection_risk"],
            "final_risk": decision["final_risk"],
            "decision": decision["decision"],
            "reason_codes": decision["reason_codes"],
            "pii_types": [e["type"] for e in pii_entities],
            "safe_text": decision["safe_text"],
            "latency_ms": total_ms,
        })
        return response
