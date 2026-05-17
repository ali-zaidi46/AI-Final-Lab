"""
Policy engine (Final Lab).

Combines the hybrid injection risk and the Presidio PII signals into ONE
auditable decision: ALLOW, MASK or BLOCK.

Risk formula (configurable in config/gateway_config.yaml)
--------------------------------------------------------
    injection_risk = fuse(rule_score, semantic_score)        # from HybridDetector
    final_risk     = clamp(
                        injection_risk
                        + pii_weight        (if any PII present)
                        + secret_weight     (if a secret/credential present)
                        + composite_weight  (if a composite PII dump present),
                        0, 1)

Justification: injection is the dominant term because a successful injection
compromises the model regardless of PII; PII/secret/composite terms only push a
borderline prompt over the BLOCK line. Each term is a separately tunable knob,
which is exactly what the Threshold Calibration table explores.

Decision precedence
-------------------
    1. injection_risk >= block_threshold        -> BLOCK  (attack)
    2. composite PII dump present               -> BLOCK  (bulk exfiltration)
    3. final_risk >= block_threshold            -> BLOCK  (combined risk)
    4. PII present (>= mask threshold)          -> MASK
    5. otherwise                                -> ALLOW
"""
from app.config_loader import CONFIG

# Human-readable code attached to a triggered rule category.
_FLAG_TO_CODE = {
    "instruction_override": "DIRECT_INJECTION",
    "jailbreak": "JAILBREAK",
    "system_prompt_extraction": "SYSTEM_PROMPT_EXTRACTION",
    "role_play_attack": "ROLEPLAY_BYPASS",
    "context_manipulation": "CONTEXT_MANIPULATION",
    "sensitive_data_request": "SECRET_EXTRACTION",
    "privilege_escalation": "PRIVILEGE_ESCALATION",
}


class PolicyEngine:
    """Configurable, auditable ALLOW / MASK / BLOCK decision engine."""

    def __init__(self, config: dict = None):
        cfg = config or CONFIG
        self.block_threshold = cfg["policy"]["block_threshold"]
        self.mask_pii_score = cfg["policy"]["mask_pii_score"]
        rf = cfg["risk_formula"]
        self.pii_weight = rf["pii_weight"]
        self.secret_weight = rf["secret_weight"]
        self.composite_weight = rf["composite_weight"]
        self.rule_block = cfg["detection"]["rule_block_threshold"]
        self.semantic_block = cfg["detection"]["semantic_block_threshold"]

    # ── risk formula ────────────────────────────────────────────────────────
    def compute_final_risk(self, injection_risk: float, pii_result: dict) -> float:
        """Apply the configurable risk formula and clamp to [0, 1]."""
        risk = injection_risk
        if pii_result.get("has_pii"):
            risk += self.pii_weight
        if pii_result.get("has_secret"):
            risk += self.secret_weight
        if pii_result.get("has_composite"):
            risk += self.composite_weight
        return round(min(1.0, max(0.0, risk)), 4)

    # ── reason codes ────────────────────────────────────────────────────────
    def _reason_codes(self, detection: dict, pii_result: dict) -> list:
        """Build the auditable list of reason codes for this decision."""
        codes = []
        for flag in detection.get("flags", []):
            codes.append(_FLAG_TO_CODE.get(flag, flag.upper()))
        if detection.get("semantic_score", 0) >= self.semantic_block:
            codes.append("SEMANTIC_INJECTION")
        if detection.get("rule_score", 0) >= self.rule_block:
            codes.append("RULE_INJECTION")
        if detection.get("obfuscated"):
            codes.append("OBFUSCATED_ATTACK")
        if detection.get("multilingual"):
            codes.append("MULTILINGUAL_ATTACK")
        if pii_result.get("has_composite"):
            codes.append("COMPOSITE_PII")
        if pii_result.get("has_secret"):
            codes.append("SECRET_DETECTED")
        if pii_result.get("has_pii"):
            codes.append("PII_DETECTED")
        # De-duplicate, keep order.
        seen, ordered = set(), []
        for c in codes:
            if c not in seen:
                seen.add(c)
                ordered.append(c)
        return ordered or ["BENIGN"]

    # ── main entry point ────────────────────────────────────────────────────
    def decide(self, user_input: str, detection: dict, pii_result: dict) -> dict:
        """
        Produce the final decision.

        Returns:
            decision      : "ALLOW" | "MASK" | "BLOCK"
            final_risk    : float 0-1
            reason_codes  : list[str]
            reason        : human-readable explanation
            safe_text     : text safe to forward (None for BLOCK)
        """
        injection_risk = detection.get("injection_risk", 0.0)
        final_risk = self.compute_final_risk(injection_risk, pii_result)
        reason_codes = self._reason_codes(detection, pii_result)
        masked_text = pii_result.get("masked_text", user_input)
        has_pii = pii_result.get("has_pii", False)

        # 1) Injection-driven BLOCK.
        if injection_risk >= self.block_threshold:
            return self._result(
                "BLOCK", final_risk, reason_codes,
                f"Injection risk {injection_risk:.2f} >= block threshold "
                f"{self.block_threshold:.2f}.", None)

        # 2) Composite PII dump -> BLOCK (bulk data exfiltration).
        if pii_result.get("has_composite"):
            return self._result(
                "BLOCK", final_risk, reason_codes,
                "Composite PII dump detected: "
                f"{', '.join(pii_result.get('composite_types', []))}.", None)

        # 3) Combined-risk BLOCK.
        if final_risk >= self.block_threshold:
            return self._result(
                "BLOCK", final_risk, reason_codes,
                f"Final risk {final_risk:.2f} >= block threshold "
                f"{self.block_threshold:.2f}.", None)

        # 4) Benign prompt carrying PII -> MASK.
        if has_pii and pii_result.get("pii_score", 0) >= self.mask_pii_score:
            return self._result(
                "MASK", final_risk, reason_codes,
                f"PII detected (score {pii_result.get('pii_score', 0):.2f}); "
                "sensitive values anonymized.", masked_text)

        # 5) Clean -> ALLOW.
        return self._result(
            "ALLOW", final_risk, reason_codes,
            "No injection or risky PII detected.", user_input)

    @staticmethod
    def _result(decision, final_risk, reason_codes, reason, safe_text):
        return {
            "decision": decision,
            "final_risk": final_risk,
            "reason_codes": reason_codes,
            "reason": reason,
            "safe_text": safe_text,
        }

    def get_thresholds(self) -> dict:
        return {
            "block_threshold": self.block_threshold,
            "mask_pii_score": self.mask_pii_score,
            "pii_weight": self.pii_weight,
            "secret_weight": self.secret_weight,
            "composite_weight": self.composite_weight,
        }
