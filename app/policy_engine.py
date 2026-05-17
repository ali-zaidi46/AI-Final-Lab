class PolicyEngine:
    def __init__(
        self,
        block_injection_score: float = 0.75,   # block if injection score >= this
        mask_pii_score: float = 0.60,           # mask PII if confidence >= this
        block_composite_pii: bool = True,       # block on composite PII dumps
    ):
        self.block_injection_score = block_injection_score
        self.mask_pii_score = mask_pii_score
        self.block_composite_pii = block_composite_pii
 
    def decide(
        self,
        user_input: str,
        injection_result: dict,
        pii_result: dict,
    ) -> dict:
        """
        Evaluate all signals and return:
        {
            decision:        "ALLOW" | "MASK" | "BLOCK"
            reason:          human-readable explanation
            processed_output: safe text to forward (or rejection message)
            masked_text:     text with PII replaced (if MASK)
        }
        """
        injection_score = injection_result.get("score", 0.0)
        injection_flags = injection_result.get("flags", [])
        entities = pii_result.get("entities", [])
        masked_text = pii_result.get("masked_text", user_input)
 
        # ── Rule 1: BLOCK on high injection score ─────────────────────────────
        if injection_score >= self.block_injection_score:
            return {
                "decision": "BLOCK",
                "reason": (
                    f"Injection/jailbreak attempt detected. "
                    f"Score: {injection_score:.2f}. "
                    f"Flags: {', '.join(injection_flags)}"
                ),
                "processed_output": (
                    "⛔ Request blocked: Your input was flagged as a potential "
                    "prompt injection or jailbreak attempt and cannot be processed."
                ),
                "masked_text": None,
            }
 
        # ── Rule 2: BLOCK on composite PII dump ───────────────────────────────
        if self.block_composite_pii:
            composite_types = {"COMPOSITE_PII_DUMP", "CREDENTIAL_LEAK", "FINANCIAL_PII"}
            composite_found = [e for e in entities if e["entity_type"] in composite_types]
            if composite_found:
                return {
                    "decision": "BLOCK",
                    "reason": (
                        f"Composite PII detected: "
                        f"{composite_found[0]['entity_type']}. "
                        "Multiple sensitive data types in a single message."
                    ),
                    "processed_output": (
                        "⛔ Request blocked: Your message contains multiple types of "
                        "sensitive personal/credential information."
                    ),
                    "masked_text": None,
                }
 
        # ── Rule 3: MASK on single PII entities above threshold ───────────────
        high_conf_entities = [
            e for e in entities
            if e.get("score", 0) >= self.mask_pii_score
            and e["entity_type"] not in {"COMPOSITE_PII_DUMP", "CREDENTIAL_LEAK", "FINANCIAL_PII"}
        ]
        if high_conf_entities:
            entity_types = list({e["entity_type"] for e in high_conf_entities})
            return {
                "decision": "MASK",
                "reason": (
                    f"PII detected and masked: {', '.join(entity_types)}. "
                    f"{len(high_conf_entities)} entity(ies) anonymized."
                ),
                "processed_output": masked_text,
                "masked_text": masked_text,
            }
 
        # ── Rule 4: Medium injection score — allow with warning ───────────────
        if injection_score >= 0.40:
            return {
                "decision": "ALLOW",
                "reason": (
                    f"Low-medium injection score ({injection_score:.2f}). "
                    "Proceeding with caution."
                ),
                "processed_output": user_input,
                "masked_text": None,
            }
 
        # ── Rule 5: Clean input — ALLOW ───────────────────────────────────────
        return {
            "decision": "ALLOW",
            "reason": "No threats or PII detected. Input is safe.",
            "processed_output": user_input,
            "masked_text": None,
        }
 
    def get_thresholds(self) -> dict:
        return {
            "block_injection_score": self.block_injection_score,
            "mask_pii_score": self.mask_pii_score,
            "block_composite_pii": self.block_composite_pii,
        }
 