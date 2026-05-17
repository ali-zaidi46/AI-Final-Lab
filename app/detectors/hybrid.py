"""
Hybrid injection detector (Final Lab).

Combines the two layers required by the final lab:

    RuleDetector      -> fast regex / keyword / obfuscation / multilingual
    SemanticDetector  -> TF-IDF + Logistic Regression for paraphrase robustness

Fusion is configurable via config/gateway_config.yaml:
    fusion_mode = "max"      -> injection_risk = max(rule, semantic)
    fusion_mode = "weighted" -> injection_risk = rule*w_r + semantic*w_s

`injection_risk` produced here is the value the policy engine's risk formula
consumes. Keeping both raw scores lets the report compare rule-only vs hybrid.
"""
from app.config_loader import CONFIG
from app.detectors.rule_detector import RuleDetector
from app.detectors.semantic_detector import SemanticDetector, get_or_train


class HybridDetector:
    """Rule + semantic fusion with configurable combination strategy."""

    def __init__(self, rule_detector: RuleDetector = None,
                 semantic_detector: SemanticDetector = None):
        cfg = CONFIG["detection"]
        self.rule = rule_detector or RuleDetector(
            block_threshold=cfg["rule_block_threshold"],
            warn_threshold=cfg["rule_warn_threshold"],
        )
        # Semantic detector is loaded/trained once and reused.
        self.semantic = semantic_detector or get_or_train()
        self.fusion_mode = cfg["fusion_mode"]
        self.rule_weight = cfg["rule_weight"]
        self.semantic_weight = cfg["semantic_weight"]

    def _fuse(self, rule_score: float, semantic_score: float) -> float:
        """Combine the two scores into a single injection risk in [0, 1]."""
        if self.fusion_mode == "weighted":
            fused = rule_score * self.rule_weight + \
                    semantic_score * self.semantic_weight
        else:  # "max" — default, favours recall
            fused = max(rule_score, semantic_score)
        return round(min(1.0, max(0.0, fused)), 4)

    def analyze(self, text: str) -> dict:
        """
        Run both detectors and return a merged result.

        Keys:
            rule_score / semantic_score : raw per-detector scores
            injection_risk              : fused score (-> risk formula)
            flags                       : triggered rule categories
            obfuscated / multilingual   : audit booleans from the rule layer
        """
        rule_result = self.rule.analyze(text)
        semantic_result = self.semantic.analyze(text)

        rule_score = rule_result["score"]
        semantic_score = semantic_result["score"]
        injection_risk = self._fuse(rule_score, semantic_score)

        return {
            "rule_score": rule_score,
            "semantic_score": semantic_score,
            "injection_risk": injection_risk,
            "fusion_mode": self.fusion_mode,
            "flags": rule_result["flags"],
            "details": rule_result["details"],
            "risk_level": ("HIGH" if injection_risk >= 0.75
                           else "MEDIUM" if injection_risk >= 0.40
                           else "LOW"),
            "obfuscated": rule_result["obfuscated"],
            "multilingual": rule_result["multilingual"],
            "deobfuscated_text": rule_result["deobfuscated_text"],
            "semantic_trained": semantic_result["trained"],
        }
