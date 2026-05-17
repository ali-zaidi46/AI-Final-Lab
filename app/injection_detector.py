import re
from typing import Optional
 
 
# ── Attack Pattern Library 
INJECTION_PATTERNS = {
    "instruction_override": {
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
            r"disregard\s+(all\s+)?(previous|prior)\s+instructions?",
            r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed)",
            r"override\s+(your\s+)?(system\s+)?(prompt|instructions?)",
        ],
        "weight": 0.9,
    },
    "jailbreak": {
        "patterns": [
            r"\bdan\b",                        # Do Anything Now
            r"jailbreak",
            r"do\s+anything\s+now",
            r"you\s+are\s+now\s+(a\s+)?(free|unrestricted|unfiltered)",
            r"pretend\s+(you\s+have\s+no\s+restrictions|you\s+are\s+evil)",
            r"act\s+as\s+if\s+you\s+have\s+no\s+(rules|restrictions|guidelines)",
            r"evil\s+(mode|version|bot)",
        ],
        "weight": 0.95,
    },
    "system_prompt_extraction": {
        "patterns": [
            r"(reveal|show|print|output|display|repeat)\s+(your\s+)?(system\s+prompt|instructions?|rules|guidelines)",
            r"what\s+(are\s+your|is\s+your)\s+(system\s+prompt|instructions?|initial\s+instructions?)",
            r"tell\s+me\s+(your|the)\s+system\s+prompt",
            r"ignore\s+(the\s+)?(above|previous).{0,30}instead",
        ],
        "weight": 0.8,
    },
    "role_play_attack": {
        "patterns": [
            r"you\s+are\s+now\s+called?\s+\w+\s+and\s+(you\s+)?(have\s+no|don.t\s+have)",
            r"roleplay\s+as\s+(a\s+)?(hacker|criminal|terrorist|evil)",
            r"simulate\s+(being\s+)?(a\s+)?(hacker|malware|virus)",
            r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(hacker|evil|uncensored|ai\s+with\s+no)",
            r"pretend\s+you\s+are\s+an\s+(evil|uncensored|unrestricted)",
            r"act\s+as\s+(a\s+)?(hacker|evil|uncensored|malicious)",
            r"help\s+me\s+hack",
        ],
        "weight": 0.85,
    },
    "context_manipulation": {
        "patterns": [
            r"--------+",           # common injection separator
            r"===========+",
            r"\[system\]",
            r"\[user\]",
            r"\[assistant\]",
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"<<<.*>>>",
        ],
        "weight": 0.6,
    },
    "sensitive_data_request": {
        "patterns": [
            r"(give|send|leak|expose|share|tell|show)\s+(me\s+)?(all\s+)?(the\s+)?(passwords?|secrets?|keys?|tokens?|credentials?)",
            r"what\s+is\s+(the\s+)?(password|api[\s_-]?key|secret)",
            r"share\s+(all\s+)?(the\s+)?(passwords?|secrets?|data|information|credentials?)",
        ],
        "weight": 0.75,
    },
    "privilege_escalation": {
        "patterns": [
            r"make\s+me\s+(an?\s+)?(admin|administrator|root|superuser|owner)",
            r"(grant|give)\s+(me\s+)?(admin|root|full|elevated)\s+(access|privileges?|permissions?|rights?)",
            r"(escalate|elevate)\s+(my\s+)?(privileges?|permissions?|access)",
            r"you\s+have\s+(absolute|full|total|unlimited)\s+(authority|power|control|access)",
            r"(bypass|disable|remove|turn\s+off)\s+(all\s+)?(security|authentication|authorization|restrictions?)",
        ],
        "weight": 0.85,
    },
}
 
 
class InjectionDetector:
    def __init__(
        self,
        block_threshold: float = 0.75,
        warn_threshold: float = 0.40,
    ):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        self._compile_patterns()
 
    def _compile_patterns(self):
        """Pre-compile all regex patterns for speed."""
        self._compiled = {}
        for category, data in INJECTION_PATTERNS.items():
            self._compiled[category] = {
                "patterns": [re.compile(p, re.IGNORECASE | re.DOTALL) for p in data["patterns"]],
                "weight": data["weight"],
            }
 
    def analyze(self, text: str) -> dict:
        """
        Score the input text for injection/jailbreak threats.
 
        Returns:
            score   : float 0-1  (higher = more dangerous)
            flags   : list of triggered categories
            details : per-category breakdown
        """
        flags = []
        details = {}
        max_score = 0.0
 
        for category, data in self._compiled.items():
            matched = []
            for pattern in data["patterns"]:
                match = pattern.search(text)
                if match:
                    matched.append(match.group(0))
 
            if matched:
                flags.append(category)
                score = data["weight"]
                details[category] = {
                    "matched_snippets": matched[:3],   # keep first 3 matches
                    "score": score,
                }
                if score > max_score:
                    max_score = score
 
        # Bonus: length heuristic — very long inputs with many separators = suspicious
        if len(text) > 1500:
            max_score = min(1.0, max_score + 0.05)
 
        # Bonus: multiple categories triggered
        if len(flags) >= 2:
            max_score = min(1.0, max_score + 0.05)
 
        return {
            "score": round(max_score, 4),
            "flags": flags,
            "details": details,
            "risk_level": self._risk_label(max_score),
        }
 
    def _risk_label(self, score: float) -> str:
        if score >= self.block_threshold:
            return "HIGH"
        elif score >= self.warn_threshold:
            return "MEDIUM"
        else:
            return "LOW"
 
    def get_thresholds(self) -> dict:
        return {
            "block_threshold": self.block_threshold,
            "warn_threshold": self.warn_threshold,
        }
 