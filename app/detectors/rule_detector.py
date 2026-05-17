"""
Rule-based injection detector (Final Lab).

This is the FAST first-pass layer of the hybrid detector. It extends the
midterm regex detector (app/injection_detector.py — kept untouched) with two
gap fixes required by the final lab:

  * Obfuscation handling  -> leetspeak / inserted-punctuation is de-obfuscated
                             and the regex layer is re-run on the clean copy.
  * Multilingual keywords -> Urdu and Korean attack phrases, since the midterm
                             English-only keyword rules miss multilingual
                             attacks.

The original midterm detector is REUSED verbatim, so any prompt the midterm
caught is still caught — this class only adds detections, never removes them.
"""
import re

from app.injection_detector import InjectionDetector
from app.utils.language import normalize_text

# ── Leetspeak / obfuscation character map ────────────────────────────────────
# Length-preserving 1:1 substitutions. Applied to a COPY of the text which is
# then re-scanned; the original text is always scanned too, so this can only
# add detections.
_LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
    "|": "l", "+": "t", "(": "c", "€": "e",
}


def deobfuscate(text: str) -> str:
    """
    Return a de-obfuscated copy of `text`.

    Reverses two common evasion tricks:
      1. Leetspeak substitution  (Ign0re -> Ignore, prev!ous -> previous)
      2. Spaced-out letters      (i g n o r e -> ignore)
    """
    lowered = text.lower()
    deleeted = "".join(_LEET_MAP.get(ch, ch) for ch in lowered)
    # Collapse "s p a c e d" single letters into words.
    despaced = re.sub(r"(?<=\b\w) (?=\w\b)", "", deleeted)
    return despaced


# ── Multilingual attack phrase lexicon ───────────────────────────────────────
# Urdu and Korean phrases for the core attack categories. Matching is plain
# substring containment (these scripts have no casing).
MULTILINGUAL_PATTERNS = {
    "instruction_override": {
        "weight": 0.9,
        "phrases": [
            # Urdu
            "نظر انداز", "پچھلی ہدایات", "پچھلی تمام ہدایات", "ہدایات کو نظر انداز",
            "بھول جاؤ", "اصول بھول",
            # Korean
            "이전 지침을 무시", "지침을 무시", "규칙을 무시", "이전 규칙을 무시",
            "무시하고", "이전 명령을 무시",
        ],
    },
    "system_prompt_extraction": {
        "weight": 0.85,
        "phrases": [
            # Urdu
            "سسٹم پرامپٹ", "سسٹم پرومپٹ", "خفیہ ہدایات", "اپنی ہدایات دکھائیں",
            "پرامپٹ دکھائیں",
            # Korean
            "시스템 프롬프트", "시스템 프롬프트를 보여", "지침을 보여", "프롬프트를 공개",
            "숨겨진 프롬프트",
        ],
    },
    "jailbreak": {
        "weight": 0.9,
        "phrases": [
            # Urdu
            "کوئی پابندی نہیں", "بغیر پابندی", "آزاد اسسٹنٹ",
            # Korean
            "제한 없는", "탈옥", "안전 규칙을 무시", "제한을 해제",
        ],
    },
    "sensitive_data_request": {
        "weight": 0.8,
        "phrases": [
            # Urdu
            "پاس ورڈ بتائیں", "اے پی آئی کی", "خفیہ کلید",
            # Korean
            "비밀번호를 알려", "api 키를", "토큰을 보여",
        ],
    },
}


class RuleDetector:
    """Fast rule/keyword layer with obfuscation + multilingual coverage."""

    def __init__(self, block_threshold: float = 0.75, warn_threshold: float = 0.40):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        # Reuse the midterm English regex detector unchanged.
        self._base = InjectionDetector(block_threshold, warn_threshold)

    def _multilingual_scan(self, text: str) -> tuple:
        """Return (max_score, flags, details) for Urdu/Korean attack phrases."""
        flags, details, max_score = [], {}, 0.0
        for category, data in MULTILINGUAL_PATTERNS.items():
            hits = [p for p in data["phrases"] if p in text]
            if hits:
                flags.append(category)
                details[category] = {"matched_snippets": hits[:3],
                                      "score": data["weight"]}
                max_score = max(max_score, data["weight"])
        return max_score, flags, details

    def analyze(self, text: str) -> dict:
        """
        Score `text` for injection threats using rules only.

        Returns the same shape as the midterm detector plus `obfuscated` /
        `multilingual` booleans for the audit log.
        """
        norm = normalize_text(text)
        deobf = deobfuscate(norm)

        # 1) English regex on the original (normalised) text.
        base = self._base.analyze(norm)

        # 2) Same regex on the de-obfuscated copy — catches leet/spacing attacks.
        deobf_base = self._base.analyze(deobf)
        was_obfuscated = deobf_base["score"] > base["score"]

        # 3) Urdu / Korean keyword scan.
        ml_score, ml_flags, ml_details = self._multilingual_scan(norm)
        is_multilingual = ml_score > 0

        # Fuse: the rule layer reports the strongest signal it found.
        score = max(base["score"], deobf_base["score"], ml_score)
        flags = sorted(set(base["flags"]) | set(deobf_base["flags"]) | set(ml_flags))
        details = {**base.get("details", {}), **deobf_base.get("details", {}),
                   **ml_details}

        return {
            "score": round(score, 4),
            "flags": flags,
            "details": details,
            "risk_level": self._risk_label(score),
            "obfuscated": was_obfuscated,
            "multilingual": is_multilingual,
            "deobfuscated_text": deobf if was_obfuscated else None,
        }

    def _risk_label(self, score: float) -> str:
        if score >= self.block_threshold:
            return "HIGH"
        if score >= self.warn_threshold:
            return "MEDIUM"
        return "LOW"

    def get_thresholds(self) -> dict:
        return {"block_threshold": self.block_threshold,
                "warn_threshold": self.warn_threshold}
