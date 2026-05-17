"""
Language detection + preprocessing for the multilingual security gateway.

The final lab requires the gateway to handle English, Urdu and Korean (plus
mixed-language text). Pure statistical detectors (langdetect) are unreliable on
very short prompts, so we combine two signals:

  1. Unicode-script counting  -> robust for Urdu (Arabic script) and Korean
     (Hangul), and lets us flag mixed-language prompts.
  2. langdetect (if installed) -> disambiguates Latin-script languages.

Returns ISO-639-1 style codes: "en", "ur", "ko", and "mixed".
"""
import re

try:
    from langdetect import detect_langs
    from langdetect.lang_detect_exception import LangDetectException
    _LANGDETECT = True
except Exception:                       # pragma: no cover - optional dependency
    _LANGDETECT = False

# Unicode ranges for the scripts we care about.
_URDU_RE = re.compile(r"[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]")
_HANGUL_RE = re.compile(r"[가-힯ᄀ-ᇿ㄰-㆏]")
_LATIN_RE = re.compile(r"[A-Za-z]")


def _script_counts(text: str) -> dict:
    """Count characters belonging to each script of interest."""
    return {
        "urdu": len(_URDU_RE.findall(text)),
        "hangul": len(_HANGUL_RE.findall(text)),
        "latin": len(_LATIN_RE.findall(text)),
    }


def detect_language(text: str) -> dict:
    """
    Detect the dominant language of `text`.

    Returns a dict:
        language   : "en" | "ur" | "ko" | "mixed"
        is_mixed   : True if two or more scripts are meaningfully present
        scripts    : raw per-script character counts
        confidence : rough 0-1 confidence in the dominant language
    """
    text = text or ""
    counts = _script_counts(text)
    urdu, hangul, latin = counts["urdu"], counts["hangul"], counts["latin"]
    total = urdu + hangul + latin

    if total == 0:
        return {"language": "en", "is_mixed": False, "scripts": counts,
                "confidence": 0.3}

    # A script "counts" as present if it holds at least 15% of the letters.
    present = [name for name, c in
               (("ur", urdu), ("ko", hangul), ("en", latin))
               if c / total >= 0.15]
    is_mixed = len(present) >= 2

    # Dominant script wins the label.
    dominant_name, dominant_count = max(
        (("ur", urdu), ("ko", hangul), ("en", latin)), key=lambda kv: kv[1])
    confidence = round(dominant_count / total, 3)

    # Latin script alone is ambiguous (English vs Roman-Urdu vs other) ->
    # ask langdetect to refine when available.
    if dominant_name == "en" and _LANGDETECT and len(text.strip()) >= 8:
        try:
            best = detect_langs(text)[0]
            if best.lang in ("en", "ur", "ko"):
                dominant_name = best.lang
                confidence = round(float(best.prob), 3)
        except LangDetectException:
            pass

    return {
        "language": "mixed" if is_mixed else dominant_name,
        "primary_language": dominant_name,
        "is_mixed": is_mixed,
        "scripts": counts,
        "confidence": confidence,
    }


def normalize_text(text: str) -> str:
    """
    Light preprocessing used before the rule detector runs.

    Collapses repeated whitespace and strips zero-width characters that attacks
    sometimes insert to break keyword matching. This does NOT change semantics,
    so it is safe to apply before detection.
    """
    text = text or ""
    text = re.sub(r"[​-‍﻿]", "", text)   # zero-width chars
    text = re.sub(r"\s+", " ", text).strip()
    return text
