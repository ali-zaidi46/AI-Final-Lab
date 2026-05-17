"""
Customized Presidio PII layer (Final Lab).

This module is the final-lab PII detector. It REUSES the midterm
PresidioAnalyzerWrapper (app/presidio_analyzer.py) so nothing already working
is broken, and adds the improvements the final lab requires:

Four+ Presidio customizations carried by this layer
---------------------------------------------------
  1. Custom recognizers   : PK_PHONE, API_KEY, CNIC, INTERNAL_ID, PASSPORT and
                            the new STUDENT_ID recognizer (FA21-BCS-123 form).
  2. Context-aware scoring: confidence is boosted when words like "email",
                            "phone", "cnic", "student id", "api key" sit near
                            the entity (inherited from the midterm wrapper).
  3. Composite detection  : credential leaks / multi-PII dumps are flagged as
                            COMPOSITE_PII_DUMP / CREDENTIAL_LEAK / FINANCIAL_PII.
  4. Confidence calibration: per-entity calibrated ceilings (API_KEY 1.0,
                            CNIC 0.95, STUDENT_ID 0.90, ...).

What is NEW in the final lab
----------------------------
  * Spec placeholders <PERSON> <EMAIL> <PHONE> <CNIC> <API_KEY> <STUDENT_ID>
    instead of the midterm's [ENTITY] style.
  * Overlap-safe masking (overlapping spans no longer corrupt the output).
  * `has_secret` / `has_composite` / `pii_score` signals for the risk formula.
"""
from app.presidio_analyzer import PresidioAnalyzerWrapper
from app.utils.language import detect_language

# Entities produced by the spaCy English NER model. Its predictions are
# unreliable on Urdu / Korean script, so they are dropped for non-English text
# (the regex custom recognizers are script-agnostic and kept for all languages).
_NLP_ENTITIES = {"PERSON", "LOCATION", "NRP", "DATE_TIME"}

# LOCATION is not one of the required final-lab placeholders and the English
# NER model frequently mislabels odd tokens (e.g. obfuscated words) as a
# LOCATION, so it is dropped for every language to keep the output clean.
_ALWAYS_DROP = {"LOCATION"}

# Map every detected entity type to the placeholder required by the final lab.
PLACEHOLDER_MAP = {
    "PERSON": "<PERSON>",
    "EMAIL": "<EMAIL>",
    "EMAIL_ADDRESS": "<EMAIL>",
    "PK_PHONE": "<PHONE>",
    "INTL_PHONE": "<PHONE>",
    "PHONE_NUMBER": "<PHONE>",
    "CNIC": "<CNIC>",
    "API_KEY": "<API_KEY>",
    "STUDENT_ID": "<STUDENT_ID>",
    "INTERNAL_ID": "<INTERNAL_ID>",
    "CREDIT_CARD": "<CREDIT_CARD>",
    "PASSPORT": "<PASSPORT>",
    "IP_ADDRESS": "<IP_ADDRESS>",
    "LOCATION": "<LOCATION>",
}

# Entities that represent a leaked secret/credential -> drive `secret_weight`.
SECRET_ENTITIES = {"API_KEY"}

# Composite markers produced by the midterm wrapper -> drive `composite_weight`.
COMPOSITE_ENTITIES = {"COMPOSITE_PII_DUMP", "CREDENTIAL_LEAK", "FINANCIAL_PII"}


def placeholder_for(entity_type: str) -> str:
    """Return the spec placeholder for an entity type."""
    return PLACEHOLDER_MAP.get(entity_type, f"<{entity_type}>")


class PresidioCustomAnalyzer(PresidioAnalyzerWrapper):
    """Final-lab PII analyzer: spec placeholders + risk signals."""

    @staticmethod
    def _dedupe_overlaps(entities: list) -> list:
        """
        Drop overlapping spans so masking cannot corrupt the text.
        When two detections overlap, the higher-confidence one is kept.
        """
        spans = [e for e in entities if "matched_text" in e
                 and "start" in e and "end" in e]
        spans.sort(key=lambda e: (-e.get("score", 0), e["start"]))
        kept = []
        for e in spans:
            if any(not (e["end"] <= k["start"] or e["start"] >= k["end"])
                   for k in kept):
                continue          # overlaps an already-kept (higher-score) span
            kept.append(e)
        return kept

    def mask_with_placeholders(self, text: str, entities: list) -> str:
        """Replace each entity span with its spec placeholder, right-to-left."""
        kept = self._dedupe_overlaps(entities)
        for e in sorted(kept, key=lambda x: x["start"], reverse=True):
            text = (text[:e["start"]]
                    + placeholder_for(e["entity_type"])
                    + text[e["end"]:])
        return text

    def analyze(self, text: str) -> dict:
        """
        Run the midterm Presidio pipeline, then re-mask with spec placeholders
        and derive the signals the policy engine's risk formula consumes.

        Composite detection is RE-COMPUTED here on overlap-deduped entities.
        The midterm wrapper computes it on raw spans, so a loose regex (e.g.
        INTL_PHONE matching CNIC digits) could inflate the type count and turn
        a benign two-field message into a false BLOCK. Deduping first fixes
        that while leaving the midterm file untouched.
        """
        base = super().analyze(text)
        raw_real = [e for e in base["entities"]
                    if e["entity_type"] not in COMPOSITE_ENTITIES
                    and e["entity_type"] not in _ALWAYS_DROP]

        # On non-English text the English NER model hallucinates PERSON /
        # LOCATION entities -> drop them to avoid multilingual false positives.
        if detect_language(text)["primary_language"] != "en":
            raw_real = [e for e in raw_real
                        if e["entity_type"] not in _NLP_ENTITIES]

        # Overlap-deduped real entities -> used for masking AND composite logic.
        real = self._dedupe_overlaps(raw_real)
        composite = self._detect_composite(text, real)
        entities = real + composite

        masked = self.mask_with_placeholders(text, real)
        pii_score = max((e.get("score", 0.0) for e in real), default=0.0)

        return {
            "entities": entities,
            "entity_count": len(real),
            "has_pii": len(real) > 0,
            "has_secret": any(e["entity_type"] in SECRET_ENTITIES for e in real),
            "has_composite": len(composite) > 0,
            "composite_types": [e["entity_type"] for e in composite],
            "pii_score": round(pii_score, 4),
            "masked_text": masked,
            "presidio_available": base.get("presidio_available", False),
        }
