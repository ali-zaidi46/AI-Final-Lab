import re

try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

CUSTOM_PATTERNS = {
    "PK_PHONE": [
        r"\b0[0-9]{2,3}[-.\s]?[0-9]{7,8}\b",
        r"\+92[-.\s]?[0-9]{2,3}[-.\s]?[0-9]{7,8}\b",
    ],
    "API_KEY": [
        r"\bsk-[A-Za-z0-9]{5,}\b",
        r"\bghp_[A-Za-z0-9]{36}\b",
        r"\bAIza[A-Za-z0-9_\-]{35}\b",
    ],
    "INTERNAL_ID": [
        r"\bEMP-\d{4,6}\b",
        r"\bSTU-\d{4,6}\b",
        r"\bCUI-\d{5,8}\b",
    ],
    # Final-lab custom recognizer: university student registration numbers
    # e.g. FA21-BCS-123, SP22-BSE-456 (semester+year - programme - roll).
    "STUDENT_ID": [
        r"\b[A-Za-z]{2}\d{2}-[A-Za-z]{2,4}-\d{1,4}\b",
    ],
    "EMAIL": [
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ],
    "CREDIT_CARD": [
        r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b",
    ],
    "INTL_PHONE": [
        r"\b(?:\+?\d{1,3})[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}\b",
    ],
    "CNIC": [
        r"\b\d{5}-\d{7}-\d{1}\b",
    ],
    "PASSPORT": [
        r"\b[A-Z]{2}\d{7}\b",       
        r"\b[A-Z]\d{8}\b",           
        r"\b\d{9}\b",                
    ],
    "IP_ADDRESS": [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    ],
}

CONTEXT_RISK_WORDS = {
    "API_KEY":     ["key", "token", "secret", "api", "auth", "bearer"],
    "PK_PHONE":    ["call", "contact", "phone", "number", "reach", "mobile"],
    "INTL_PHONE":  ["call", "contact", "phone", "number", "reach", "mobile", "whatsapp"],
    "EMAIL":       ["email", "mail", "contact", "send"],
    "CREDIT_CARD": ["card", "payment", "pay", "billing", "credit", "debit"],
    "INTERNAL_ID": ["employee", "student", "id", "identifier", "ticket", "ref"],
    "STUDENT_ID":  ["student", "registration", "roll", "id", "reg", "enrollment"],
    "CNIC":        ["cnic", "identity", "national", "card"],
    "PASSPORT":    ["passport", "travel", "document", "visa"],
}

CONFIDENCE_CALIBRATION = {
    "API_KEY":     1.0,
    "CREDIT_CARD": 0.98,
    "CNIC":        0.95,
    "PASSPORT":    0.92,
    "PK_PHONE":    0.90,
    "INTL_PHONE":  0.88,
    "EMAIL":       0.88,
    "INTERNAL_ID": 0.85,
    "STUDENT_ID":  0.90,
    "IP_ADDRESS":  0.70,
}


class PresidioAnalyzerWrapper:
    def __init__(self):
        if PRESIDIO_AVAILABLE:
            self._init_presidio()
        self._compile_fallback_patterns()

    def _init_presidio(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        for entity_type, patterns in CUSTOM_PATTERNS.items():
            presidio_patterns = [
                Pattern(name=f"{entity_type}_{i}", regex=p, score=0.7)
                for i, p in enumerate(patterns)
            ]
            recognizer = PatternRecognizer(
                supported_entity=entity_type,
                patterns=presidio_patterns,
                context=CONTEXT_RISK_WORDS.get(entity_type, []),
            )
            self.analyzer.registry.add_recognizer(recognizer)

    def _compile_fallback_patterns(self):
        self._compiled_patterns = {}
        for entity_type, patterns in CUSTOM_PATTERNS.items():
            self._compiled_patterns[entity_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def _detect_composite(self, text, entities):
        entity_types = {e["entity_type"] for e in entities}
        
        # Group similar entity types so overlapping phone matchers don't trigger composite dump
        unique_categories = set()
        for e in entity_types:
            if "PHONE" in e:
                unique_categories.add("PHONE_GROUP")
            else:
                unique_categories.add(e)
                
        composite = []
        if len(unique_categories) >= 3:
            composite.append({
                "entity_type": "COMPOSITE_PII_DUMP",
                "score": 1.0,
                "start": 0,
                "end": len(text),
                "note": f"Multiple PII types: {', '.join(entity_types)}"
            })
        elif {"API_KEY", "EMAIL"}.issubset(entity_types):
            composite.append({
                "entity_type": "CREDENTIAL_LEAK",
                "score": 0.98,
                "start": 0,
                "end": len(text),
                "note": "API key + email detected"
            })
        elif {"CREDIT_CARD"}.intersection(entity_types) and unique_categories.intersection({"PHONE_GROUP"}):
            composite.append({
                "entity_type": "FINANCIAL_PII",
                "score": 0.97,
                "start": 0,
                "end": len(text),
                "note": "Credit card + phone detected"
            })
        return composite

    def _apply_context_scoring(self, text, entity):
        entity_type = entity["entity_type"]
        context_words = CONTEXT_RISK_WORDS.get(entity_type, [])
        text_lower = text.lower()
        boost = sum(0.05 for w in context_words if w in text_lower)
        calibrated_max = CONFIDENCE_CALIBRATION.get(entity_type, 0.85)
        entity = dict(entity)
        entity["score"] = round(min(calibrated_max, entity["score"] + boost), 4)
        entity["context_boosted"] = boost > 0
        return entity

    def _fallback_analyze(self, text):
        findings = []
        for entity_type, compiled_list in self._compiled_patterns.items():
            for pattern in compiled_list:
                for match in pattern.finditer(text):
                    findings.append({
                        "entity_type": entity_type,
                        "start": match.start(),
                        "end": match.end(),
                        "score": CONFIDENCE_CALIBRATION.get(entity_type, 0.75),
                        "matched_text": match.group(0),
                        "context_boosted": False,
                    })
        return findings

    def analyze(self, text):
        if PRESIDIO_AVAILABLE:
            raw = self.analyzer.analyze(
                text=text,
                language="en",
                entities=list(CUSTOM_PATTERNS.keys()) + ["PERSON", "LOCATION"],
            )
            entities = [{
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": r.score,
                "matched_text": text[r.start:r.end],
                "context_boosted": False,
            } for r in raw]
        else:
            entities = self._fallback_analyze(text)

        entities = [self._apply_context_scoring(text, e) for e in entities]
        entities.extend(self._detect_composite(text, entities))
        masked = self._mask_text(text, [e for e in entities if "matched_text" in e])

        return {
            "entities": entities,
            "entity_count": len(entities),
            "has_pii": len(entities) > 0,
            "masked_text": masked,
            "presidio_available": PRESIDIO_AVAILABLE,
        }

    def _mask_text(self, text, entities):
        sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
        masked = text
        for e in sorted_entities:
            masked = masked[:e["start"]] + f"[{e['entity_type']}]" + masked[e["end"]:]
        return masked