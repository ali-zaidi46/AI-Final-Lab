"""
Tests for the customized Presidio PII layer.

Run:  python -m pytest tests/ -q       (or)     python tests/test_pii.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pii.presidio_custom import PresidioCustomAnalyzer

pii = PresidioCustomAnalyzer()


def _types(result):
    return {e["entity_type"] for e in result["entities"]}


def test_detects_student_id():
    r = pii.analyze("My student ID is FA21-BCS-123 for the result check.")
    assert "STUDENT_ID" in _types(r)


def test_detects_cnic():
    r = pii.analyze("My CNIC is 35202-1234567-1, please update it.")
    assert "CNIC" in _types(r)


def test_detects_api_key_as_secret():
    r = pii.analyze("My key is sk-abcdefghijklmnopqrstuvwxyz123456")
    assert r["has_secret"] is True


def test_masks_with_spec_placeholders():
    r = pii.analyze("Email me at test@example.com please.")
    assert "<EMAIL>" in r["masked_text"]
    assert "test@example.com" not in r["masked_text"]


def test_two_pii_types_not_flagged_composite():
    # CNIC + STUDENT_ID is two fields -> MASK territory, not a composite dump.
    r = pii.analyze("My CNIC is 35202-1234567-1 and student ID is FA21-BCS-123.")
    assert r["has_composite"] is False


def test_composite_dump_is_flagged():
    r = pii.analyze("Name Hina Tariq, email hina@example.com, "
                    "phone 0301-4455667, CNIC 37405-1122334-5.")
    assert r["has_composite"] is True


def test_benign_text_has_no_pii():
    r = pii.analyze("Explain supervised learning with one example.")
    assert r["has_pii"] is False


def test_no_nlp_false_positive_on_urdu():
    # English NER must not hallucinate PERSON/LOCATION on Urdu text.
    r = pii.analyze("مشین لرننگ کیا ہے؟ ایک آسان مثال دیں۔")
    assert r["has_pii"] is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}  {e}")
    print(f"\n{passed}/{len(fns)} PII tests passed")
    sys.exit(0 if passed == len(fns) else 1)
