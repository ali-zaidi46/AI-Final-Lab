"""
Central config loader for the LLM Security Gateway (Final Lab).

All thresholds live in config/gateway_config.yaml. This module loads that file
once and exposes it as a plain dict. If the YAML file or PyYAML is missing, a
built-in DEFAULTS dict is used so the gateway still runs (non-breaking).
"""
import os

# Absolute path to config/gateway_config.yaml regardless of where Python is run.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "gateway_config.yaml")

# Fallback used only if the YAML cannot be read. Keeps the gateway functional.
DEFAULTS = {
    "detection": {
        "rule_block_threshold": 0.75,
        "rule_warn_threshold": 0.40,
        "semantic_block_threshold": 0.70,
        "semantic_warn_threshold": 0.45,
        "fusion_mode": "max",
        "rule_weight": 0.45,
        "semantic_weight": 0.55,
    },
    "risk_formula": {
        "pii_weight": 0.10,
        "secret_weight": 0.35,
        "composite_weight": 0.45,
    },
    "policy": {
        "block_threshold": 0.75,
        "mask_pii_score": 0.55,
    },
    "language": {"supported": ["en", "ur", "ko"], "default": "en"},
    "audit": {"enabled": True, "log_path": "results/audit_log.jsonl"},
    "model": {
        "semantic_model_path": "results/semantic_model.joblib",
        "dataset_path": "data/final_eval.csv",
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base recursively so a partial YAML still works."""
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config() -> dict:
    """Load and return the merged configuration dictionary."""
    try:
        import yaml
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        return _deep_merge(DEFAULTS, loaded)
    except Exception:
        # Missing file / missing PyYAML / parse error -> safe defaults.
        return dict(DEFAULTS)


def project_path(*parts: str) -> str:
    """Return an absolute path rooted at the project directory."""
    return os.path.join(_PROJECT_ROOT, *parts)


# Loaded once at import time; modules import CONFIG directly.
CONFIG = load_config()
