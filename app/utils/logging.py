"""
Auditable logging for the security gateway.

The final lab requires every decision to be auditable: scores, reason codes,
the policy decision, the masked output and latency must all be recorded. This
module appends one JSON object per request to a JSON-Lines file (results/
audit_log.jsonl) so the log can be replayed, counted or shown in the report.
"""
import datetime
import json
import os

from app.config_loader import CONFIG, project_path


class AuditLogger:
    """Append-only JSON-Lines audit logger."""

    def __init__(self, log_path: str = None, enabled: bool = None):
        audit_cfg = CONFIG.get("audit", {})
        self.enabled = audit_cfg.get("enabled", True) if enabled is None else enabled
        rel_path = log_path or audit_cfg.get("log_path", "results/audit_log.jsonl")
        self.log_path = project_path(rel_path)
        if self.enabled:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, record: dict) -> dict:
        """
        Write one audit record. A UTC timestamp is added automatically.
        Returns the record (with timestamp) so callers can reuse it.
        """
        record = dict(record)
        record.setdefault(
            "timestamp",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        if self.enabled:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception:
                # Logging must never crash the gateway.
                pass
        return record

    def read_all(self) -> list:
        """Read back every audit record (used by the evaluation script)."""
        if not os.path.exists(self.log_path):
            return []
        records = []
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records
