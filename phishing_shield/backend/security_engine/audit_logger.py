import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = ROOT / "logs"
LOG_FILE = LOG_DIR / "audit_log.jsonl"

class AuditLogger:
    def __init__(self):
        self._setup_logging()

    def _setup_logging(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        # We'll use a specific logger for audit trails
        self.logger = logging.getLogger("security_audit")
        self.logger.setLevel(logging.INFO)
        
        # Avoid adding multiple handlers if re-initialized
        if not self.logger.handlers:
            file_handler = logging.FileHandler(LOG_FILE)
            formatter = logging.Formatter('%(message)s')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_event(self, email_id: str, analysis_result: Dict[str, Any], mode: str):
        """
        Log a security analysis event.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "email_id": email_id,
            "mode": mode,
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "ml_confidence": analysis_result.get("ml_confidence"),
            "rules_triggered": analysis_result.get("rules_triggered", []),
            "final_decision": "BLOCK" if analysis_result.get("risk_level") == "High" else "WARN" if analysis_result.get("risk_level") == "Medium" else "ALLOW"
        }
        
        self.logger.info(json.dumps(entry))
