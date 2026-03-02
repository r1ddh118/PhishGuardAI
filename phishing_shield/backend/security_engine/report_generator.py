import json
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    @staticmethod
    def generate_json_report(analysis_result: Dict[str, Any], email_meta: Dict[str, Any]) -> str:
        """Generate a full JSON report suitable for API responses or storage."""
        report = {
            "meta": {
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "1.0",
                "email_id": email_meta.get("id", "unknown"),
                "sender": email_meta.get("sender", "unknown"),
                "subject": email_meta.get("subject", "unknown")
            },
            "analysis": analysis_result
        }
        return json.dumps(report, indent=2)

    @staticmethod
    def generate_text_report(analysis_result: Dict[str, Any], email_meta: Dict[str, Any]) -> str:
        """Generate a human-readable text report for analysts."""
        lines = []
        lines.append("====== PHISHING SHIELD SECURITY REPORT ======")
        lines.append(f"Date: {datetime.utcnow().isoformat()}")
        lines.append(f"Email ID: {email_meta.get('id', 'N/A')}")
        lines.append(f"Subject: {email_meta.get('subject', 'N/A')}")
        lines.append(f"Sender: {email_meta.get('sender', 'N/A')}")
        lines.append("-" * 45)
        
        lines.append(f"RISK LEVEL: {analysis_result.get('risk_level', 'UNKNOWN').upper()}")
        lines.append(f"Risk Score: {analysis_result.get('risk_score', 0):.4f}")
        lines.append("-" * 45)
        
        lines.append("DETAILS:")
        lines.append(f"ML Confidence: {analysis_result.get('ml_confidence', 0):.4f}")
        
        rules = analysis_result.get('rules_triggered', [])
        if rules:
            lines.append("\nViolations:")
            for r in rules:
                lines.append(f" [!] {r}")
        
        if 'explanation' in analysis_result:
            lines.append("\nAnalyst Evidence:")
            lines.append(analysis_result['explanation'])
            
        lines.append("=============================================")
        return "\n".join(lines)
