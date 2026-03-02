import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from backend.security_engine.scoring import SecurityEngine
from backend.security_engine.audit_logger import AuditLogger
from backend.security_engine.report_generator import ReportGenerator

def test_engine():
    print("Initializing Security Engine...")
    engine = SecurityEngine()
    logger = AuditLogger()
    reporter = ReportGenerator()
    
    # Test Case 1: Safe Email
    print("\n--- Test Case 1: Safe Email ---")
    safe_email = {
        "id": "test_001",
        "subject": "Meeting Reminder",
        "body": "Hi team, quick reminder about the sync at 2 PM. Best, Alice",
        "sender": "alice@company.com"
    }
    result_safe = engine.analyze_email(safe_email, mode="field")
    print(f"Result: {result_safe['risk_level']} (Score: {result_safe['risk_score']})")
    
    # Test Case 2: Phishing (Urgency + Rules)
    print("\n--- Test Case 2: Phishing (Urgency + Rules) ---")
    phish_email = {
        "id": "test_002",
        "subject": "URGENT: Account Suspended",
        "body": "Your bank account has been suspended due to suspicious activity. Verify now or lose access immediately. Click http://bit.ly/fake-bank to login.",
        "sender": "support@security-alert-bank.com"
    }
    # Mocking features usually extracted by NLP engine if we passed raw text, 
    # but `analyze_email` calls `extract_features` internally, so passing dict is fine.
    
    result_phish = engine.analyze_email(phish_email, mode="analyst")
    print(f"Result: {result_phish['risk_level']} (Score: {result_phish['risk_score']})")
    print("Triggers:", result_phish['rules_triggered'])
    
    # Test Logging
    logger.log_event(phish_email['id'], result_phish, mode="analyst")
    print("Logged event to audit_log.jsonl")
    
    # Test Report
    report_txt = reporter.generate_text_report(result_phish, phish_email)
    print("\nGenerated Report Preview:")
    print(report_txt)

if __name__ == "__main__":
    test_engine()
