import re
from typing import Any, Dict, List, Union

from backend.nlp_engine.credential_detector import CREDENTIAL_KEYWORDS, credential_request_score
from backend.nlp_engine.impersonation_detector import ORG_KEYWORDS, impersonation_score
from backend.nlp_engine.preprocess import clean_text, combine_subject_body, extract_email_addresses, extract_urls
from backend.nlp_engine.urgency_detector import URGENT_WORDS, urgency_score
from backend.nlp_engine.url_analyzer import analyze_urls, url_features

RISK_KEYWORDS = {
    "urgency": URGENT_WORDS,
    "impersonation": ORG_KEYWORDS,
    "credential": CREDENTIAL_KEYWORDS,
}

EXPLAINABILITY_MAP = {
    "url_count": "Email contains URLs, which can redirect to malicious websites.",
    "suspicious_url_score": "URLs include risky patterns (long, numeric, hyphenated, shorteners, IP-based or lookalike domains).",
    "ip_url_count": "At least one URL directly uses an IP address instead of a trusted domain.",
    "shortener_url_count": "URL shortener detected, which can hide the real destination.",
    "suspicious_subdomain_count": "Potentially deceptive subdomain terms detected (e.g., login/secure/verify).",
    "lookalike_domain_count": "Potential typosquatted or lookalike brand domain detected (e.g., paypa1).",
    "urgency_score": "Urgency language found that pressures quick action.",
    "impersonation_score": "Impersonation-like sender/organization cues detected.",
    "credential_request_score": "Possible credential-harvesting request detected (password/OTP/PIN/CVV).",
    "digit_count": "High digit usage can indicate codes, account numbers, or obfuscation.",
}

def _build_explanations(features: Dict[str, Any]):
    reasons = []
    weighted_total = 0.0

    feature_weights = {
        "url_count": 1.0,
        "suspicious_url_score": 2.0,
        "ip_url_count": 2.2,
        "shortener_url_count": 1.3,
        "suspicious_subdomain_count": 1.5,
        "lookalike_domain_count": 2.0,
        "urgency_score": 1.2,
        "impersonation_score": 1.4,
        "credential_request_score": 2.1,
        "digit_count": 0.2,
    }

    interim = []
    for key, message in EXPLAINABILITY_MAP.items():
        value = float(features.get(key, 0) or 0)
        if value > 0:
            # --- CALIBRATION FIX ---
            if key == 'digit_count' and value <= 5:
                continue
            
            weighted = value * feature_weights.get(key, 1.0)
            weighted_total += weighted
            interim.append((key, value, message, weighted))

    for key, value, message, weighted in interim:
        contribution_percent = (weighted / weighted_total * 100.0) if weighted_total > 0 else 0.0
        reasons.append(
            {
                "feature": key,
                "value": value,
                "reason": message,
                "contribution_percent": round(contribution_percent, 2),
            }
        )

    return reasons

def _find_problem_lines(text: str) -> List[Dict[str, Any]]:
    if not isinstance(text, str) or not text.strip():
        return []

    flagged: List[Dict[str, Any]] = []
    lines = text.splitlines() if "\n" in text else [text]

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        lowered = line.lower()
        indicators: List[str] = []

        if re.search(r"https?://\S+", line):
            indicators.append("url")

        for category, keywords in RISK_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                indicators.append(category)

        if indicators:
            flagged.append(
                {
                    "line_number": idx,
                    "line": line,
                    "indicators": sorted(set(indicators)),
                }
            )

    return flagged

def extract_features(record: Union[str, Dict[str, Any]]):
    """Extract explainable security features from text or structured email record."""
    if isinstance(record, str):
        text = clean_text(record)
        subject = None
        sender = None
        recipient = None
        raw_text = str(record)
    else:
        subject = record.get("subject") if hasattr(record, "get") else record.get("Subject")
        body = record.get("body") if hasattr(record, "get") else record.get("Body")
        sender = record.get("sender") if hasattr(record, "get") else record.get("From")
        recipient = record.get("recipient") if hasattr(record, "get") else record.get("To")
        raw_text = f"{subject or ''}\n{body or ''}".strip()
        text = combine_subject_body(subject, body)

    urls = extract_urls(text)
    url_count = len(urls)

    url_details = (
        analyze_urls(text)
        if url_count
        else {
            "url_count": 0,
            "suspicious_score": 0,
            "ip_url_count": 0,
            "shortener_url_count": 0,
            "suspicious_subdomain_count": 0,
            "lookalike_domain_count": 0,
        }
    )

    suspicious_url_score = url_details.get("suspicious_score", 0)
    urgency = urgency_score(text)
    impersonation = impersonation_score(text)
    credential_score = credential_request_score(text)
    digit_count = sum(c.isdigit() for c in text)
    length = len(text)
    email_addresses = extract_email_addresses(text)

    features = {
        "text": text,
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "url_count": url_count,
        "suspicious_url_score": suspicious_url_score,
        "ip_url_count": url_details.get("ip_url_count", 0),
        "shortener_url_count": url_details.get("shortener_url_count", 0),
        "suspicious_subdomain_count": url_details.get("suspicious_subdomain_count", 0),
        "lookalike_domain_count": url_details.get("lookalike_domain_count", 0),
        "urgency_score": urgency,
        "impersonation_score": impersonation,
        "credential_request_score": credential_score,
        "digit_count": digit_count,
        "length": length,
        "email_addresses": email_addresses,
    }
    features['explanations'] = _build_explanations(features)
    features['highlighted_lines'] = _find_problem_lines(raw_text)
    return features

def to_vector(features: dict):
    """Convert named features into a numeric vector for classic ML."""
    return [
        features.get("url_count", 0),
        features.get("suspicious_url_score", 0),
        features.get("ip_url_count", 0),
        features.get("shortener_url_count", 0),
        features.get("suspicious_subdomain_count", 0),
        features.get("lookalike_domain_count", 0),
        features.get("urgency_score", 0),
        features.get("impersonation_score", 0),
        features.get("credential_request_score", 0),
        features.get("digit_count", 0),
        features.get("length", 0),
        features.get("text_length", features.get("length", 0)),
    ]
