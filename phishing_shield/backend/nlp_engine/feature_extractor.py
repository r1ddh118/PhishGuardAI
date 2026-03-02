from backend.nlp_engine.preprocess import clean_text, extract_urls, extract_email_addresses, combine_subject_body
from backend.nlp_engine.url_analyzer import url_features, analyze_urls
from backend.nlp_engine.urgency_detector import urgency_score
from backend.nlp_engine.impersonation_detector import impersonation_score
from backend.nlp_engine.credential_detector import credential_request_score
from typing import Union, Dict, Any


EXPLAINABILITY_MAP = {
    'url_count': 'Email contains URLs, which can redirect to malicious websites.',
    'suspicious_url_score': 'URLs include risky patterns (long, numeric, hyphenated, shorteners, IP-based or lookalike domains).',
    'ip_url_count': 'At least one URL directly uses an IP address instead of a trusted domain.',
    'shortener_url_count': 'URL shortener detected, which can hide the real destination.',
    'suspicious_subdomain_count': 'Potentially deceptive subdomain terms detected (e.g., login/secure/verify).',
    'lookalike_domain_count': 'Potential typosquatted or lookalike brand domain detected (e.g., paypa1).',
    'urgency_score': 'Urgency language found that pressures quick action.',
    'impersonation_score': 'Impersonation-like sender/organization cues detected.',
    'credential_request_score': 'Possible credential-harvesting request detected (password/OTP/PIN/CVV).',
    'digit_count': 'High digit usage can indicate codes, account numbers, or obfuscation.',
}


def _build_explanations(features: Dict[str, Any]):
    reasons = []
    for key, message in EXPLAINABILITY_MAP.items():
        val = features.get(key, 0)
        if val > 0:
            if key == 'digit_count' and val <= 5:
                continue
            reasons.append({
                'feature': key,
                'value': features.get(key),
                'reason': message,
            })
    return reasons


def extract_features(record: Union[str, Dict[str, Any]]):
    """Extract explainable security features from text or structured email record.

    record can be a plain string (treated as body) or a dict-like with keys
    'subject', 'body', 'sender', 'recipient', 'timestamp', 'attachments'.

    Returns a dictionary of named features.
    """
    # support plain string input
    if isinstance(record, str):
        text = clean_text(record)
        subject = None
        sender = None
        recipient = None
    else:
        subject = record.get('subject') if hasattr(record, 'get') else record.get('Subject')
        body = record.get('body') if hasattr(record, 'get') else record.get('Body')
        sender = record.get('sender') if hasattr(record, 'get') else record.get('From')
        recipient = record.get('recipient') if hasattr(record, 'get') else record.get('To')
        text = combine_subject_body(subject, body)

    urls = extract_urls(text)
    url_count = len(urls)

    url_details = analyze_urls(text) if url_count else {
        'url_count': 0,
        'suspicious_score': 0,
        'ip_url_count': 0,
        'shortener_url_count': 0,
        'suspicious_subdomain_count': 0,
        'lookalike_domain_count': 0,
    }
    # keep backward-compatible aggregate URL score
    suspicious_url_score = url_details.get('suspicious_score', 0)

    urgency = urgency_score(text)
    impersonation = impersonation_score(text)
    credential_score = credential_request_score(text)
    digit_count = sum(c.isdigit() for c in text)
    length = len(text)
    email_addresses = extract_email_addresses(text)

    features = {
        'text': text,
        'subject': subject,
        'sender': sender,
        'recipient': recipient,
        'url_count': url_count,
        'suspicious_url_score': suspicious_url_score,
        'ip_url_count': url_details.get('ip_url_count', 0),
        'shortener_url_count': url_details.get('shortener_url_count', 0),
        'suspicious_subdomain_count': url_details.get('suspicious_subdomain_count', 0),
        'lookalike_domain_count': url_details.get('lookalike_domain_count', 0),
        'urgency_score': urgency,
        'impersonation_score': impersonation,
        'credential_request_score': credential_score,
        'digit_count': digit_count,
        'length': length,
        'email_addresses': email_addresses,
    }
    features['explanations'] = _build_explanations(features)
    return features


def to_vector(features: dict):
    """Convert named features into a numeric vector for classic ML (order consistent)."""
    return [
        features.get('url_count', 0),
        features.get('suspicious_url_score', 0),
        features.get('ip_url_count', 0),
        features.get('shortener_url_count', 0),
        features.get('suspicious_subdomain_count', 0),
        features.get('lookalike_domain_count', 0),
        features.get('urgency_score', 0),
        features.get('impersonation_score', 0),
        features.get('credential_request_score', 0),
        features.get('digit_count', 0),
        features.get('length', 0),
    ]
