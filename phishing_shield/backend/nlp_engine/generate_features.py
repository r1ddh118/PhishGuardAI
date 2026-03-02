"""Combine all CSVs in data/, extract NLP/security features and save results.

Usage:
  python -m backend.nlp_engine.generate_features
"""
from pathlib import Path
import sys
import pandas as pd
from scipy import sparse

from .vectorizer import EnhancedVectorizer
from .feature_extractor import extract_features

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
FEATURE_CSV = DATA_DIR / "features.csv"
FEATURE_NPZ = DATA_DIR / "features.npz"


def find_csv_files():
    # include all CSV files in data/ except generated features.csv
    files = sorted([p for p in DATA_DIR.glob("*.csv") if p.name != FEATURE_CSV.name])
    return files


def normalize_label(label):
    if pd.isna(label):
        return None
    s = str(label).strip().lower()
    if s in ("legitimate", "legit", "safe"):
        return "legitimate"
    if s in ("phishing", "phish"):
        return "phishing"
    return s


def read_and_combine(paths):
    from io import StringIO
    encodings_to_try = [None, 'utf-8', 'latin-1', 'cp1252']
    dfs = []
    for p in paths:
        df = None
        last_exc = None
        for enc in encodings_to_try:
            try:
                if enc is None:
                    # let pandas auto-detect
                    df = pd.read_csv(p, on_bad_lines='skip')
                else:
                    df = pd.read_csv(p, encoding=enc, on_bad_lines='skip')
                break
            except Exception as e:
                last_exc = e
                continue
        if df is None:
            # final fallback: read bytes and decode with replacement, then parse
            try:
                raw = p.read_bytes()
                text = raw.decode('utf-8', errors='replace')
                df = pd.read_csv(StringIO(text), on_bad_lines='skip')
                print(f"Warning: read {p.name} with replacement decoding due to: {last_exc}")
            except Exception as e:
                print(f"Warning: failed to read {p}: {e}")
                continue
        df['__source_file'] = p.name
        dfs.append(df)
    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True, sort=False)


def main(argv=sys.argv):
    csvs = find_csv_files()
    if not csvs:
        raise SystemExit("No CSV files found in data/ to process")
    print("Found CSV files:", csvs)

    df_all = read_and_combine(csvs)
    if df_all.empty:
        raise SystemExit("Combined dataframe is empty")

    records = []
    texts = []
    labels = []
    ids = []
    meta_sender = []
    meta_recipient = []

    for idx, row in df_all.iterrows():
        eid = row.get('Email ID') if 'Email ID' in row.index else row.get('id') if 'id' in row.index else row.get('email_id') if 'email_id' in row.index else row.get('ID') if 'ID' in row.index else idx
        sender = row.get('Sender') if 'Sender' in row.index else row.get('From') if 'From' in row.index else row.get('sender') if 'sender' in row.index else None
        recipient = row.get('Recipient') if 'Recipient' in row.index else row.get('To') if 'To' in row.index else row.get('recipient') if 'recipient' in row.index else None
        subject = row.get('Subject') if 'Subject' in row.index else row.get('subject') if 'subject' in row.index else None
        body = row.get('Body') if 'Body' in row.index else row.get('body') if 'body' in row.index else row.get('text') if 'text' in row.index else None
        label = row.get('Label') if 'Label' in row.index else row.get('label') if 'label' in row.index else row.get('Labels') if 'Labels' in row.index else None

        rec = {'subject': subject, 'body': body, 'sender': sender, 'recipient': recipient}
        feat = extract_features(rec)

        records.append(feat)
        texts.append(feat.get('text', ''))
        labels.append(normalize_label(label))
        ids.append(eid)
        meta_sender.append(sender)
        meta_recipient.append(recipient)

    # build engineered features dataframe
    feats_df = pd.DataFrame([{
        'url_count': r.get('url_count', 0),
        'suspicious_url_score': r.get('suspicious_url_score', 0),
        'urgency_score': r.get('urgency_score', 0),
        'impersonation_score': r.get('impersonation_score', 0),
        'credential_request_score': r.get('credential_request_score', 0),
        'ip_url_count': r.get('ip_url_count', 0),
        'shortener_url_count': r.get('shortener_url_count', 0),
        'suspicious_subdomain_count': r.get('suspicious_subdomain_count', 0),
        'lookalike_domain_count': r.get('lookalike_domain_count', 0),
        'digit_count': r.get('digit_count', 0),
        'text_length': r.get('length', 0),
        'email_addresses': ';'.join(r.get('email_addresses', [])) if r.get('email_addresses') else '',
        'explanations': ' | '.join([f"{item.get('feature')}:{item.get('reason')}" for item in r.get('explanations', [])])
    } for r in records])

    # Fit vectorizer and produce sparse matrix
    vec = EnhancedVectorizer(max_features=2000)
    X = vec.fit_transform(texts)

    # Save engineered features CSV (with metadata and labels)
    out_df = pd.DataFrame({'id': ids, 'sender': meta_sender, 'recipient': meta_recipient, 'label': labels})
    out_df = pd.concat([out_df.reset_index(drop=True), feats_df.reset_index(drop=True)], axis=1)
    out_df.to_csv(FEATURE_CSV, index=False)

    # Save sparse feature matrix and vectorizer
    sparse.save_npz(FEATURE_NPZ, X)
    MODEL_DIR = ROOT / "backend" / "model"
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    vec.save(MODEL_DIR / "vectorizer.joblib")

    print("Wrote:", FEATURE_CSV, FEATURE_NPZ, "and saved vectorizer to", MODEL_DIR / "vectorizer.joblib")


if __name__ == '__main__':
    main()
