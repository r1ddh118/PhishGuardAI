// Batch scan API integration
const API_BASE = "http://127.0.0.1:8000";

export interface BatchScanResult {
  batch_results: Array<{
    text_preview: string;
    is_phishing: boolean;
    confidence: number;
    risk_level: string;
  }>;
  total_scanned: number;
}

