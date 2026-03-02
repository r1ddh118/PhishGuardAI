// Mock AI Inference Engine for Phishing Detection
// In production, this would call a TensorFlow.js or ONNX model

export interface InferenceResult {
  prediction: 'safe' | 'suspicious' | 'phishing';
  confidence: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  triggeredFeatures: {
    name: string;
    detected: boolean;
    severity: number;
  }[];
  explanation: string;
}

const PHISHING_PATTERNS = {
  urgency: [
    /urgent/i,
    /immediate action/i,
    /act now/i,
    /expires/i,
    /suspended/i,
    /locked/i,
    /verify now/i,
    /within 24 hours/i,
    /confirm immediately/i,
  ],
  impersonation: [
    /dear user/i,
    /dear customer/i,
    /dear member/i,
    /valued customer/i,
    /account holder/i,
    /IT department/i,
    /security team/i,
    /support team/i,
  ],
  suspiciousURL: [
    /bit\.ly/i,
    /tinyurl/i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /-secure-/i,
    /-login/i,
    /-verify/i,
    /[0-9]{5,}/,
  ],
  financialTrigger: [
    /refund/i,
    /payment failed/i,
    /unauthorized charge/i,
    /wire transfer/i,
    /bank account/i,
    /credit card/i,
    /ssn/i,
    /social security/i,
  ],
  credentialRequest: [
    /username/i,
    /password/i,
    /login credentials/i,
    /verify your identity/i,
    /confirm your details/i,
    /update your information/i,
  ],
  spoofedDomain: [
    /paypa1/i,
    /g00gle/i,
    /micros0ft/i,
    /amaz0n/i,
    /app1e/i,
  ],
};

function analyzeContent(text: string): InferenceResult['triggeredFeatures'] {
  const features = [
    {
      name: 'urgency',
      label: 'Urgency Language',
      patterns: PHISHING_PATTERNS.urgency,
    },
    {
      name: 'impersonation',
      label: 'Impersonation Indicators',
      patterns: PHISHING_PATTERNS.impersonation,
    },
    {
      name: 'suspicious_url',
      label: 'Suspicious URL Patterns',
      patterns: PHISHING_PATTERNS.suspiciousURL,
    },
    {
      name: 'financial_trigger',
      label: 'Financial Keywords',
      patterns: PHISHING_PATTERNS.financialTrigger,
    },
    {
      name: 'credential_request',
      label: 'Credential Request',
      patterns: PHISHING_PATTERNS.credentialRequest,
    },
    {
      name: 'spoofed_domain',
      label: 'Domain Spoofing',
      patterns: PHISHING_PATTERNS.spoofedDomain,
    },
  ];

  return features.map(feature => {
    const detected = feature.patterns.some(pattern => pattern.test(text));
    const severity = detected ? Math.random() * 0.3 + 0.7 : Math.random() * 0.3;
    return {
      name: feature.label,
      detected,
      severity,
    };
  });
}

export async function analyzeMessage(content: string): Promise<InferenceResult> {
  const API_URL = 'http://localhost:8000/predict';

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content: content,
        subject: '', // Optional
        sender: ''   // Optional
      }),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as InferenceResult;
    return data;
  } catch (error) {
    console.error('Phishing API Error:', error);
    // Fallback to minimal risk result if API fails
    return {
      prediction: 'safe',
      confidence: 0,
      riskLevel: 'low',
      triggeredFeatures: [],
      explanation: 'Unable to reach detection server. Please check your connection.',
    };
  }
}

// Model metadata
export const MODEL_INFO = {
  version: '2.3.1',
  lastUpdate: '2026-02-08T14:30:00Z',
  ruleSetVersion: '4.1.0',
  totalFeatures: 47,
  accuracy: 0.94,
};
