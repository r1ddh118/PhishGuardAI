import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router';
import { ArrowLeft, AlertTriangle } from 'lucide-react';
import { Card } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { getAllScans } from '../lib/db';
import type { ScanRecord } from '../lib/db';

interface ApiHistoryRecord {
  id: number;
  created_at: string;
  mode: string;
  text_preview: string;
  risk_level: string;
  confidence: number;
  explanations: Array<{
    feature?: string;
    value?: number;
    reason?: string;
    contribution_percent?: number;
  }>;
  highlighted_lines?: Array<{ line_number: number; line: string; indicators: string[] }>;
  class_percentages?: Record<string, number>;
}

function toRiskLevel(riskLevel: string): ScanRecord['riskLevel'] {
  const normalized = riskLevel.toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  return 'low';
}

function toVerdict(riskLevel: string, confidence: number): ScanRecord['verdict'] {
  const normalized = riskLevel.toLowerCase();
  if (normalized === 'high' || normalized === 'critical') return 'phishing';
  if (normalized === 'medium' || confidence >= 0.5) return 'suspicious';
  return 'safe';
}

export function ExplainabilityDetails() {
  const navigate = useNavigate();
  const { scanId } = useParams();
  const location = useLocation();
  const [scan, setScan] = useState<ScanRecord | null>((location.state as { scan?: ScanRecord } | null)?.scan || null);
  const [loading, setLoading] = useState(!scan);

  useEffect(() => {
    if (scan) return;

    const load = async () => {
      setLoading(true);
      try {
        const [local, remote] = await Promise.allSettled([
          getAllScans(),
          fetch('http://localhost:8000/history?limit=300').then((res) => res.ok ? res.json() : []),
        ]);

        const localScans = local.status === 'fulfilled' ? local.value : [];
        const remoteScans: ScanRecord[] = remote.status === 'fulfilled'
          ? (remote.value as ApiHistoryRecord[]).map((item) => ({
              id: `api-${item.id}`,
              timestamp: new Date(item.created_at),
              messageType: item.mode === 'batch' ? 'chat' : 'email',
              content: item.text_preview,
              verdict: toVerdict(item.risk_level, item.confidence),
              confidence: item.confidence,
              riskLevel: toRiskLevel(item.risk_level),
              triggeredFeatures: item.explanations
                .map((explanation) => explanation.feature || explanation.reason)
                .filter((value): value is string => Boolean(value)),
              explainability: {
                explanations: item.explanations,
                highlighted_lines: item.highlighted_lines || [],
                class_percentages: item.class_percentages || {},
              },
            }))
          : [];

        const combined = [...localScans, ...remoteScans];
        const found = combined.find((item) => item.id === decodeURIComponent(scanId || '')) || null;
        setScan(found);
      } finally {
        setLoading(false);
      }
    };

    void load();
  }, [scan, scanId]);

  const hasData = useMemo(() => {
    if (!scan) return false;
    return Boolean(
      (scan.explainability?.explanations?.length || 0) > 0 ||
      (scan.explainability?.highlighted_lines?.length || 0) > 0 ||
      Object.keys(scan.explainability?.class_percentages || {}).length > 0,
    );
  }, [scan]);

  if (loading) {
    return <div className="p-8 text-zinc-500">Loading explainability details...</div>;
  }

  if (!scan) {
    return (
      <div className="p-8">
        <Button variant="outline" onClick={() => navigate('/history')} className="mb-4 border-zinc-700">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to History
        </Button>
        <p className="text-zinc-400">Scan record not found.</p>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-5xl mx-auto p-8 space-y-6">
        <Button variant="outline" onClick={() => navigate('/history')} className="border-zinc-700">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to History
        </Button>

        <Card className="p-5 bg-zinc-900 border-zinc-800">
          <h1 className="text-xl font-semibold mb-2">Explainability Breakdown</h1>
          <p className="text-sm text-zinc-300 mb-3">{scan.content}</p>
          <div className="flex gap-2">
            <Badge className="bg-zinc-800 text-zinc-200 border-0">Confidence {(scan.confidence * 100).toFixed(1)}%</Badge>
            <Badge className="bg-zinc-800 text-zinc-200 border-0">Verdict {scan.verdict}</Badge>
            <Badge className="bg-zinc-800 text-zinc-200 border-0">Risk {scan.riskLevel}</Badge>
          </div>
        </Card>

        {!hasData && (
          <Card className="p-4 bg-zinc-900 border-zinc-800 text-zinc-500">
            Explainability details are not available for this scan.
          </Card>
        )}

        <Card className="p-5 bg-zinc-900 border-zinc-800">
          <h2 className="text-sm font-semibold mb-3 uppercase tracking-wider text-zinc-400">Class probabilities</h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {Object.entries(scan.explainability?.class_percentages || {}).map(([label, percent]) => (
              <div key={label} className="p-3 rounded border border-zinc-800 bg-zinc-950">
                <p className="text-xs text-zinc-500 capitalize">{label}</p>
                <p className="text-lg font-semibold">{Number(percent).toFixed(1)}%</p>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-5 bg-zinc-900 border-zinc-800">
          <h2 className="text-sm font-semibold mb-3 uppercase tracking-wider text-zinc-400">Indicator explanations</h2>
          <div className="space-y-2">
            {(scan.explainability?.explanations || []).map((item, idx) => (
              <div key={`${item.feature}-${idx}`} className="p-3 rounded border border-zinc-800 bg-zinc-950">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-zinc-200">{item.feature || 'Indicator'}</p>
                  <p className="text-xs text-zinc-400">Contribution {Number(item.contribution_percent || 0).toFixed(1)}%</p>
                </div>
                <p className="text-xs text-zinc-400 mt-1">{item.reason || 'No reason provided'}</p>
              </div>
            ))}
            {(scan.explainability?.explanations || []).length === 0 && (
              <p className="text-sm text-zinc-500">No indicators were recorded.</p>
            )}
          </div>
        </Card>

        <Card className="p-5 bg-zinc-900 border-zinc-800">
          <h2 className="text-sm font-semibold mb-3 uppercase tracking-wider text-zinc-400">Highlighted suspicious lines</h2>
          {(scan.explainability?.highlighted_lines || []).length > 0 ? (
            <div className="space-y-2">
              {(scan.explainability?.highlighted_lines || []).map((line) => (
                <div key={`${line.line_number}-${line.line}`} className="p-3 rounded border border-red-500/30 bg-red-500/5">
                  <p className="text-[11px] text-red-300 mb-1">Line {line.line_number} · {line.indicators.join(', ')}</p>
                  <p className="text-xs text-zinc-200 font-mono whitespace-pre-wrap">{line.line}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-zinc-500 text-sm">
              <AlertTriangle className="w-4 h-4" />
              No specific lines were highlighted for this scan.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
