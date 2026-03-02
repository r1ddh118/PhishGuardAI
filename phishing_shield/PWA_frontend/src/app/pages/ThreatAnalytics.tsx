import { useEffect, useState } from 'react';
import { 
  TrendingUp, 
  AlertTriangle, 
  Shield,
  Activity
} from 'lucide-react';
import { Card } from '../components/ui/card';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { getAllScans } from '../lib/db';
import type { ScanRecord } from '../lib/db';
import { format, subDays, startOfDay } from 'date-fns';

export function ThreatAnalytics() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const data = await getAllScans();
      setScans(data);
    } catch (error) {
      console.error('Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  };

  // Calculate stats
  const today = startOfDay(new Date());
  const scansToday = scans.filter(s => 
    startOfDay(new Date(s.timestamp)).getTime() === today.getTime()
  );
  const phishingToday = scansToday.filter(s => s.verdict === 'phishing');

  // Top features
  const featureCounts: Record<string, number> = {};
  scans.forEach(scan => {
    scan.triggeredFeatures.forEach(feature => {
      featureCounts[feature] = (featureCounts[feature] || 0) + 1;
    });
  });
  const topFeatures = Object.entries(featureCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  // Trend data (last 7 days)
  const trendData = Array.from({ length: 7 }, (_, i) => {
    const date = subDays(new Date(), 6 - i);
    const dayStart = startOfDay(date);
    const dayScans = scans.filter(s => 
      startOfDay(new Date(s.timestamp)).getTime() === dayStart.getTime()
    );
    return {
      date: format(date, 'MMM dd'),
      phishing: dayScans.filter(s => s.verdict === 'phishing').length,
      suspicious: dayScans.filter(s => s.verdict === 'suspicious').length,
      safe: dayScans.filter(s => s.verdict === 'safe').length,
    };
  });

  // Verdict distribution
  const verdictData = [
    { name: 'Safe', value: scans.filter(s => s.verdict === 'safe').length, color: '#22c55e' },
    { name: 'Suspicious', value: scans.filter(s => s.verdict === 'suspicious').length, color: '#eab308' },
    { name: 'Phishing', value: scans.filter(s => s.verdict === 'phishing').length, color: '#ef4444' },
  ];

  // Risk distribution
  const riskData = [
    { name: 'Low', count: scans.filter(s => s.riskLevel === 'low').length },
    { name: 'Medium', count: scans.filter(s => s.riskLevel === 'medium').length },
    { name: 'High', count: scans.filter(s => s.riskLevel === 'high').length },
    { name: 'Critical', count: scans.filter(s => s.riskLevel === 'critical').length },
  ];


  const confidenceTrendData = [...scans]
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    .map((scan, index) => ({
      scan: `#${index + 1}`,
      time: format(new Date(scan.timestamp), 'MMM dd HH:mm'),
      confidence: Number((scan.confidence * 100).toFixed(1)),
      verdict: scan.verdict,
    }));

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-zinc-500">Loading analytics...</div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-semibold mb-2">Threat Analytics Dashboard</h1>
          <p className="text-sm text-zinc-500">
            Real-time security metrics and threat intelligence
          </p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Activity className="w-5 h-5 text-blue-500" />
              </div>
            </div>
            <p className="text-3xl font-semibold mb-1">{scansToday.length}</p>
            <p className="text-sm text-zinc-500">Scans Today</p>
          </Card>

          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-500" />
              </div>
            </div>
            <p className="text-3xl font-semibold mb-1 text-red-500">{phishingToday.length}</p>
            <p className="text-sm text-zinc-500">Phishing Detected</p>
          </Card>

          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                <Shield className="w-5 h-5 text-green-500" />
              </div>
            </div>
            <p className="text-3xl font-semibold mb-1 text-green-500">
              {scans.length > 0 ? ((scans.filter(s => s.verdict === 'safe').length / scans.length) * 100).toFixed(0) : 0}%
            </p>
            <p className="text-sm text-zinc-500">Safe Messages</p>
          </Card>

          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                <TrendingUp className="w-5 h-5 text-yellow-500" />
              </div>
            </div>
            <p className="text-3xl font-semibold mb-1">{scans.filter(s => s.riskLevel === 'critical').length}</p>
            <p className="text-sm text-zinc-500">Critical Threats</p>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Threat Trend */}
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4">7-Day Threat Trend</h3>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                <XAxis dataKey="date" stroke="#71717a" style={{ fontSize: '12px' }} />
                <YAxis stroke="#71717a" style={{ fontSize: '12px' }} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#18181b', 
                    border: '1px solid #3f3f46',
                    borderRadius: '8px'
                  }}
                />
                <Line type="monotone" dataKey="phishing" stroke="#ef4444" strokeWidth={2} />
                <Line type="monotone" dataKey="suspicious" stroke="#eab308" strokeWidth={2} />
                <Line type="monotone" dataKey="safe" stroke="#22c55e" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          {/* Verdict Distribution */}
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4">Verdict Distribution</h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={verdictData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {verdictData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#18181b', 
                    border: '1px solid #3f3f46',
                    borderRadius: '8px'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-4">
              {verdictData.map((entry, index) => (
                <div key={index} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                  <span className="text-xs text-zinc-400">{entry.name}: {entry.value}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="mb-6">
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4">Confidence Trend per Scan</h3>
            <ResponsiveContainer width="100%" height={260}>
              <LineChart data={confidenceTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                <XAxis dataKey="scan" stroke="#71717a" style={{ fontSize: '12px' }} />
                <YAxis domain={[0, 100]} stroke="#71717a" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#18181b',
                    border: '1px solid #3f3f46',
                    borderRadius: '8px'
                  }}
                  formatter={(value: number) => [`${value}%`, 'Confidence']}
                  labelFormatter={(_, payload) => {
                    const point = payload?.[0]?.payload;
                    return point ? `${point.scan} · ${point.time}` : 'Scan';
                  }}
                />
                <Line type="monotone" dataKey="confidence" stroke="#38bdf8" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Detected Features */}
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4">Top Detected Indicators</h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={topFeatures} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                <XAxis type="number" stroke="#71717a" style={{ fontSize: '12px' }} />
                <YAxis dataKey="name" type="category" stroke="#71717a" style={{ fontSize: '11px' }} width={120} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#18181b', 
                    border: '1px solid #3f3f46',
                    borderRadius: '8px'
                  }}
                />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          {/* Risk Level Distribution */}
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4">Risk Level Distribution</h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={riskData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                <XAxis dataKey="name" stroke="#71717a" style={{ fontSize: '12px' }} />
                <YAxis stroke="#71717a" style={{ fontSize: '12px' }} />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#18181b', 
                    border: '1px solid #3f3f46',
                    borderRadius: '8px'
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskData.map((entry, index) => {
                    let color = '#71717a';
                    if (entry.name === 'Low') color = '#22c55e';
                    if (entry.name === 'Medium') color = '#eab308';
                    if (entry.name === 'High') color = '#f97316';
                    if (entry.name === 'Critical') color = '#ef4444';
                    return <Cell key={`cell-${index}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </div>
      </div>
    </div>
  );
}
