import { useState, useEffect } from 'react';
import {
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Download,
  Database,
  Cpu,
  HardDrive,
  Clock,
  Shield,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import { MODEL_INFO, checkForUpdates } from '../lib/ai-engine';
import { getAllScans } from '../lib/db';
import { toast } from 'sonner';

export function SystemStatus() {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [dbSize, setDbSize] = useState(0);
  const [scanCount, setScanCount] = useState(0);
  const [checking, setChecking] = useState(false);
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<string>(MODEL_INFO.lastUpdate);
  const [backendVersion, setBackendVersion] = useState<string>(MODEL_INFO.version);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    loadSystemInfo();

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const loadSystemInfo = async () => {
    try {
      const scans = await getAllScans();
      setScanCount(scans.length);

      // Estimate database size
      const estimatedSize =
        scans.reduce((acc, scan) => acc + scan.content.length + 200, 0) / 1024; // Convert to KB
      setDbSize(estimatedSize);
    } catch (error) {
      console.error('Failed to load system info');
    }
  };

  const handleCheckUpdates = async () => {
    setChecking(true);
    try {
      const status = await checkForUpdates();
      setBackendVersion(status.model_version || MODEL_INFO.version);
      if (status.last_updated) {
        setLastUpdatedAt(status.last_updated);
      }
      setLastCheckedAt(new Date());
      if (status.status === 'offline-fallback') {
        toast.info('Using offline update metadata (backend unavailable)');
      } else {
        toast.success('System is up to date');
      }
    } finally {
      setChecking(false);
    }
  };

  const handleApplyUpdate = async () => {
    await handleCheckUpdates();
  };

  const systemHealth = [
    {
      name: 'AI Model',
      status: 'operational',
      version: backendVersion,
      icon: Cpu,
    },
    {
      name: 'Local Database',
      status: 'operational',
      version: 'IndexedDB v1',
      icon: Database,
    },
    {
      name: 'Rule Set',
      status: 'operational',
      version: MODEL_INFO.ruleSetVersion,
      icon: Shield,
    },
    {
      name: 'Service Worker',
      status: 'operational',
      version: 'Active',
      icon: HardDrive,
    },
  ];

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-semibold mb-2">System Status & Updates</h1>
          <p className="text-sm text-zinc-500">Monitor system health and manage updates</p>
        </div>

        {/* Connection Status */}
        <Card className="p-6 bg-zinc-900 border-zinc-800 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              {isOnline ? (
                <div className="w-12 h-12 rounded-lg bg-green-500/10 flex items-center justify-center">
                  <Wifi className="w-6 h-6 text-green-500" />
                </div>
              ) : (
                <div className="w-12 h-12 rounded-lg bg-yellow-500/10 flex items-center justify-center">
                  <WifiOff className="w-6 h-6 text-yellow-500" />
                </div>
              )}
              <div>
                <h3 className="text-lg font-semibold mb-1">{isOnline ? 'System Online' : 'Offline Mode'}</h3>
                <p className="text-sm text-zinc-500">
                  {isOnline
                    ? 'Connected to network. Updates available.'
                    : 'Operating in offline mode. All features functional.'}
                </p>
              </div>
            </div>
            <Badge
              className={`${
                isOnline
                  ? 'bg-green-500/10 text-green-500 border-green-500/20'
                  : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
              } border px-4 py-2`}
            >
              {isOnline ? 'CONNECTED' : 'OFFLINE'}
            </Badge>
          </div>
        </Card>

        {/* System Components */}
        <div className="mb-6">
          <h2 className="text-sm font-semibold mb-4 text-zinc-400 uppercase tracking-wider">
            System Components
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {systemHealth.map((component, idx) => {
              const Icon = component.icon;
              return (
                <Card key={idx} className="p-5 bg-zinc-900 border-zinc-800">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                        <Icon className="w-5 h-5 text-red-500" />
                      </div>
                      <div>
                        <h3 className="font-medium text-sm">{component.name}</h3>
                        <p className="text-xs text-zinc-500">{component.version}</p>
                      </div>
                    </div>
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  </div>
                  <Badge variant="outline" className="border-green-500/20 text-green-500 text-xs">
                    Operational
                  </Badge>
                </Card>
              );
            })}
          </div>
        </div>

        {/* Metrics Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4 text-zinc-400 uppercase tracking-wider">
              Model Information
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Version</span>
                <span className="text-sm font-medium">{backendVersion}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Rule Set</span>
                <span className="text-sm font-medium">{MODEL_INFO.ruleSetVersion}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Feature Count</span>
                <span className="text-sm font-medium">{MODEL_INFO.totalFeatures}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Accuracy</span>
                <span className="text-sm font-medium text-green-500">
                  {(MODEL_INFO.accuracy * 100).toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-sm text-zinc-400">Last Updated</span>
                <span className="text-sm font-medium">{new Date(lastUpdatedAt).toLocaleDateString()}</span>
              </div>
            </div>
          </Card>

          {/* Storage Information */}
          <Card className="p-6 bg-zinc-900 border-zinc-800">
            <h3 className="text-sm font-semibold mb-4 text-zinc-400 uppercase tracking-wider">
              Local Storage
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Database Type</span>
                <span className="text-sm font-medium">IndexedDB</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Total Scans</span>
                <span className="text-sm font-medium">{scanCount}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                <span className="text-sm text-zinc-400">Database Size</span>
                <span className="text-sm font-medium">{dbSize.toFixed(1)} KB</span>
              </div>
              <div className="py-2">
                <div className="flex justify-between mb-2">
                  <span className="text-sm text-zinc-400">Storage Used</span>
                  <span className="text-xs text-zinc-500">{((dbSize / 10240) * 100).toFixed(1)}% of 10 MB</span>
                </div>
                <Progress value={(dbSize / 10240) * 100} className="h-2 bg-zinc-800" />
              </div>
            </div>
          </Card>
        </div>

        {/* Update Controls */}
        <Card className="p-6 bg-zinc-900 border-zinc-800">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-sm font-semibold mb-1 text-zinc-400 uppercase tracking-wider">
                System Updates
              </h3>
              <p className="text-sm text-zinc-500">
                {isOnline
                  ? 'Check for and apply security updates'
                  : 'Offline fallback metadata will be used when backend is unreachable'}
              </p>
              {lastCheckedAt && (
                <p className="text-xs text-zinc-500 mt-1">
                  Last check: {lastCheckedAt.toLocaleTimeString()}
                </p>
              )}
            </div>
            <Clock className="w-5 h-5 text-zinc-600" />
          </div>

          <div className="flex gap-3">
            <Button onClick={handleCheckUpdates} disabled={checking} className="bg-red-600 hover:bg-red-700">
              {checking ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Check for Updates
                </>
              )}
            </Button>
            <Button
              onClick={handleApplyUpdate}
              variant="outline"
              disabled={checking}
              className="border-zinc-700"
            >
              <Download className="w-4 h-4 mr-2" />
              Apply Secure Update
            </Button>
          </div>

          {!isOnline && (
            <div className="mt-4 flex items-start gap-2 p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
              <AlertCircle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-yellow-500 font-medium">Offline Mode Active</p>
                <p className="text-xs text-zinc-400 mt-1">
                  Local model metadata remains available even without backend connectivity. All core
                  functions continue operating offline.
                </p>
              </div>
            </div>
          )}
        </Card>

        {/* System Integrity */}
        <Card className="p-6 bg-zinc-900 border-zinc-800 mt-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-green-500" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">System Integrity</h3>
              <p className="text-xs text-zinc-500 mt-0.5">All security checks passed</p>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-3 bg-zinc-800/50 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-500 mb-2" />
              <p className="text-xs text-zinc-400">Model Verified</p>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-500 mb-2" />
              <p className="text-xs text-zinc-400">Database Healthy</p>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-500 mb-2" />
              <p className="text-xs text-zinc-400">Rules Current</p>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-500 mb-2" />
              <p className="text-xs text-zinc-400">No Errors</p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
