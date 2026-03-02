import { openDB, DBSchema, IDBPDatabase } from 'idb';

// Database schema
interface PhishingDB extends DBSchema {
  scans: {
    key: string;
    value: ScanRecord;
    indexes: { 'by-date': Date; 'by-verdict': string; 'by-risk': string };
  };
  settings: {
    key: string;
    value: any;
  };
}

export interface ScanRecord {
  id: string;
  timestamp: Date;
  messageType: 'email' | 'sms' | 'chat' | 'file';
  content: string;
  verdict: 'safe' | 'suspicious' | 'phishing';
  confidence: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  triggeredFeatures: string[];
  explainability?: {
    explanations?: Array<{ feature?: string; value?: number; reason?: string; contribution_percent?: number }>;
    highlighted_lines?: Array<{ line_number: number; line: string; indicators: string[] }>;
    class_percentages?: Record<string, number>;
  };
  operatorDecision?: 'incident' | 'false-positive' | 'pending';
  operator?: string;
}

let dbInstance: IDBPDatabase<PhishingDB> | null = null;

export async function getDB(): Promise<IDBPDatabase<PhishingDB>> {
  if (dbInstance) return dbInstance;

  dbInstance = await openDB<PhishingDB>('phishing-detection-db', 1, {
    upgrade(db) {
      // Create scans store
      const scanStore = db.createObjectStore('scans', { keyPath: 'id' });
      scanStore.createIndex('by-date', 'timestamp');
      scanStore.createIndex('by-verdict', 'verdict');
      scanStore.createIndex('by-risk', 'riskLevel');

      // Create settings store
      db.createObjectStore('settings', { keyPath: 'key' });
    },
  });

  return dbInstance;
}

export async function saveScan(scan: ScanRecord): Promise<void> {
  const db = await getDB();
  await db.add('scans', scan);
}

export async function getAllScans(): Promise<ScanRecord[]> {
  const db = await getDB();
  return db.getAll('scans');
}

export async function getScansByVerdict(verdict: string): Promise<ScanRecord[]> {
  const db = await getDB();
  const index = db.transaction('scans').store.index('by-verdict');
  return index.getAll(verdict);
}

export async function updateScan(id: string, updates: Partial<ScanRecord>): Promise<void> {
  const db = await getDB();
  const scan = await db.get('scans', id);
  if (scan) {
    await db.put('scans', { ...scan, ...updates });
  }
}

export async function deleteScan(id: string): Promise<void> {
  const db = await getDB();
  await db.delete('scans', id);
}

export async function exportScansToCSV(): Promise<string> {
  const scans = await getAllScans();
  
  const headers = ['Timestamp', 'Type', 'Verdict', 'Risk', 'Confidence', 'Features', 'Decision'];
  const rows = scans.map(scan => [
    new Date(scan.timestamp).toISOString(),
    scan.messageType,
    scan.verdict,
    scan.riskLevel,
    (scan.confidence * 100).toFixed(1) + '%',
    scan.triggeredFeatures.join('; '),
    scan.operatorDecision || 'N/A'
  ]);

  const csv = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');

  return csv;
}

export async function getSetting(key: string): Promise<any> {
  const db = await getDB();
  return db.get('settings', key);
}

export async function setSetting(key: string, value: any): Promise<void> {
  const db = await getDB();
  await db.put('settings', { key, value });
}
