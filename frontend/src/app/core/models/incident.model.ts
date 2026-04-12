export interface Incident {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  classificationSeverity?: string;
  targetIp?: string;
  type: string;
  asset: string;
  aiScore: number;
  decision: 'ISOLATE' | 'ESCALATE' | 'MONITOR';
  confidence: number;
  classificationConfidence?: string;
  confidenceRaw?: number;
  status: 'OPEN' | 'INVESTIGATING' | 'CLOSED';
  mttd: number;
  detectedAt: string;
  iocs?: IOC[];
  timeline?: TimelineEvent[];
  assignee?: string;
  rawDetails?: Record<string, unknown>;
}

export interface IOC {
  type: 'IP' | 'DOMAIN' | 'HASH' | 'BEHAVIOR';
  value: string;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
}
