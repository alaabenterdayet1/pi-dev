export interface Incident {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  type: string;
  asset: string;
  aiScore: number;
  decision: 'ISOLATE' | 'ESCALATE' | 'MONITOR';
  confidence: number;
  status: 'OPEN' | 'INVESTIGATING' | 'CLOSED';
  mttd: number;
  detectedAt: string;
  iocs?: IOC[];
  timeline?: TimelineEvent[];
  assignee?: string;
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
