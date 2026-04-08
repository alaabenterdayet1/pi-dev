export interface ToolStatus {
  name: string;
  role: string;
  network: string;
  ip?: string;
  status: 'ONLINE' | 'OFFLINE' | 'WARNING' | 'DEGRADED';
  metrics: { label: string; value: string }[];
  icon: string;
  lastChecked?: string;
}
