export interface KpiData {
  mttd: number;
  mttr: number;
  falsePositiveRate: number;
  criticalAssetProtectionRate: number;
  automationRatio: number;
  mttdSparkline: number[];
  mttrSparkline: number[];
  mttdTrend: 'up' | 'down';
  mttrTrend: 'up' | 'down';
  fpTrend: 'up' | 'down';
  protectionTrend: 'up' | 'down';
}

export interface ThreatDistribution {
  donut: { label: string; value: number }[];
  bySeverity: { severity: string; count: number }[];
}
