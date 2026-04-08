export interface AiScore {
  score: number;
  decision: 'ISOLATE' | 'ESCALATE' | 'MONITOR';
  confidence: number;
  featureContributions: FeatureContribution[];
}

export interface FeatureContribution {
  feature: string;
  points: number;
  weight: number;
}

export interface ThreatFeatures {
  threatType: string;
  assetType: string;
  userRole: string;
  alertSeverity: number;
  iocPresence: boolean;
  historicalIncidents: number;
}

export interface ModelMetrics {
  accuracy: number;
  falsePositiveRate: number;
  precisionCritical: number;
  featureImportance: { feature: string; importance: number }[];
}

export interface ScoreDistribution {
  bins: { label: string; count: number }[];
  timeline: { timestamp: string; score: number; decision: string }[];
}
