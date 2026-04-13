export interface AiScore {
  score: number;
  decision: 'ISOLATE' | 'ESCALATE' | 'INVESTIGATE' | 'MONITOR';
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

export interface PipelineSummary {
  generatedAt: string | null;
  modelType: string;
  modelSource: string;
  metrics: {
    modelAccuracy: number;
    falsePositiveRate: number;
    precisionCritical: number;
    mae: number;
    r2Score: number;
  };
  statistics: {
    totalAlerts: number;
    avgMttdMinutes: number;
    avgMttrMinutes: number;
    avgAiScore: number;
    decisionDistribution: {
      ISOLATE: number;
      ESCALATE: number;
      INVESTIGATE: number;
      MONITOR: number;
    };
  };
  trainingDataset: {
    realRows: number;
    syntheticRows: number;
    totalRows: number;
  };
}
