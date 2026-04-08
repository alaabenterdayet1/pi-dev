import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AiScore, ThreatFeatures, ModelMetrics, ScoreDistribution } from '../models/ai-score.model';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class AiScoringService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  calculateScore(features: ThreatFeatures): Observable<AiScore> {
    return this.http.post<AiScore>(`${this.base}/ai/score`, features).pipe(
      catchError(() => of(this.mockCalculate(features)))
    );
  }

  getModelMetrics(): Observable<ModelMetrics> {
    return this.http.get<ModelMetrics>(`${this.base}/ai/model-metrics`).pipe(
      catchError(() => this.http.get<ModelMetrics>('/assets/mock/ai-model-metrics.json').pipe(
        catchError(() => of({
          accuracy: 94.7, falsePositiveRate: 5.3, precisionCritical: 96.1,
          featureImportance: [
            { feature: 'Threat Type', importance: 35 },
            { feature: 'Asset Type', importance: 28 },
            { feature: 'IOC Presence', importance: 18 },
            { feature: 'Alert Severity', importance: 12 },
            { feature: 'Historical Data', importance: 7 }
          ]
        }))
      ))
    );
  }

  getScoreDistribution(): Observable<ScoreDistribution> {
    return this.http.get<any>('/assets/mock/ai-model-metrics.json').pipe(
      catchError(() => of({ bins: [], timeline: [] }))
    );
  }

  private mockCalculate(f: ThreatFeatures): AiScore {
    const isRansomware = ['Ransomware', 'Exfiltration', 'Malware'].includes(f.threatType);
    const isCriticalAsset = ['Patient DB', 'EHR', 'Emergency Workstation', 'IoMT'].includes(f.assetType);
    const threatPts = isRansomware ? 30 : f.threatType === 'Credentials' ? 15 : 5;
    const assetPts = isCriticalAsset ? 20 : 5;
    const iocPts = f.iocPresence ? 15 : 0;
    const severityPts = f.alertSeverity * 8;
    const histPts = Math.min(f.historicalIncidents * 0.5, 10);
    const confPts = 3;
    const score = Math.min(Math.round(threatPts + assetPts + iocPts + severityPts + histPts + confPts), 100);
    const decision: 'MONITOR' | 'ESCALATE' | 'ISOLATE' = score < 40 ? 'MONITOR' : score <= 70 ? 'ESCALATE' : 'ISOLATE';
    const confidence = Math.min(75 + Math.floor(Math.random() * 20), 99);
    return {
      score, decision, confidence,
      featureContributions: [
        { feature: 'Threat Type', points: threatPts, weight: 35 },
        { feature: 'Asset Type', points: assetPts, weight: 28 },
        { feature: 'IOC Presence', points: iocPts, weight: 18 },
        { feature: 'Alert Severity', points: severityPts, weight: 12 },
        { feature: 'Historical Data', points: Math.round(histPts), weight: 7 }
      ]
    };
  }
}
