import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { AiScore, ThreatFeatures, ModelMetrics, ScoreDistribution, PipelineSummary } from '../models/ai-score.model';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class AiScoringService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  calculateScore(features: ThreatFeatures): Observable<AiScore> {
    return this.http.post<AiScore>(`${this.base}/ai/score`, features).pipe(
      catchError(() => of({
        score: 0,
        decision: 'MONITOR' as const,
        confidence: 0,
        featureContributions: []
      } as AiScore))
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
    return this.http.get<any>(`${this.base}/ai/score-distribution`).pipe(
      catchError(() => this.http.get<any>('/assets/mock/ai-model-metrics.json').pipe(
        catchError(() => of({ bins: [], timeline: [] }))
      ))
    );
  }

  getPipelineSummary(): Observable<PipelineSummary> {
    return this.http.get<PipelineSummary>(`${this.base}/ai/pipeline-summary`).pipe(
      catchError(() => of({
        generatedAt: null,
        modelType: 'RandomForestRegressor',
        modelSource: 'pre-trained',
        metrics: {
          modelAccuracy: 0,
          falsePositiveRate: 0,
          precisionCritical: 0,
          mae: 0,
          r2Score: 0,
        },
        statistics: {
          totalAlerts: 0,
          avgMttdMinutes: 0,
          avgMttrMinutes: 0,
          avgAiScore: 0,
          decisionDistribution: {
            ISOLATE: 0,
            ESCALATE: 0,
            INVESTIGATE: 0,
            MONITOR: 0,
          },
        },
        trainingDataset: {
          realRows: 0,
          syntheticRows: 0,
          totalRows: 0,
        },
      }))
    );
  }
}
