import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';
import { environment } from '../../../environments/environment';
import { AlertItem, AlertsResponse } from '../models/alert.model';

interface ClassificationItem {
  severity?: string;
  confidence?: string | number;
}

@Injectable({ providedIn: 'root' })
export class AlertsService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  getLatestAlerts(limit = 5): Observable<AlertItem[]> {
    return this.getAllAlerts().pipe(
      map((alerts) => alerts.slice(0, Math.max(1, limit))),
      catchError(() => of([]))
    );
  }

  getAllAlerts(): Observable<AlertItem[]> {
    return this.http.get<AlertsResponse>(`${this.base}/alerts`).pipe(
      map(res => res.data ?? []),
      switchMap((alerts) => {
        const size = Math.max(1, alerts.length);
        return this.http.get<{ data?: ClassificationItem[] }>(`${this.base}/alerts/classification?limit=${size}`).pipe(
          map((classifications) => this.mergeClassification(alerts, classifications.data ?? [])),
          catchError(() => of(alerts))
        );
      }),
      catchError(() => of([]))
    );
  }

  private mergeClassification(alerts: AlertItem[], classifications: ClassificationItem[]): AlertItem[] {
    return alerts.map((alert, index) => {
      const cls = classifications[index];
      const {
        ai_classification,
        ai_decision,
        ai_confidence,
        ai_risk_score,
        ai_recommendation,
        ...cleanAlert
      } = alert;

      if (!cls) return cleanAlert;

      const severity = String(cls.severity ?? '').trim();
      const confidence = cls.confidence !== undefined && cls.confidence !== null
        ? String(cls.confidence).trim()
        : '';

      return {
        ...cleanAlert,
        severity: severity || cleanAlert.severity,
        confidence: confidence || cleanAlert.confidence,
      };
    });
  }
}
