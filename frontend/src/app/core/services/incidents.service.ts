import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, forkJoin, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { Incident } from '../models/incident.model';
import { AiScore } from '../models/ai-score.model';
import { environment } from '../../../environments/environment';
import { AlertItem, AlertsResponse } from '../models/alert.model';

interface ClassificationItem {
  severity?: string;
  confidence?: string | number;
}

@Injectable({ providedIn: 'root' })
export class IncidentsService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  private readonly fallbackScore: AiScore = {
    score: 40,
    decision: 'MONITOR',
    confidence: 60,
    featureContributions: [
      { feature: 'Alert Severity', points: 12, weight: 30 },
      { feature: 'Fired Times', points: 10, weight: 25 },
      { feature: 'Threat Intelligence', points: 8, weight: 20 },
      { feature: 'Source Reputation', points: 6, weight: 15 },
      { feature: 'Historical Pattern', points: 4, weight: 10 }
    ]
  };

  getIncidents(): Observable<Incident[]> {
    return forkJoin({
      alerts: this.http.get<AlertsResponse>(`${this.base}/alerts`),
      classifications: this.http.get<{ data?: ClassificationItem[] }>(`${this.base}/alerts/classification`),
    }).pipe(
      map(({ alerts, classifications }) => {
        const alertList = alerts.data ?? [];
        const classificationList = classifications.data ?? [];

        return alertList.map((alert, index) => this.mapAlertToIncident(alert, classificationList[index]));
      }),
      catchError(() => this.http.get<Incident[]>('/assets/mock/incidents.json'))
    );
  }

  getIncidentById(id: string): Observable<Incident | undefined> {
    return this.getIncidents().pipe(
      map(incidents => incidents.find(i => i.id === id))
    );
  }

  getIncidentScore(id: string): Observable<AiScore> {
    return this.getIncidentById(id).pipe(
      map((incident) => {
        if (!incident) {
          return this.fallbackScore;
        }

        const decision = incident.decision;
        return {
          score: incident.aiScore,
          decision,
          confidence: incident.confidence,
          featureContributions: [
            { feature: 'Alert Severity', points: Math.min(30, Math.round(incident.aiScore * 0.35)), weight: 35 },
            { feature: 'Fired Times', points: Math.min(20, Math.round(incident.mttd * 2)), weight: 25 },
            { feature: 'Threat Type', points: Math.min(18, Math.round(incident.aiScore * 0.18)), weight: 18 },
            { feature: 'Source Context', points: Math.min(15, Math.round(incident.confidence * 0.12)), weight: 12 },
            { feature: 'Historical Data', points: Math.min(10, Math.round(incident.confidence * 0.1)), weight: 10 }
          ]
        } as AiScore;
      }),
      catchError(() => of(this.fallbackScore))
    );
  }

  respondToIncident(id: string, action: string): Observable<{ success: boolean }> {
    return this.http.post<{ success: boolean }>(
      `${this.base}/incidents/${id}/respond`,
      { action }
    ).pipe(catchError(() => of({ success: true })));
  }

  updateIncidentStatus(id: string, status: Incident['status']): Observable<{ success: boolean }> {
    return this.http.patch<{ message: string }>(`${this.base}/alerts/${id}/status`, { status }).pipe(
      map(() => ({ success: true })),
      catchError(() => of({ success: false }))
    );
  }

  private mapAlertToIncident(alert: AlertItem, classification?: ClassificationItem): Incident {
    const mongoId = this.getAlertId(alert);
    const severity = this.toSeverity(alert);
    const decision = this.toDecision(alert, severity);
    const confidenceRaw = this.toConfidenceRaw(alert);
    const classificationSeverity = String(classification?.severity ?? '').trim();
    const classificationConfidence = classification?.confidence !== undefined && classification?.confidence !== null
      ? String(classification.confidence)
      : undefined;

    return {
      id: mongoId,
      severity,
      classificationSeverity,
      type: alert.rule_description || alert.iris_alert_title || 'Security Alert',
      asset: alert.agent_name || alert.src_ip || 'Unknown asset',
      aiScore: this.toScore(alert, severity),
      decision,
      confidence: Math.round(confidenceRaw * 100),
      classificationConfidence,
      confidenceRaw,
      status: this.toStatus(alert),
      mttd: this.toMttd(alert),
      detectedAt: this.toDetectedAt(alert),
      assignee: alert.dst_user,
      iocs: this.toIocs(alert),
      timeline: this.toTimeline(alert),
      rawDetails: this.toRawDetails(alert, mongoId),
    };
  }

  private toRawDetails(alert: AlertItem, mongoId: string): Record<string, unknown> {
    const raw = { ...alert } as Record<string, unknown>;
    raw['_id'] = mongoId;
    return raw;
  }

  private getAlertId(alert: AlertItem): string {
    if (typeof alert._id === 'string') return alert._id;
    return alert._id?.$oid ?? `rule-${alert.rule_id || 'unknown'}`;
  }

  private toSeverity(alert: AlertItem): Incident['severity'] {
    const dbSeverity = this.normalizeSeverity(alert.severity);
    if (dbSeverity) return dbSeverity;

    const ai = alert.ai_classification;
    if (ai) return ai;

    const named = (alert.iris_severity_name || '').toLowerCase();
    if (named === 'critical') return 'CRITICAL';
    if (named === 'high') return 'HIGH';
    if (named === 'medium') return 'MEDIUM';

    const level = Number(alert.rule_level ?? 0);
    if (level >= 12) return 'CRITICAL';
    if (level >= 8) return 'HIGH';
    if (level >= 5) return 'MEDIUM';
    return 'LOW';
  }

  private normalizeSeverity(value: unknown): Incident['severity'] | null {
    const sev = String(value ?? '').trim().toUpperCase();
    if (sev === 'CRITICAL') return 'CRITICAL';
    if (sev === 'HIGH') return 'HIGH';
    if (sev === 'MEDIUM') return 'MEDIUM';
    if (sev === 'LOW') return 'LOW';
    return null;
  }

  private toConfidenceRaw(alert: AlertItem): number {
    const dbConfidence = this.asFiniteNumber(alert.confidence);
    if (dbConfidence !== null) {
      if (dbConfidence <= 1) return Math.max(0, Math.min(1, dbConfidence));
      return Math.max(0, Math.min(1, dbConfidence / 100));
    }

    const aiConfidence = this.asFiniteNumber(alert.ai_confidence);
    if (aiConfidence !== null) {
      if (aiConfidence <= 1) return Math.max(0, Math.min(1, aiConfidence));
      return Math.max(0, Math.min(1, aiConfidence / 100));
    }

    return 0.7;
  }

  private asFiniteNumber(value: unknown): number | null {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }

  private toDecision(alert: AlertItem, severity: Incident['severity']): Incident['decision'] {
    const aiDecision = (alert.ai_decision || '').toUpperCase();
    if (aiDecision === 'ISOLATE' || aiDecision === 'ESCALATE' || aiDecision === 'MONITOR') {
      return aiDecision;
    }
    if (aiDecision === 'INVESTIGATE') return 'ESCALATE';

    if (severity === 'CRITICAL') return 'ISOLATE';
    if (severity === 'HIGH') return 'ESCALATE';
    return 'MONITOR';
  }

  private toScore(alert: AlertItem, severity: Incident['severity']): number {
    if (typeof alert.ai_risk_score === 'number') return Math.max(0, Math.min(100, alert.ai_risk_score));

    const level = Number(alert.rule_level ?? 0);
    const fired = Number(alert.fired_times ?? 0);
    const base = level * 6 + Math.min(25, fired * 2);
    const floor = severity === 'CRITICAL' ? 85 : severity === 'HIGH' ? 65 : severity === 'MEDIUM' ? 40 : 15;
    return Math.max(floor, Math.min(100, Math.round(base)));
  }

  private toStatus(alert: AlertItem): Incident['status'] {
    if (alert.alert_status === 'OPEN' || alert.alert_status === 'INVESTIGATING' || alert.alert_status === 'CLOSED') {
      return alert.alert_status;
    }

    const action = (alert.fw_action_type || '').toLowerCase();
    if (action === 'block') return 'INVESTIGATING';
    if ((alert.vt_malicious ?? 0) > 0) return 'OPEN';
    return 'OPEN';
  }

  private toMttd(alert: AlertItem): number {
    const fired = Number(alert.fired_times ?? 1);
    return Math.max(1, Math.min(60, Math.round((10 / Math.max(1, fired)) * 10) / 10));
  }

  private toDetectedAt(alert: AlertItem): string {
    const candidate =
      (alert as Record<string, unknown>)['@timestamp'] ??
      (alert as Record<string, unknown>)['timestamp'] ??
      (alert as Record<string, unknown>)['createdAt'] ??
      (alert as Record<string, unknown>)['created_at'];

    if (typeof candidate === 'string') {
      const parsed = new Date(candidate);
      if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
    }

    return new Date().toISOString();
  }

  private toIocs(alert: AlertItem): Incident['iocs'] {
    const iocs: Incident['iocs'] = [];
    if (alert.src_ip) iocs.push({ type: 'IP', value: alert.src_ip });
    if (alert.mitre_ids) iocs.push({ type: 'BEHAVIOR', value: `MITRE ${alert.mitre_ids}` });
    if (alert.cortex_taxonomies) iocs.push({ type: 'BEHAVIOR', value: alert.cortex_taxonomies });
    return iocs;
  }

  private toTimeline(alert: AlertItem): Incident['timeline'] {
    return [
      {
        timestamp: this.toDetectedAt(alert),
        event: alert.iris_alert_title || alert.rule_description || 'Alert generated',
        severity: (alert.vt_malicious ?? 0) > 0 ? 'CRITICAL' : (alert.rule_level ?? 0) >= 8 ? 'WARN' : 'INFO',
      },
    ];
  }
}
