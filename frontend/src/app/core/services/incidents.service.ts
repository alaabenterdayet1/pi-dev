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

        const rawDetails = incident.rawDetails as Record<string, unknown> | undefined;
        const contributions = rawDetails?.['ai_feature_contributions'];
        return {
          score: incident.aiScore,
          decision: incident.decision,
          confidence: incident.classificationConfidence ? Number(incident.classificationConfidence) : incident.confidence,
          featureContributions: contributions && Array.isArray(contributions)
            ? (contributions as Array<{ feature: string; points: number; weight: number }>)
            : [
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

  updateIncidentStatus(id: string, status: Incident['status']): Observable<{ success: boolean; updatedAt?: string }> {
    return this.http.patch<{ message: string; data?: Record<string, unknown> }>(`${this.base}/alerts/${id}/status`, { status }).pipe(
      map((res) => ({
        success: true,
        updatedAt: typeof res?.data?.['alert_status_updated_at'] === 'string'
          ? String(res.data['alert_status_updated_at'])
          : undefined,
      })),
      catchError(() => of({ success: false }))
    );
  }

  private mapAlertToIncident(alert: AlertItem, classification?: ClassificationItem): Incident {
    const mongoId = this.getAlertId(alert);
    const rawSeverity = this.toSeverity(alert);
    const confidenceRaw = this.toConfidenceRaw(alert);
    const targetIp = this.pickFirstString([
      alert.src_ip,
      alert.iris_alert_source,
    ]);
    const userIdentity = this.pickFirstString([
      alert.dst_user,
      alert.dstuser,
      alert.user,
      alert.username,
    ]);
    const agentName = this.pickFirstString([alert.agent_name]);
    const ruleText = this.pickFirstString([alert.rule_description, alert.iris_alert_title]);
    const decoderName = this.pickFirstString([alert.decoder_name]);
    const type = ruleText || (decoderName ? `Decoder: ${decoderName}` : 'Security Alert');
    const asset = this.pickFirstString([
      agentName,
      targetIp,
      userIdentity,
      this.pickFirstString([alert.log_program]),
    ]) || 'Asset non renseigne en DB';

    const classificationSeverity = String(alert.ai_classification ?? classification?.severity ?? '').trim();
    const aiScore = this.toScore(alert, rawSeverity);
    const scoreSeverity = this.scoreToSeverity(aiScore);
    const sourceSeverity = this.normalizeSeverity(classificationSeverity) ?? this.normalizeSeverity(alert.ai_classification) ?? rawSeverity;
    const mergedSeverity = this.maxSeverity(sourceSeverity, scoreSeverity);
    const classificationConfidence = alert.ai_confidence !== undefined && alert.ai_confidence !== null
      ? String(alert.ai_confidence)
      : classification?.confidence !== undefined && classification?.confidence !== null
        ? String(classification.confidence)
        : undefined;

    return {
      id: mongoId,
      severity: mergedSeverity,
      classificationSeverity,
      targetIp,
      type,
      asset,
      aiScore,
      decision: this.toDecision(alert, mergedSeverity),
      confidence: alert.ai_confidence ?? Math.round(confidenceRaw * 100),
      classificationConfidence,
      confidenceRaw,
      status: this.toStatus(alert),
      mttd: this.toMttd(alert),
      detectedAt: this.toDetectedAt(alert),
      assignee: userIdentity,
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

  private scoreToSeverity(score: number): Incident['severity'] {
    if (score >= 85) return 'CRITICAL';
    if (score >= 65) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  private maxSeverity(a: Incident['severity'], b: Incident['severity']): Incident['severity'] {
    const order: Incident['severity'][] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return order[Math.max(order.indexOf(a), order.indexOf(b))];
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
    if (aiDecision === 'ISOLATE' || aiDecision === 'ESCALATE' || aiDecision === 'INVESTIGATE' || aiDecision === 'MONITOR') {
      return aiDecision;
    }

    if (severity === 'CRITICAL') return 'ISOLATE';
    if (severity === 'HIGH') return 'ESCALATE';
    if (severity === 'MEDIUM') return 'INVESTIGATE';
    return 'MONITOR';
  }

  private toScore(alert: AlertItem, severity: Incident['severity']): number {
    if (typeof alert.ai_score === 'number') {
      const score = alert.ai_score <= 1 ? alert.ai_score * 100 : alert.ai_score;
      return Math.max(0, Math.min(100, score));
    }

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
    if ((alert.ai_decision || '').toUpperCase() === 'ESCALATE' || (alert.ai_decision || '').toUpperCase() === 'INVESTIGATE') {
      return 'INVESTIGATING';
    }
    if ((alert.vt_malicious ?? 0) > 0) return 'OPEN';
    return 'OPEN';
  }

  private toMttd(alert: AlertItem): number {
    const provided = this.asFiniteNumber(alert.mttd_minutes);
    if (provided !== null) return Math.max(1, Math.min(240, Math.round(provided * 10) / 10));

    const fired = Number(alert.fired_times ?? 1);
    return Math.max(1, Math.min(60, Math.round((10 / Math.max(1, fired)) * 10) / 10));
  }

  private toDetectedAt(alert: AlertItem): string {
    const raw = alert as Record<string, unknown>;
    const candidates = [
      raw['@timestamp'],
      raw['timestamp'],
      raw['detection_date'],
      raw['detected_at'],
      raw['detected'],
      raw['date'],
      raw['createdAt'],
      raw['created_at'],
    ];

    for (const candidate of candidates) {
      const parsed = this.parseUnknownDate(candidate);
      if (parsed) return parsed.toISOString();
    }

    const idDate = this.parseObjectIdDate(this.getAlertId(alert));
    if (idDate) return idDate.toISOString();

    // Keep deterministic fallback to epoch instead of current system time.
    return new Date(0).toISOString();
  }

  private toIocs(alert: AlertItem): Incident['iocs'] {
    const iocs: Incident['iocs'] = [];
    const ip = this.pickFirstString([alert.src_ip]);
    const mitre = this.pickFirstString([alert.mitre_ids]);
    const taxonomy = this.pickFirstString([alert.cortex_taxonomies]);
    const vtTags = this.pickFirstString([alert.vt_tags]);

    if (ip) iocs.push({ type: 'IP', value: ip });
    if (mitre) iocs.push({ type: 'BEHAVIOR', value: `MITRE ${mitre}` });
    if (taxonomy) iocs.push({ type: 'BEHAVIOR', value: taxonomy });
    if (vtTags) iocs.push({ type: 'BEHAVIOR', value: `VT Tags: ${vtTags}` });
    return iocs;
  }

  private getTargetIp(incident: Incident): string {
    return String(incident.targetIp || incident.rawDetails?.['src_ip'] || '').trim();
  }

  private toTimeline(alert: AlertItem): Incident['timeline'] {
    const timeline: Incident['timeline'] = [
      {
        timestamp: this.toDetectedAt(alert),
        event: alert.iris_alert_title || alert.rule_description || 'Alert generated',
        severity: (alert.vt_malicious ?? 0) > 0 ? 'CRITICAL' : (alert.rule_level ?? 0) >= 8 ? 'WARN' : 'INFO',
      },
    ];

    const statusHistory = Array.isArray(alert.alert_status_history) ? alert.alert_status_history : [];
    for (const item of statusHistory) {
      if (!item || !item.changed_at || !item.status) continue;
      timeline.push({
        timestamp: String(item.changed_at),
        event: `Status changed to ${String(item.status).toUpperCase()}`,
        severity: 'INFO',
      });
    }

    if (alert.alert_status_updated_at && alert.alert_status) {
      timeline.push({
        timestamp: String(alert.alert_status_updated_at),
        event: `Status updated: ${String(alert.alert_status).toUpperCase()}`,
        severity: 'INFO',
      });
    }

    return timeline;
  }

  private parseUnknownDate(value: unknown): Date | null {
    if (value === null || value === undefined) return null;

    if (value instanceof Date && !Number.isNaN(value.getTime())) {
      return value;
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      const ms = value > 1e12 ? value : value * 1000;
      const date = new Date(ms);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed || trimmed.toLowerCase() === 'nan') return null;

      if (/^\d+$/.test(trimmed)) {
        const asNum = Number(trimmed);
        if (Number.isFinite(asNum)) {
          const ms = asNum > 1e12 ? asNum : asNum * 1000;
          const numericDate = new Date(ms);
          if (!Number.isNaN(numericDate.getTime())) return numericDate;
        }
      }

      const parsed = new Date(trimmed);
      return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    if (typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      if (obj['$date']) {
        return this.parseUnknownDate(obj['$date']);
      }
    }

    return null;
  }

  private parseObjectIdDate(id: string): Date | null {
    const normalized = String(id || '').trim();
    if (!/^[a-fA-F0-9]{24}$/.test(normalized)) return null;

    const seconds = Number.parseInt(normalized.slice(0, 8), 16);
    if (!Number.isFinite(seconds)) return null;

    const date = new Date(seconds * 1000);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  private pickFirstString(values: Array<unknown>): string {
    for (const value of values) {
      const cleaned = this.cleanString(value);
      if (cleaned) return cleaned;
    }
    return '';
  }

  private cleanString(value: unknown): string {
    if (value === null || value === undefined) return '';
    const str = String(value).trim();
    if (!str) return '';
    const normalized = str.toLowerCase();
    if (normalized === 'nan' || normalized === 'null' || normalized === 'undefined' || normalized === '-') {
      return '';
    }
    return str;
  }
}
