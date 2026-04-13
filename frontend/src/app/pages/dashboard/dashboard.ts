import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { NgApexchartsModule } from 'ng-apexcharts';
import { Subject, interval } from 'rxjs';
import { takeUntil, switchMap, startWith } from 'rxjs/operators';

import { AlertsService } from '../../core/services/alerts.service';
import { KpiService } from '../../core/services/kpi.service';
import { ToolsService } from '../../core/services/tools.service';
import { AlertItem } from '../../core/models/alert.model';
import { KpiData, ThreatDistribution } from '../../core/models/kpi.model';
import { ToolStatus } from '../../core/models/tool-status.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, NgApexchartsModule, SeverityBadgeComponent, TimeAgoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css'
})
export class DashboardComponent implements OnInit, OnDestroy {
  private readonly hiddenToolTokens = ['n8n'];
  private readonly detailsOrder = [
    '_id',
    'rule_id',
    'rule_level',
    'rule_description',
    'fired_times',
    'rule_groups',
    'mitre_ids',
    'mitre_tactics',
    'mitre_techniques',
    'agent_name',
    'src_ip',
    'src_port',
    'dst_user',
    'log_program',
    'log_location',
    'decoder_name',
    'vt_reputation',
    'vt_malicious',
    'vt_suspicious',
    'vt_undetected',
    'vt_tags',
    'cortex_taxonomies',
    'iris_severity_id',
    'iris_severity_name',
    'iris_alert_title',
    'iris_alert_source',
    'fw_action_type',
    'fw_interface',
    'fw_source_blocked'
  ];

  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private alertsSvc = inject(AlertsService);
  private kpiSvc = inject(KpiService);
  private toolsSvc = inject(ToolsService);

  alerts: AlertItem[] = [];
  allAlerts: AlertItem[] = [];
  selectedAlert: AlertItem | null = null;
  showFullDetails = false;
  kpis: KpiData | null = null;
  threatDist: ThreatDistribution | null = null;
  tools: ToolStatus[] = [];
  donutChart: any = {};
  mttdSparkline: any = {};
  mttrSparkline: any = {};

  trackByAlertId = (_: number, item: AlertItem) => this.getAlertId(item);
  trackByName = (_: number, t: ToolStatus) => t.name;
  trackBySeverity = (_: number, s: { severity: string; count: number }) => s.severity;
  trackByLabel = (_: number, item: { label: string }) => item.label;

  ngOnInit(): void {
    // Poll latest alerts every 15s
    interval(15000).pipe(startWith(0), takeUntil(this.destroy$), switchMap(() => this.alertsSvc.getLatestAlerts(5)))
      .subscribe(data => {
        this.alerts = data;
        if (!this.selectedAlert && data.length) {
          this.selectAlert(data[0]);
        }
        this.cdr.markForCheck();
      });

    this.alertsSvc.getAllAlerts().pipe(takeUntil(this.destroy$)).subscribe(data => {
      this.allAlerts = data;
      this.cdr.markForCheck();
    });

    this.kpiSvc.getKpis().pipe(takeUntil(this.destroy$)).subscribe(k => { this.kpis = k; this.buildSparklines(k); this.cdr.markForCheck(); });
    this.kpiSvc.getThreatDistribution().pipe(takeUntil(this.destroy$)).subscribe(d => {
      this.threatDist = d;
      this.buildDonut(d);
      this.cdr.markForCheck();
    });
    this.toolsSvc.getToolsStatus().pipe(takeUntil(this.destroy$)).subscribe(t => {
      this.tools = t.filter(tool => this.isVisibleTool(tool.name)).slice(0, 8);
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  selectAlert(alert: AlertItem): void {
    this.selectedAlert = alert;
    this.showFullDetails = false;
  }

  toggleFullDetails(): void {
    this.showFullDetails = !this.showFullDetails;
  }

  getStatusColor(status: string): string {
    const map: Record<string,string> = { ONLINE:'#00E396', WARNING:'#FFD700', OFFLINE:'#FF4560', DEGRADED:'#FF8C00' };
    return map[status] ?? '#64748B';
  }

  getAlertId(alert: AlertItem): string {
    if (typeof alert._id === 'string') return alert._id;
    return alert._id?.$oid ?? 'unknown';
  }

  getAlertTitle(alert: AlertItem): string {
    return alert.iris_alert_title || alert.rule_description || 'Alert';
  }

  getAssetIdentity(alert: AlertItem): string {
    const parts = [
      this.getStringField(alert, ['agent_name']),
      this.getStringField(alert, ['src_ip', 'source_ip']),
      this.getStringField(alert, ['dst_user', 'dstuser', 'user', 'username'])
    ].filter(Boolean);

    return parts.length ? parts.join(' | ') : 'N/A';
  }

  getAiScore(alert: AlertItem): number | null {
    const raw = this.getNumberField(alert, ['ai_score', 'ai_risk_score']);
    if (raw === null) return null;

    const normalized = raw <= 1 ? raw * 100 : raw;
    return Math.round(Math.max(0, Math.min(100, normalized)));
  }

  getAiScoreLevel(alert: AlertItem): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const score = this.getAiScore(alert);
    if (score === null) return this.getAlertSeverity(alert);
    if (score >= 85) return 'CRITICAL';
    if (score >= 65) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  getAiScoreText(alert: AlertItem): string {
    const score = this.getAiScore(alert);
    if (score === null) return 'N/A';
    return `${score} (${this.getAiScoreLevel(alert)})`;
  }

  getPriorityRank(alert: AlertItem): 'P1' | 'P2' | 'P3' | 'P4' {
    const score = this.getAiScore(alert) ?? 0;
    if (score >= 85) return 'P1';
    if (score >= 65) return 'P2';
    if (score >= 40) return 'P3';
    return 'P4';
  }

  getDecision(alert: AlertItem): string {
    return String(alert.ai_decision || 'MONITOR').toUpperCase();
  }

  getDecisionExplanation(alert: AlertItem): string {
    const reasons: string[] = [];
    const score = this.getAiScore(alert) ?? 0;
    const fired = this.getNumberField(alert, ['fired_times']) ?? 0;
    const level = this.getNumberField(alert, ['rule_level']) ?? 0;
    const malicious = this.getNumberField(alert, ['vt_malicious']) ?? 0;
    const suspicious = this.getNumberField(alert, ['vt_suspicious']) ?? 0;
    const failedAttempts = this.getNumberField(alert, ['failed_attempts', 'failed_logins', 'auth_failures']) ?? 0;
    const action = this.getStringField(alert, ['fw_action_type']);

    if (score >= 65) reasons.push(`AI score eleve (${score})`);
    if (level >= 10) reasons.push(`rule_level eleve (${level})`);
    if (fired >= 8) reasons.push(`alerte repetee (${fired} occurrences)`);
    if (malicious > 0 || suspicious >= 3) reasons.push(`indicateurs VT suspects (malicious=${malicious}, suspicious=${suspicious})`);
    if (failedAttempts >= 5) reasons.push(`plusieurs echecs d'authentification (${failedAttempts})`);
    if (action.toLowerCase() === 'block') reasons.push('pare-feu deja en mode blocage');

    if (!reasons.length) {
      return 'Decision basee sur un niveau de risque global modere et surveillance continue des indicateurs.';
    }

    return `Decision ${this.getDecision(alert)} car ${reasons.join(', ')}.`;
  }

  getAiExplanation(alert: AlertItem): string {
    const ip = this.getStringField(alert, ['src_ip', 'source_ip']) || 'IP inconnue';
    const behavior = this.getStringField(alert, ['rule_description', 'decoder_name', 'cortex_taxonomies']) || 'comportement non precise';
    const failedAttempts = this.getNumberField(alert, ['failed_attempts', 'failed_logins', 'auth_failures']);
    const attemptsText = failedAttempts !== null
      ? `${failedAttempts} tentatives echouees observees`
      : 'nombre de tentatives echouees non disponible';

    return `Source ${ip}. ${attemptsText}. Comportement detecte: ${behavior}. ${this.getDecisionExplanation(alert)}`;
  }

  getModelInputs(alert: AlertItem): Array<{ label: string; value: string }> {
    return [
      { label: 'Alert Type', value: this.getStringField(alert, ['iris_alert_title', 'rule_description']) || 'N/A' },
      { label: 'Rule ID', value: this.getStringField(alert, ['rule_id']) || 'N/A' },
      { label: 'Rule Level', value: this.getNumberText(alert, ['rule_level']) },
      { label: 'Fired Times', value: this.getNumberText(alert, ['fired_times']) },
      { label: 'Source IP', value: this.getStringField(alert, ['src_ip', 'source_ip']) || 'N/A' },
      { label: 'Source Port', value: this.getStringField(alert, ['src_port']) || 'N/A' },
      { label: 'User', value: this.getStringField(alert, ['dst_user', 'dstuser', 'user', 'username']) || 'N/A' },
      { label: 'Program', value: this.getStringField(alert, ['log_program']) || 'N/A' },
      { label: 'Action', value: this.getStringField(alert, ['fw_action_type']) || 'N/A' }
    ];
  }

  getThreatIntelligence(alert: AlertItem): Array<{ label: string; value: string }> {
    return [
      { label: 'VT Reputation', value: this.getNumberText(alert, ['vt_reputation']) },
      { label: 'VT Malicious', value: this.getNumberText(alert, ['vt_malicious']) },
      { label: 'VT Suspicious', value: this.getNumberText(alert, ['vt_suspicious']) },
      { label: 'VT Undetected', value: this.getNumberText(alert, ['vt_undetected']) },
      { label: 'MISP', value: this.getStringField(alert, ['misp', 'misp_ioc', 'misp_event_id']) || 'N/A' },
      { label: 'Geo IP', value: this.getStringField(alert, ['geo_ip', 'geoip_country', 'geoip']) || 'N/A' },
      { label: 'Taxonomies', value: this.getStringField(alert, ['cortex_taxonomies']) || 'N/A' }
    ];
  }

  getWorkflowSoc(): Array<{ label: string; value: string }> {
    return [
      { label: '1. Wazuh', value: 'Detection & alert generation' },
      { label: '2. n8n', value: 'Orchestration & enrichment trigger' },
      { label: '3. AI', value: 'Scoring, decision, confidence' },
      { label: '4. Cortex', value: 'Analyzer context & IOC enrichment' },
      { label: '5. IRIS', value: 'Case management & analyst workflow' }
    ];
  }

  getTimeline(alert: AlertItem): Array<{ label: string; value: string }> {
    const events: Array<{ label: string; date: Date }> = [];
    const dateFields = [
      { key: 'detected', label: 'Detected' },
      { key: 'detected_at', label: 'Detected At' },
      { key: 'date', label: 'Event Date' },
      { key: 'timestamp', label: 'Timestamp' },
      { key: 'created_at', label: 'Created At' }
    ];

    for (const field of dateFields) {
      const value = this.getRawField(alert, [field.key]);
      const parsed = this.parseDate(value);
      if (parsed) {
        events.push({ label: field.label, date: parsed });
      }
    }

    const idDate = this.getAlertTime(alert);
    if (!Number.isNaN(idDate.getTime())) {
      events.push({ label: 'Mongo Created (ObjectId)', date: idDate });
    }

    const uniq = new Map<string, { label: string; date: Date }>();
    for (const event of events) {
      const key = `${event.label}-${event.date.toISOString()}`;
      if (!uniq.has(key)) uniq.set(key, event);
    }

    return [...uniq.values()]
      .sort((a, b) => a.date.getTime() - b.date.getTime())
      .map(e => ({ label: e.label, value: e.date.toLocaleString() }));
  }

  getLimitations(alert: AlertItem): string[] {
    const limitations: string[] = [];
    const missingCritical = [
      this.getRawField(alert, ['rule_level']) === null,
      this.getRawField(alert, ['fired_times']) === null,
      !this.getStringField(alert, ['src_ip']),
      this.getRawField(alert, ['vt_malicious']) === null && this.getRawField(alert, ['vt_suspicious']) === null
    ].filter(Boolean).length;

    if (missingCritical >= 2) {
      limitations.push('Risque de sous-evaluation: plusieurs champs d entree sont manquants.');
    }
    limitations.push('Faux positifs possibles lorsque le contexte metier n est pas present dans l alerte.');
    limitations.push('Le score depend de la qualite de l enrichissement (VT/MISP/Geo IP).');

    return limitations;
  }

  getAlertSeverity(alert: AlertItem): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const aiClass = String(alert.ai_classification || '').trim().toLowerCase();
    if (aiClass === 'critical') return 'CRITICAL';
    if (aiClass === 'high') return 'HIGH';
    if (aiClass === 'medium') return 'MEDIUM';
    if (aiClass === 'low' || aiClass === 'informational' || aiClass === 'info') return 'LOW';

    const aiScore = Number(alert.ai_risk_score);
    if (Number.isFinite(aiScore)) {
      if (aiScore >= 85) return 'CRITICAL';
      if (aiScore >= 65) return 'HIGH';
      if (aiScore >= 40) return 'MEDIUM';
      return 'LOW';
    }

    const dbSeverity = (alert.severity || '').toLowerCase();
    if (dbSeverity === 'critical') return 'CRITICAL';
    if (dbSeverity === 'high') return 'HIGH';
    if (dbSeverity === 'medium') return 'MEDIUM';
    if (dbSeverity === 'low' || dbSeverity === 'informational' || dbSeverity === 'info') return 'LOW';

    return 'LOW';
  }

  getAlertConfidence(alert: AlertItem): string {
    const aiConfidence = Number(alert.ai_confidence);
    if (Number.isFinite(aiConfidence)) {
      return `${Math.round(aiConfidence)}%`;
    }

    if (alert.confidence === undefined || alert.confidence === null) return 'N/A';
    const raw = Number(alert.confidence);
    if (Number.isFinite(raw)) {
      if (raw <= 1) return `${Math.round(raw * 100)}%`;
      return `${Math.round(raw)}%`;
    }

    const value = String(alert.confidence).trim();
    return value || 'N/A';
  }

  getAlertTime(alert: AlertItem): Date {
    const id = this.getAlertId(alert);
    const ts = Number.parseInt(id.slice(0, 8), 16);
    return Number.isNaN(ts) ? new Date() : new Date(ts * 1000);
  }

  getSeverityCount(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): number {
    const source = this.allAlerts.length ? this.allAlerts : this.alerts;
    return source.filter(a => this.getAlertSeverity(a) === severity).length;
  }

  get maxSeverityCount(): number {
    const counts = [
      this.getSeverityCount('CRITICAL'),
      this.getSeverityCount('HIGH'),
      this.getSeverityCount('MEDIUM'),
      this.getSeverityCount('LOW')
    ];
    return Math.max(1, ...counts);
  }

  get severityStats(): { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; count: number }[] {
    return [
      { severity: 'CRITICAL', count: this.getSeverityCount('CRITICAL') },
      { severity: 'HIGH', count: this.getSeverityCount('HIGH') },
      { severity: 'MEDIUM', count: this.getSeverityCount('MEDIUM') },
      { severity: 'LOW', count: this.getSeverityCount('LOW') }
    ];
  }

  get blockedCount(): number {
    const source = this.allAlerts.length ? this.allAlerts : this.alerts;
    return source.filter(a => (a.fw_action_type || '').toLowerCase() === 'block').length;
  }

  get totalCount(): number {
    return this.allAlerts.length || this.alerts.length;
  }

  get uniqueSources(): number {
    const source = this.allAlerts.length ? this.allAlerts : this.alerts;
    return new Set(source.map(a => a.src_ip).filter(Boolean)).size;
  }

  get detailsButtonLabel(): string {
    return this.showFullDetails ? 'Masquer les détails' : 'Voir tous les détails';
  }

  get allDetailEntries(): Array<{ key: string; label: string; value: string; isLong: boolean }> {
    if (!this.selectedAlert) return [];

    const source = this.selectedAlert as Record<string, unknown>;
    return Object.entries(source)
      .filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== '')
      .map(([key, value]) => {
        const formatted = this.formatDetailValue(key, value);
        return {
          key,
          label: this.toReadableLabel(key),
          value: formatted,
          isLong: formatted.length > 38,
        };
      })
      .sort((a, b) => this.sortDetailKeys(a.key, b.key));
  }

  private sortDetailKeys(a: string, b: string): number {
    const ai = this.detailsOrder.indexOf(a);
    const bi = this.detailsOrder.indexOf(b);
    const aRank = ai === -1 ? Number.MAX_SAFE_INTEGER : ai;
    const bRank = bi === -1 ? Number.MAX_SAFE_INTEGER : bi;

    if (aRank !== bRank) return aRank - bRank;
    return a.localeCompare(b);
  }

  private toReadableLabel(key: string): string {
    return key
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  private formatDetailValue(key: string, value: unknown): string {
    if (key === '_id' && typeof value === 'object' && value !== null) {
      const oid = (value as { $oid?: string }).$oid;
      return oid || 'N/A';
    }

    if (Array.isArray(value)) {
      return value.map(v => String(v)).join(', ');
    }

    if (typeof value === 'object' && value !== null) {
      return Object.entries(value as Record<string, unknown>)
        .map(([k, v]) => `${this.toReadableLabel(k)}: ${String(v)}`)
        .join(' | ');
    }

    return String(value);
  }

  private buildDonut(d: ThreatDistribution): void {
    this.donutChart = {
      series: d.donut.map(x => x.value),
      labels: d.donut.map(x => x.label),
      chart: { type: 'donut', height: 180, background: 'transparent' },
      colors: ['#FF4560','#00D4FF','#6366F1','#FF8C00','#64748B'],
      legend: { position: 'bottom', fontFamily: 'DM Sans', fontSize: '11px', labels: { colors: '#64748B' } },
      dataLabels: { enabled: false },
      plotOptions: { pie: { donut: { size: '65%', labels: { show: true, total: { show: true, label: 'Total', color: '#64748B', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px' } } } } },
      theme: { mode: 'dark' },
      stroke: { colors: ['#0F1629'], width: 2 }
    };
  }

  private buildSparklines(k: KpiData): void {
    const base = { chart: { type: 'line', height: 40, sparkline: { enabled: true }, background: 'transparent' }, stroke: { curve: 'smooth', width: 2 }, theme: { mode: 'dark' }, tooltip: { enabled: false } };
    this.mttdSparkline = { ...base, series: [{ data: k.mttdSparkline }], colors: ['#00D4FF'] };
    this.mttrSparkline = { ...base, series: [{ data: k.mttrSparkline }], colors: ['#6366F1'] };
  }

  private isVisibleTool(toolName: string): boolean {
    const normalized = String(toolName || '').trim().toLowerCase();
    return !this.hiddenToolTokens.some(token => normalized.includes(token));
  }

  private getRawField(alert: AlertItem, keys: string[]): unknown {
    const source = alert as unknown as Record<string, unknown>;
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null) {
        return source[key];
      }
    }
    return null;
  }

  private getStringField(alert: AlertItem, keys: string[]): string {
    const value = this.getRawField(alert, keys);
    if (value === null) return '';
    if (typeof value === 'string') return value.trim();
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    return '';
  }

  private getNumberField(alert: AlertItem, keys: string[]): number | null {
    const value = this.getRawField(alert, keys);
    if (value === null) return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  private getNumberText(alert: AlertItem, keys: string[]): string {
    const value = this.getNumberField(alert, keys);
    if (value === null) return 'N/A';
    return String(value);
  }

  private parseDate(value: unknown): Date | null {
    if (!value) return null;
    const date = new Date(String(value));
    if (Number.isNaN(date.getTime())) return null;
    return date;
  }
}
