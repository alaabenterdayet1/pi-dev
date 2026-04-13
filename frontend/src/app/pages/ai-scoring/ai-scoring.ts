import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatIconModule } from '@angular/material/icon';
import { NgApexchartsModule } from 'ng-apexcharts';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { IncidentsService } from '../../core/services/incidents.service';
import { AiScoringService } from '../../core/services/ai-scoring.service';
import { Incident } from '../../core/models/incident.model';
import { PipelineSummary } from '../../core/models/ai-score.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge';

@Component({
  selector: 'app-ai-scoring',
  standalone: true,
  imports: [CommonModule, MatIconModule, NgApexchartsModule, SeverityBadgeComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ai-scoring.html',
  styleUrls: ['./ai-scoring.css']
})
export class AiScoringComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private incidentsSvc = inject(IncidentsService);
  private aiScoringSvc = inject(AiScoringService);

  incidents: Incident[] = [];
  selectedIncident: Incident | null = null;
  activeSeverity: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  pipelineSummary: PipelineSummary | null = null;

  kpiChart: any = {};
  responseChart: any = {};
  decisionChart: any = {};
  scoreBandsChart: any = {};

  trackByIncident = (_: number, item: Incident) => item.id;

  ngOnInit(): void {
    this.aiScoringSvc.getPipelineSummary().pipe(takeUntil(this.destroy$)).subscribe((summary) => {
      this.pipelineSummary = summary;
      this.buildSummaryCharts();
      this.cdr.markForCheck();
    });

    this.incidentsSvc.getIncidents().pipe(takeUntil(this.destroy$)).subscribe((data) => {
      this.incidents = data.filter((i) => i.severity === 'LOW' || i.severity === 'MEDIUM' || i.severity === 'HIGH');
      this.selectedIncident = this.incidents[0] ?? null;
      this.refreshCharts();
      this.buildSummaryCharts();
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  setSeverityTab(severity: 'LOW' | 'MEDIUM' | 'HIGH'): void {
    this.activeSeverity = severity;
    const first = this.filteredIncidents[0] ?? null;
    if (first) {
      this.selectedIncident = first;
      this.refreshCharts();
    }
    this.cdr.markForCheck();
  }

  selectIncident(incident: Incident): void {
    this.selectedIncident = incident;
    this.refreshCharts();
    this.cdr.markForCheck();
  }

  getScoreColor(s: number): string { return s >= 70 ? '#FF4560' : s >= 40 ? '#FF8C00' : '#00E396'; }

  get filteredIncidents(): Incident[] {
    return this.incidents.filter((i) => i.severity === this.activeSeverity);
  }

  get summaryCards(): Array<{ label: string; value: string; tone: string }> {
    const s = this.pipelineSummary;
    if (!s) return [];

    return [
      { label: 'Model Type', value: s.modelType, tone: '#E2E8F0' },
      { label: 'Model Source', value: s.modelSource, tone: '#94A3B8' },
      { label: 'Accuracy', value: s.metrics.modelAccuracy.toFixed(4), tone: '#00D4FF' },
      { label: 'R² Score', value: s.metrics.r2Score.toFixed(4), tone: '#22D3EE' },
      { label: 'MAE', value: s.metrics.mae.toFixed(2), tone: '#F59E0B' },
      { label: 'FPR', value: s.metrics.falsePositiveRate.toFixed(4), tone: '#FF8C00' },
      { label: 'Precision Critical', value: s.metrics.precisionCritical.toFixed(4), tone: '#00E396' },
      { label: 'Avg AI Score', value: s.statistics.avgAiScore.toFixed(2), tone: '#6366F1' },
    ];
  }

  get scoreBandStats(): Array<{ label: string; value: number }> {
    const scores = this.incidents.map(i => Number(i.aiScore) || 0);
    return [
      { label: 'critical_>=85', value: scores.filter(s => s >= 85).length },
      { label: 'high_65_84', value: scores.filter(s => s >= 65 && s < 85).length },
      { label: 'medium_40_64', value: scores.filter(s => s >= 40 && s < 65).length },
      { label: 'low_<40', value: scores.filter(s => s < 40).length },
      { label: 'min_score', value: scores.length ? Math.min(...scores) : 0 },
      { label: 'max_score', value: scores.length ? Math.max(...scores) : 0 },
    ];
  }

  get lowCount(): number {
    return this.incidents.filter((i) => i.severity === 'LOW').length;
  }

  get mediumCount(): number {
    return this.incidents.filter((i) => i.severity === 'MEDIUM').length;
  }

  get highCount(): number {
    return this.incidents.filter((i) => i.severity === 'HIGH').length;
  }

  get selectedStats(): Array<{ label: string; value: string; tone: string }> {
    if (!this.selectedIncident) return [];
    return [
      { label: 'AI SCORE', value: `${this.selectedIncident.aiScore}`, tone: this.getScoreColor(this.selectedIncident.aiScore) },
      { label: 'CONFIDENCE', value: `${this.selectedIncident.confidence}%`, tone: '#00D4FF' },
      { label: 'DECISION', value: this.selectedIncident.decision, tone: '#6366F1' },
      { label: 'MTTD', value: `${this.selectedIncident.mttd}m`, tone: '#FF8C00' },
      { label: 'MTTR', value: `${this.selectedIncident.mttr}m`, tone: '#FF4560' },
      { label: 'STATUS', value: this.selectedIncident.status, tone: '#00E396' },
    ];
  }

  get hasKpiChart(): boolean {
    return !!this.kpiChart?.series?.length;
  }

  get hasResponseChart(): boolean {
    return !!this.responseChart?.series?.length;
  }

  get selectedDetectedAt(): string {
    if (!this.selectedIncident) return '--';
    return new Date(this.selectedIncident.detectedAt).toLocaleString('fr-FR');
  }

  get selectedType(): string {
    return this.selectedIncident?.type || 'Security Alert';
  }

  get selectedAsset(): string {
    return this.selectedIncident?.asset || 'Unknown asset';
  }

  get selectedIp(): string {
    return this.selectedIncident?.targetIp || '-';
  }

  get selectedPriority(): 'P1' | 'P2' | 'P3' | 'P4' {
    const score = Number(this.selectedIncident?.aiScore || 0);
    if (score >= 85) return 'P1';
    if (score >= 65) return 'P2';
    if (score >= 40) return 'P3';
    return 'P4';
  }

  get selectedExplanation(): string {
    const incident = this.selectedIncident;
    if (!incident) return 'Aucune alerte selectionnee.';

    const raw = incident.rawDetails || {};
    const level = this.toNumber(raw['rule_level']);
    const fired = this.toNumber(raw['fired_times']);
    const malicious = this.toNumber(raw['vt_malicious']);
    const suspicious = this.toNumber(raw['vt_suspicious']);
    const action = String(raw['fw_action_type'] || '').toLowerCase();

    const reasons: string[] = [];
    if (incident.aiScore >= 65) reasons.push(`score eleve (${incident.aiScore})`);
    if (level >= 10) reasons.push(`rule_level eleve (${level})`);
    if (fired >= 5) reasons.push(`repetition importante (${fired})`);
    if (malicious > 0 || suspicious >= 3) reasons.push(`signaux CTI suspects (m=${malicious}, s=${suspicious})`);
    if (action === 'block') reasons.push('action firewall en blocage');

    if (!reasons.length) {
      return 'Decision basee sur risque modere, avec surveillance continue des signaux disponibles.';
    }

    return `Decision ${incident.decision}: ${reasons.join(', ')}.`;
  }

  get selectedInputsSummary(): Array<{ label: string; value: string }> {
    const raw = this.selectedIncident?.rawDetails || {};
    return [
      { label: 'Rule ID', value: this.toText(raw['rule_id']) || this.selectedIncident?.id || '-' },
      { label: 'Rule Level', value: this.toText(raw['rule_level']) || '-' },
      { label: 'Fired Times', value: this.toText(raw['fired_times']) || '-' },
      { label: 'Source IP', value: this.toText(raw['src_ip']) || this.selectedIp },
      { label: 'Program', value: this.toText(raw['log_program']) || this.toText(raw['decoder_name']) || '-' },
      { label: 'Action', value: this.toText(raw['fw_action_type']) || '-' },
    ];
  }

  get selectedCtiSummary(): Array<{ label: string; value: string }> {
    const raw = this.selectedIncident?.rawDetails || {};
    return [
      { label: 'VT Reputation', value: this.toText(raw['vt_reputation']) || '-' },
      { label: 'VT Malicious', value: this.toText(raw['vt_malicious']) || '-' },
      { label: 'VT Suspicious', value: this.toText(raw['vt_suspicious']) || '-' },
      { label: 'MISP', value: this.toText(raw['misp'] || raw['misp_ioc'] || raw['misp_event_id']) || 'non enrichi' },
      { label: 'Geo IP', value: this.toText(raw['geo_ip'] || raw['geoip'] || raw['geoip_country']) || 'non enrichi' },
    ];
  }

  get selectedLimitations(): string[] {
    const raw = this.selectedIncident?.rawDetails || {};
    const limitations: string[] = [];

    const missing = [
      !this.toText(raw['rule_level']),
      !this.toText(raw['fired_times']),
      !this.toText(raw['src_ip']),
      !this.toText(raw['vt_malicious']) && !this.toText(raw['vt_suspicious']),
    ].filter(Boolean).length;

    if (missing >= 2) {
      limitations.push('Plusieurs champs critiques sont absents, le score peut etre sous-estime.');
    }

    limitations.push('Des faux positifs restent possibles sans contexte metier complet.');
    limitations.push('La qualite depend de l enrichissement CTI (VT/MISP/GeoIP).');
    return limitations;
  }

  private refreshCharts(): void {
    if (!this.selectedIncident) {
      this.kpiChart = {};
      this.responseChart = {};
      return;
    }

    const score = this.selectedIncident.aiScore;
    const confidence = this.selectedIncident.confidence;
    const mttd = Number(this.selectedIncident.mttd || 0);
    const mttr = Number(this.selectedIncident.mttr || 0);

    this.kpiChart = {
      series: [
        {
          name: 'KPI',
          data: [score, confidence, Math.max(0, 100 - Math.min(100, mttd * 4)), Math.max(0, 100 - Math.min(100, mttr * 2))]
        }
      ],
      chart: { type: 'bar', height: 260, background: 'transparent', toolbar: { show: false } },
      xaxis: {
        categories: ['AI Score', 'Confidence', 'MTTD Index', 'MTTR Index'],
        labels: { style: { colors: '#64748B', fontFamily: 'JetBrains Mono', fontSize: '10px' } }
      },
      yaxis: { min: 0, max: 100, labels: { style: { colors: '#64748B' } } },
      plotOptions: { bar: { borderRadius: 5, columnWidth: '58%' } },
      colors: ['#00D4FF'],
      dataLabels: { enabled: false },
      grid: { borderColor: '#1E2D4E' },
      theme: { mode: 'dark' }
    };

    this.responseChart = {
      series: [mttd, mttr],
      chart: { type: 'donut', height: 260, background: 'transparent' },
      labels: ['MTTD (min)', 'MTTR (min)'],
      colors: ['#FF8C00', '#FF4560'],
      legend: { labels: { colors: '#94A3B8' } },
      dataLabels: { enabled: true, style: { colors: ['#0F1629'] } },
      stroke: { colors: ['#0F1629'], width: 2 },
      plotOptions: {
        pie: {
          donut: {
            size: '70%',
            labels: {
              show: true,
              total: {
                show: true,
                label: 'Total min',
                formatter: () => `${(mttd + mttr).toFixed(1)}`
              }
            }
          }
        }
      },
      theme: { mode: 'dark' }
    };
  }

  private buildSummaryCharts(): void {
    const summary = this.pipelineSummary;
    if (!summary) {
      this.decisionChart = {};
      this.scoreBandsChart = {};
      return;
    }

    const decision = summary.statistics.decisionDistribution;
    this.decisionChart = {
      series: [decision.ISOLATE, decision.ESCALATE, decision.INVESTIGATE, decision.MONITOR],
      chart: { type: 'donut', height: 280, background: 'transparent' },
      labels: ['ISOLATE', 'ESCALATE', 'INVESTIGATE', 'MONITOR'],
      colors: ['#FF4560', '#FF8C00', '#FFD700', '#00E396'],
      legend: { labels: { colors: '#94A3B8' } },
      stroke: { colors: ['#0F1629'], width: 2 },
      dataLabels: { enabled: true, style: { colors: ['#0F1629'] } },
      theme: { mode: 'dark' }
    };

    const bands = this.scoreBandStats;
    this.scoreBandsChart = {
      series: [{
        name: 'Alerts',
        data: bands.slice(0, 4).map(b => b.value),
      }],
      chart: { type: 'bar', height: 280, background: 'transparent', toolbar: { show: false } },
      xaxis: {
        categories: bands.slice(0, 4).map(b => b.label),
        labels: { style: { colors: '#64748B', fontFamily: 'JetBrains Mono', fontSize: '10px' } }
      },
      yaxis: { labels: { style: { colors: '#64748B' } } },
      plotOptions: { bar: { borderRadius: 5, columnWidth: '58%' } },
      colors: ['#6366F1'],
      dataLabels: { enabled: true },
      grid: { borderColor: '#1E2D4E' },
      theme: { mode: 'dark' }
    };
  }

  private toText(value: unknown): string {
    if (value === undefined || value === null) return '';
    const str = String(value).trim();
    const low = str.toLowerCase();
    if (!str || low === 'nan' || low === 'null' || low === 'undefined' || low === '-') return '';
    return str;
  }

  private toNumber(value: unknown): number {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }
}
