import { Component, OnInit, OnDestroy, AfterViewInit, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatTableModule, MatTableDataSource } from '@angular/material/table';
import { MatSortModule, MatSort } from '@angular/material/sort';
import { MatPaginatorModule, MatPaginator } from '@angular/material/paginator';
import { MatSelectModule } from '@angular/material/select';
import { MatSidenavModule, MatDrawer } from '@angular/material/sidenav';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { IncidentsService } from '../../core/services/incidents.service';
import { Incident } from '../../core/models/incident.model';
import { AiScore } from '../../core/models/ai-score.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge';
import { ValidationEvidenceComponent } from '../../shared/components/validation-evidence/validation-evidence';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';
import { buildIncidentValidationSections, ValidationInsightSection } from '../../core/utils/validation-guidance.util';

@Component({
  selector: 'app-incidents',
  standalone: true,
  imports: [CommonModule, FormsModule, MatTableModule, MatSortModule, MatPaginatorModule,
    MatSelectModule, MatSidenavModule, MatProgressBarModule, MatIconModule, MatButtonModule,
    MatChipsModule, MatProgressSpinnerModule, SeverityBadgeComponent, ValidationEvidenceComponent, TimeAgoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './incidents.html',
  styleUrl: './incidents.css'
})
export class IncidentsComponent implements OnInit, OnDestroy, AfterViewInit {
  private readonly detailOrder = [
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
    'vt_as_owner',
    'cortex_taxonomies',
    'rdns',
    'abuseipdb_score',
    'abuseipdb_total_reports',
    'abuseipdb_last_reported_at',
    'internal_enrichment_status',
    'internal_enrichment_indicator',
    'internal_enrichment_sources',
    'internal_enrichment_summary',
    'internal_enrichment_fetched_at',
    'enrichment_status',
    'enrichment_indicator',
    'enrichment_sources',
    'enrichment_summary',
    'enrichment_fetched_at',
    'external_enrichment_status',
    'external_enrichment_indicator',
    'external_enrichment_sources',
    'external_enrichment_summary',
    'external_enrichment_fetched_at',
    'iris_severity_id',
    'iris_severity_name',
    'iris_alert_title',
    'iris_alert_source',
    'fw_action_type',
    'fw_interface',
    'fw_source_blocked',
    'ai_classification',
    'ai_decision',
    'ai_confidence',
    'ai_risk_score',
    'ai_recommendation',
    'mttr_minutes',
  ];

  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild('detailDrawer') detailDrawer!: MatDrawer;

  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private incidentsSvc = inject(IncidentsService);
  private snack = inject(MatSnackBar);

  displayedColumns = ['arrivalDateTime','severity','confidence','type','asset','aiScore','decision','mttd','mttr','status','actions'];
  dataSource = new MatTableDataSource<Incident>([]);
  allIncidents: Incident[] = [];
  pageSize = 20;
  pageSizeOptions: number[] = [10, 20, 50];
  showAllMode = false;
  selectedIncident: Incident | null = null;
  selectedScore: AiScore | null = null;
  actionLoading = false;

  filters = { severity: '', type: '', asset: '', status: '', ip: '' };
  severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  types: string[] = [];
  assets: string[] = [];
  statuses = ['OPEN', 'INVESTIGATING', 'CLOSED'];

  ngOnInit(): void {
    this.incidentsSvc.getIncidents().pipe(takeUntil(this.destroy$)).subscribe(data => {
      this.allIncidents = data;
      this.types = [...new Set(data.map(d => d.type))];
      this.assets = [...new Set(data.map(d => d.asset))];
      this.applyFilters();
      this.cdr.markForCheck();
    });
  }

  ngAfterViewInit(): void {
    this.dataSource.sort = this.sort;
    this.dataSource.paginator = this.paginator;
    this.refreshPaginationOptions();
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  applyFilters(): void {
    this.dataSource.data = this.allIncidents.filter(i =>
      (!this.filters.severity || this.normalizeSeverityValue(i.classificationSeverity || i.severity) === this.normalizeSeverityValue(this.filters.severity)) &&
      (!this.filters.type || i.type === this.filters.type) &&
      (!this.filters.asset || i.asset === this.filters.asset) &&
      (!this.filters.status || i.status === this.filters.status) &&
      (!this.filters.ip || this.matchesIpFilter(i, this.filters.ip))
    );
    this.dataSource.paginator = this.showAllMode ? null : this.paginator;
    this.refreshPaginationOptions();
    if (this.paginator) this.paginator.firstPage();
    this.cdr.markForCheck();
  }

  showAllHistory(): void {
    this.showAllMode = true;
    this.filters = { severity: '', type: '', asset: '', status: '', ip: '' };
    this.dataSource.data = this.allIncidents;
    this.dataSource.paginator = null;
    this.pageSize = Math.max(1, this.allIncidents.length);
    this.refreshPaginationOptions();
    this.cdr.detectChanges();
  }

  updateStatus(incident: Incident, status: Incident['status']): void {
    if (incident.status === status) return;

    const prev = incident.status;
    incident.status = status;
    if (this.selectedIncident?.id === incident.id) {
      this.selectedIncident.status = status;
    }
    this.applyFilters();

    this.incidentsSvc.updateIncidentStatus(incident.id, status).pipe(takeUntil(this.destroy$)).subscribe(result => {
      if (!result.success) {
        incident.status = prev;
        if (this.selectedIncident?.id === incident.id) {
          this.selectedIncident.status = prev;
        }
        this.applyFilters();
        this.snack.open('Echec de mise a jour du statut', 'x', { panelClass: 'toast-error' });
        return;
      }

      const changedAt = result.updatedAt || new Date().toISOString();
      incident.timeline = [
        {
          timestamp: changedAt,
          event: `Status changed to ${status}`,
          severity: 'INFO',
        },
        ...(incident.timeline || []),
      ];

      if (this.selectedIncident?.id === incident.id) {
        this.selectedIncident.timeline = [
          {
            timestamp: changedAt,
            event: `Status changed to ${status}`,
            severity: 'INFO',
          },
          ...(this.selectedIncident.timeline || []),
        ];
      }

      this.snack.open(`Statut mis a jour: ${status}`, '✓', { panelClass: 'toast-success' });
      this.cdr.markForCheck();
    });
  }

  openDetail(inc: Incident): void {
    this.selectedIncident = inc;
    this.selectedScore = null;
    this.loadIncidentContext(inc.id);
    this.incidentsSvc.getIncidentScore(inc.id).pipe(takeUntil(this.destroy$))
      .subscribe(s => { this.selectedScore = s; this.cdr.markForCheck(); });
    this.detailDrawer.open();
    this.cdr.markForCheck();
  }

  respond(action: string): void {
    if (!this.selectedIncident) return;
    this.actionLoading = true;
    this.incidentsSvc.respondToIncident(this.selectedIncident.id, action).pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        this.actionLoading = false;
        this.snack.open(`Action "${action}" appliquee sur historique ${this.selectedIncident!.id}`, '✓', { panelClass: 'toast-success' });
        this.cdr.markForCheck();
      });
  }

  getScoreColor(s: number): string { return s >= 70 ? '#FF4560' : s >= 40 ? '#FF8C00' : '#00E396'; }
  trackById = (_: number, i: Incident) => i.id;
  trackByLabel = (_: number, item: { label: string }) => item.label;

  getDisplaySeverity(incident: Incident): string {
    return this.normalizeSeverityLabel(incident.classificationSeverity || incident.severity);
  }

  getProfessionalAsset(incident: Incident): string {
    const raw = incident.rawDetails ?? {};
    const parts = [
      this.cleanText(raw['agent_name']),
      this.cleanText(incident.targetIp || raw['src_ip']),
      this.cleanText(raw['dst_user'] || raw['dstuser'] || raw['user'] || raw['username']),
    ].filter(Boolean) as string[];

    return parts.length ? parts.join(' | ') : this.cleanText(incident.asset) || 'Asset non renseigne en DB';
  }

  getPriority(incident: Incident): 'P1' | 'P2' | 'P3' | 'P4' {
    const score = Number(incident.aiScore || 0);
    if (score >= 85) return 'P1';
    if (score >= 65) return 'P2';
    if (score >= 40) return 'P3';
    return 'P4';
  }

  getExplanation(incident: Incident): string {
    const raw = incident.rawDetails ?? {};
    const reasons: string[] = [];
    const level = this.asNumber(raw['rule_level']);
    const fired = this.asNumber(raw['fired_times']);
    const malicious = this.asNumber(raw['vt_malicious']);
    const suspicious = this.asNumber(raw['vt_suspicious']);
    const action = this.cleanText(raw['fw_action_type']).toLowerCase();

    if (incident.aiScore >= 65) reasons.push(`score eleve (${incident.aiScore})`);
    if (level >= 10) reasons.push(`rule_level eleve (${level})`);
    if (fired >= 5) reasons.push(`repetition alerte (${fired})`);
    if (malicious > 0 || suspicious >= 3) reasons.push(`indicateurs TI suspects (m=${malicious}, s=${suspicious})`);
    if (action === 'block') reasons.push('firewall deja en blocage');

    if (!reasons.length) {
      return 'Decision basee sur risque modere, avec surveillance continue et verification contextuelle SOC.';
    }

    return `Decision ${incident.decision} expliquee par ${reasons.join(', ')}.`;
  }

  getModelInputs(incident: Incident): Array<{ label: string; value: string }> {
    const raw = incident.rawDetails ?? {};
    const alertType = this.cleanText(raw['iris_alert_title']) || this.cleanText(raw['rule_description']) || this.cleanText(incident.type) || 'Type non renseigne en DB';
    const ruleId = this.cleanText(raw['rule_id']) || incident.id;
    const sourceIp = this.cleanText(incident.targetIp || raw['src_ip']) || 'IP source non renseignee';
    const sourcePort = this.cleanText(raw['src_port']) || 'Port non fourni';
    const program = this.cleanText(raw['log_program']) || this.cleanText(raw['decoder_name']) || 'Programme non renseigne';
    const action = this.cleanText(raw['fw_action_type']) || 'Action firewall non renseignee';

    return [
      { label: 'Alert Type', value: alertType },
      { label: 'Rule ID', value: ruleId },
      { label: 'Rule Level', value: this.toValue(raw['rule_level']) },
      { label: 'Fired Times', value: this.toValue(raw['fired_times']) },
      { label: 'Rule Groups', value: this.cleanText(raw['rule_groups']) || 'Non renseigne' },
      { label: 'MITRE IDs', value: this.cleanText(raw['mitre_ids']) || 'Non renseigne' },
      { label: 'MITRE Tactics', value: this.cleanText(raw['mitre_tactics']) || 'Non renseigne' },
      { label: 'MITRE Techniques', value: this.cleanText(raw['mitre_techniques']) || 'Non renseigne' },
      { label: 'Firewall Interface', value: this.cleanText(raw['fw_interface']) || 'Non renseigne' },
      { label: 'Blocked Source', value: this.cleanText(raw['fw_source_blocked']) || 'Non renseigne' },
      { label: 'IRIS Source', value: this.cleanText(raw['iris_alert_source']) || 'Non renseigne' },
      { label: 'Program', value: program },
      { label: 'Firewall Action', value: action },
    ];
  }

  getCti(incident: Incident): Array<{ label: string; value: string }> {
    const raw = incident.rawDetails ?? {};
    const vtReputation = this.toValue(raw['vt_reputation']);
    const vtMalicious = this.toValue(raw['vt_malicious']);
    const vtSuspicious = this.toValue(raw['vt_suspicious']);
    const vtUndetected = this.toValue(raw['vt_undetected']);
    const vtTags = this.cleanText(raw['vt_tags']) || 'Aucun tag VT';
    const misp = this.cleanText(raw['misp'] || raw['misp_ioc'] || raw['misp_event_id']) || 'Aucun enrichissement MISP en DB';
    const geoIp = this.cleanText(raw['geo_ip'] || raw['geoip'] || raw['geoip_country']) || 'GeoIP non enrichi';
    const taxonomies = this.cleanText(raw['cortex_taxonomies']) || 'Aucune taxonomie CTI';
    const irisSource = this.cleanText(raw['iris_alert_source']) || 'Source IRIS non renseignee';
    const irisSeverity = this.cleanText(raw['iris_severity_name']) || 'Severite IRIS non renseignee';

    return [
      { label: 'VT Reputation', value: vtReputation },
      { label: 'VT Malicious', value: vtMalicious },
      { label: 'VT Suspicious', value: vtSuspicious },
      { label: 'VT Undetected', value: vtUndetected },
      { label: 'VT Tags', value: vtTags },
      { label: 'VT AS Owner', value: this.cleanText(raw['vt_as_owner']) || 'AS non renseigne' },
      { label: 'MISP', value: misp },
      { label: 'Geo IP', value: geoIp },
      { label: 'Reverse DNS', value: this.cleanText(raw['rdns']) || 'RDNS non resolu' },
      { label: 'AbuseIPDB Score', value: this.toValue(raw['abuseipdb_score']) },
      { label: 'Abuse Reports', value: this.toValue(raw['abuseipdb_total_reports']) },
      { label: 'Taxonomies', value: taxonomies },
      { label: 'IRIS Severity', value: irisSeverity },
      { label: 'IRIS Source', value: irisSource },
      { label: 'Enrichment Status', value: this.cleanText(raw['enrichment_status'] || raw['internal_enrichment_status'] || raw['external_enrichment_status']) || 'DB only' },
      { label: 'Enrichment Sources', value: this.cleanText(raw['enrichment_sources'] || raw['internal_enrichment_sources'] || raw['external_enrichment_sources']) || 'Aucune source externe' },
      { label: 'Enrichment Summary', value: this.cleanText(raw['enrichment_summary'] || raw['internal_enrichment_summary'] || raw['external_enrichment_summary']) || 'Aucun resume externe' },
    ];
  }

  getTimelineProfessional(incident: Incident): Array<{ label: string; value: string }> {
    const raw = incident.rawDetails ?? {};
    const events: Array<{ label: string; date: Date }> = [];

    const fields: Array<{ key: string; label: string }> = [
      { key: '@timestamp', label: 'Detected' },
      { key: 'timestamp', label: 'Timestamp' },
      { key: 'detected', label: 'Detected At' },
      { key: 'detected_at', label: 'Detected At' },
      { key: 'created_at', label: 'Created At' },
      { key: 'date', label: 'Event Date' },
    ];

    for (const field of fields) {
      const value = raw[field.key];
      const parsed = this.parseDate(value);
      if (parsed) events.push({ label: field.label, date: parsed });
    }

    const detectedAt = this.parseDate(incident.detectedAt);
    if (detectedAt) events.push({ label: 'Incident Detected', date: detectedAt });

    for (const item of incident.timeline || []) {
      const parsed = this.parseDate(item.timestamp);
      if (parsed) events.push({ label: item.event, date: parsed });
    }

    const unique = new Map<string, { label: string; date: Date }>();
    for (const event of events) {
      const key = `${event.label}-${event.date.toISOString()}`;
      if (!unique.has(key)) unique.set(key, event);
    }

    return [...unique.values()]
      .sort((a, b) => a.date.getTime() - b.date.getTime())
      .map(event => ({ label: event.label, value: event.date.toLocaleString() }));
  }

  getExternalEnrichmentStatus(incident: Incident): string {
    return this.cleanText(
      incident.rawDetails?.['enrichment_status'] ||
      incident.rawDetails?.['internal_enrichment_status'] ||
      incident.rawDetails?.['external_enrichment_status']
    ) || 'database-only';
  }

  getExternalEnrichmentSummary(incident: Incident): string {
    const summary = this.cleanText(
      incident.rawDetails?.['enrichment_summary'] ||
      incident.rawDetails?.['internal_enrichment_summary'] ||
      incident.rawDetails?.['external_enrichment_summary']
    );
    if (summary) return summary;

    if (this.getExternalEnrichmentStatus(incident) === 'database-sufficient') {
      return 'Threat context is already available in the stored data.';
    }

    return 'No additional external enrichment is currently visible for this incident.';
  }

  getExternalEnrichmentTone(incident: Incident): 'success' | 'warning' | 'neutral' {
    const status = this.getExternalEnrichmentStatus(incident);
    if (status === 'external-fallback' || status === 'database-sufficient') return 'success';
    if (status === 'private-indicator' || status === 'external-unavailable' || status === 'no-indicator') return 'warning';
    return 'neutral';
  }

  getAllDetailEntries(incident: Incident): Array<{ key: string; label: string; value: string; isLong: boolean }> {
    const source = incident.rawDetails ?? {};
    return Object.entries(source)
      .filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== '')
      .map(([key, value]) => {
        const formatted = this.formatDetailValue(value);
        return {
          key,
          label: this.toReadableLabel(key),
          value: formatted,
          isLong: formatted.length > 48,
        };
      })
      .sort((a, b) => this.sortDetailKeys(a.key, b.key));
  }

  get selectedIncidentValidationSections(): ValidationInsightSection[] {
    if (!this.selectedIncident) return [];
    return buildIncidentValidationSections(this.selectedIncident);
  }

  private loadIncidentContext(incidentId: string): void {
    this.incidentsSvc.getIncidentContext(incidentId).pipe(takeUntil(this.destroy$)).subscribe((incident) => {
      if (!incident || !this.selectedIncident || this.selectedIncident.id !== incidentId) return;

      this.selectedIncident = incident;
      this.allIncidents = this.allIncidents.map((item) => item.id === incidentId ? incident : item);
      this.dataSource.data = this.dataSource.data.map((item) => item.id === incidentId ? incident : item);
      this.cdr.markForCheck();
    });
  }

  private sortDetailKeys(a: string, b: string): number {
    const ai = this.detailOrder.indexOf(a);
    const bi = this.detailOrder.indexOf(b);
    const aRank = ai === -1 ? Number.MAX_SAFE_INTEGER : ai;
    const bRank = bi === -1 ? Number.MAX_SAFE_INTEGER : bi;
    if (aRank !== bRank) return aRank - bRank;
    return a.localeCompare(b);
  }

  private normalizeSeverityValue(value: string): string {
    return String(value || '').trim().toUpperCase();
  }

  private normalizeSeverityLabel(value: string): string {
    const normalized = this.normalizeSeverityValue(value);
    if (normalized === 'INFORMATIONAL' || normalized === 'INFO') return 'LOW';
    if (normalized === 'CRITICAL') return 'CRITICAL';
    if (normalized === 'HIGH') return 'HIGH';
    if (normalized === 'MEDIUM') return 'MEDIUM';
    if (normalized === 'LOW') return 'LOW';
    return normalized || 'LOW';
  }

  private matchesIpFilter(incident: Incident, value: string): boolean {
    const filter = String(value || '').trim().toLowerCase();
    if (!filter) return true;

    const targetIp = String((incident.targetIp || incident.rawDetails?.['src_ip'] || '')).toLowerCase();
    return targetIp.includes(filter);
  }

  private toReadableLabel(key: string): string {
    return key
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
  }

  private formatDetailValue(value: unknown): string {
    if (Array.isArray(value)) return value.map(v => String(v)).join(', ');
    if (typeof value === 'object' && value !== null) {
      return Object.entries(value as Record<string, unknown>)
        .map(([k, v]) => `${k}: ${String(v)}`)
        .join(' | ');
    }
    return String(value);
  }

  private toValue(value: unknown): string {
    const clean = this.cleanText(value);
    return clean || 'Non renseigne en DB';
  }

  private parseDate(value: unknown): Date | null {
    if (!value) return null;
    if (typeof value === 'string') {
      const trimmed = value.trim().toLowerCase();
      if (!trimmed || trimmed === 'nan' || trimmed === 'null' || trimmed === 'undefined') return null;
      if (/^\d+$/.test(trimmed)) {
        const n = Number(trimmed);
        const dateFromNum = new Date(n > 1e12 ? n : n * 1000);
        if (!Number.isNaN(dateFromNum.getTime())) return dateFromNum;
      }
    }
    const date = new Date(String(value));
    if (Number.isNaN(date.getTime())) return null;
    return date;
  }

  private cleanText(value: unknown): string {
    if (value === undefined || value === null) return '';
    const str = String(value).trim();
    if (!str) return '';
    const lowered = str.toLowerCase();
    if (lowered === 'nan' || lowered === 'null' || lowered === 'undefined' || lowered === '-') return '';
    return str;
  }

  private asNumber(value: unknown): number {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }

  exportCsv(): void {
    const headers = 'Arrival DateTime,Severity,Confidence,Type,Asset,Score,Decision,Status,MTTD,MTTR\n';
    const rows = this.dataSource.data
      .map(i => `${new Date(i.detectedAt).toLocaleString()},${i.classificationSeverity || i.severity},${i.classificationConfidence || i.confidenceRaw || ''},${i.type},${i.asset},${i.aiScore},${i.decision},${i.status},${i.mttd},${i.mttr}`)
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'historique.csv'; a.click();
  }

  private refreshPaginationOptions(): void {
    const total = this.dataSource.data.length;
    const options = [10, 20, 50];
    if (total > 0) options.push(total);
    this.pageSizeOptions = Array.from(new Set(options)).sort((a, b) => a - b);

    if (this.pageSize > total && total > 0) {
      this.pageSize = total;
    }
  }
}
