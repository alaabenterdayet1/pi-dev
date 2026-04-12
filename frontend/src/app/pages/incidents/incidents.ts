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
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-incidents',
  standalone: true,
  imports: [CommonModule, FormsModule, MatTableModule, MatSortModule, MatPaginatorModule,
    MatSelectModule, MatSidenavModule, MatProgressBarModule, MatIconModule, MatButtonModule,
    MatChipsModule, MatProgressSpinnerModule, SeverityBadgeComponent, TimeAgoPipe],
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
    'cortex_taxonomies',
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
  ];

  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild('detailDrawer') detailDrawer!: MatDrawer;

  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private incidentsSvc = inject(IncidentsService);
  private snack = inject(MatSnackBar);

  displayedColumns = ['arrivalDateTime','severity','confidence','type','asset','aiScore','decision','mttd','status','actions'];
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

      this.snack.open(`Statut mis a jour: ${status}`, '✓', { panelClass: 'toast-success' });
    });
  }

  openDetail(inc: Incident): void {
    this.selectedIncident = inc;
    this.selectedScore = null;
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

  getDisplaySeverity(incident: Incident): string {
    return incident.classificationSeverity || incident.severity;
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

  exportCsv(): void {
    const headers = 'Arrival DateTime,Severity,Confidence,Type,Asset,Score,Decision,Status,MTTD\n';
    const rows = this.dataSource.data
      .map(i => `${new Date(i.detectedAt).toLocaleString()},${i.classificationSeverity || i.severity},${i.classificationConfidence || i.confidenceRaw || ''},${i.type},${i.asset},${i.aiScore},${i.decision},${i.status},${i.mttd}`)
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
