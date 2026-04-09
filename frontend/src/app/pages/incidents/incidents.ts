import { Component, OnInit, OnDestroy, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
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
export class IncidentsComponent implements OnInit, OnDestroy {
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

  displayedColumns = ['id','severity','type','asset','aiScore','decision','mttd','status','actions'];
  dataSource = new MatTableDataSource<Incident>([]);
  allIncidents: Incident[] = [];
  selectedIncident: Incident | null = null;
  selectedScore: AiScore | null = null;
  actionLoading = false;

  filters = { severity: '', type: '', asset: '', status: '' };
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
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  applyFilters(): void {
    this.dataSource.data = this.allIncidents.filter(i =>
      (!this.filters.severity || i.severity === this.filters.severity) &&
      (!this.filters.type || i.type === this.filters.type) &&
      (!this.filters.asset || i.asset === this.filters.asset) &&
      (!this.filters.status || i.status === this.filters.status)
    );
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
    const headers = 'ID,Severity,Type,Asset,Score,Decision,Status,MTTD\n';
    const rows = this.dataSource.data.map(i => `${i.id},${i.severity},${i.type},${i.asset},${i.aiScore},${i.decision},${i.status},${i.mttd}`).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'historique.csv'; a.click();
  }
}
