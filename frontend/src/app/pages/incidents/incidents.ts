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
        this.snack.open(`Action "${action}" applied to ${this.selectedIncident!.id}`, '✓', { panelClass: 'toast-success' });
        this.cdr.markForCheck();
      });
  }

  getScoreColor(s: number): string { return s >= 70 ? '#FF4560' : s >= 40 ? '#FF8C00' : '#00E396'; }
  trackById = (_: number, i: Incident) => i.id;

  exportCsv(): void {
    const headers = 'ID,Severity,Type,Asset,Score,Decision,Status,MTTD\n';
    const rows = this.dataSource.data.map(i => `${i.id},${i.severity},${i.type},${i.asset},${i.aiScore},${i.decision},${i.status},${i.mttd}`).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'incidents.csv'; a.click();
  }
}
