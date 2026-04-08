import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { NgApexchartsModule } from 'ng-apexcharts';
import { Subject, interval } from 'rxjs';
import { takeUntil, switchMap, startWith } from 'rxjs/operators';

import { IncidentsService } from '../../core/services/incidents.service';
import { KpiService } from '../../core/services/kpi.service';
import { ToolsService } from '../../core/services/tools.service';
import { Incident } from '../../core/models/incident.model';
import { AiScore } from '../../core/models/ai-score.model';
import { KpiData, ThreatDistribution } from '../../core/models/kpi.model';
import { ToolStatus } from '../../core/models/tool-status.model';
import { SeverityBadgeComponent } from '../../shared/components/severity-badge/severity-badge';
import { AiScoreGaugeComponent } from '../../shared/components/ai-score-gauge/ai-score-gauge';
import { TimeAgoPipe } from '../../shared/pipes/time-ago.pipe';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, NgApexchartsModule, SeverityBadgeComponent, AiScoreGaugeComponent, TimeAgoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css'
})
export class DashboardComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private incidentsSvc = inject(IncidentsService);
  private kpiSvc = inject(KpiService);
  private toolsSvc = inject(ToolsService);

  incidents: Incident[] = [];
  selectedIncident: Incident | null = null;
  selectedScore: AiScore | null = null;
  kpis: KpiData | null = null;
  threatDist: ThreatDistribution | null = null;
  tools: ToolStatus[] = [];
  donutChart: any = {};
  mttdSparkline: any = {};
  mttrSparkline: any = {};

  trackById = (_: number, item: Incident) => item.id;
  trackByName = (_: number, t: ToolStatus) => t.name;

  ngOnInit(): void {
    // Polling every 15s
    interval(15000).pipe(startWith(0), takeUntil(this.destroy$), switchMap(() => this.incidentsSvc.getIncidents()))
      .subscribe(data => { this.incidents = data; if (!this.selectedIncident && data.length) this.selectIncident(data[0]); this.cdr.markForCheck(); });

    this.kpiSvc.getKpis().pipe(takeUntil(this.destroy$)).subscribe(k => { this.kpis = k; this.buildSparklines(k); this.cdr.markForCheck(); });
    this.kpiSvc.getThreatDistribution().pipe(takeUntil(this.destroy$)).subscribe(d => { this.threatDist = d; this.buildDonut(d); this.cdr.markForCheck(); });
    this.toolsSvc.getToolsStatus().pipe(takeUntil(this.destroy$)).subscribe(t => { this.tools = t.slice(0, 8); this.cdr.markForCheck(); });
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  selectIncident(inc: Incident): void {
    this.selectedIncident = inc;
    this.incidentsSvc.getIncidentScore(inc.id).pipe(takeUntil(this.destroy$))
      .subscribe(score => { this.selectedScore = score; this.cdr.markForCheck(); });
  }

  getScoreColor(score: number): string {
    return score >= 70 ? '#FF4560' : score >= 40 ? '#FF8C00' : '#00E396';
  }

  getStatusColor(status: string): string {
    const map: Record<string,string> = { ONLINE:'#00E396', WARNING:'#FFD700', OFFLINE:'#FF4560', DEGRADED:'#FF8C00' };
    return map[status] ?? '#64748B';
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
}
