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
    this.toolsSvc.getToolsStatus().pipe(takeUntil(this.destroy$)).subscribe(t => { this.tools = t.slice(0, 8); this.cdr.markForCheck(); });
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

  getAlertSeverity(alert: AlertItem): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    const named = (alert.iris_severity_name || '').toLowerCase();
    if (named === 'critical') return 'CRITICAL';
    if (named === 'high') return 'HIGH';
    if (named === 'medium') return 'MEDIUM';
    if (named === 'low' || named === 'informational' || named === 'info') return 'LOW';

    const level = alert.rule_level ?? 0;
    if (level >= 12) return 'CRITICAL';
    if (level >= 8) return 'HIGH';
    if (level >= 5) return 'MEDIUM';
    return 'LOW';
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

  get selectedAlertJson(): string {
    if (!this.selectedAlert) return '';
    return JSON.stringify(this.selectedAlert, null, 2);
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
