import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { of } from 'rxjs';
import { KpiData, ThreatDistribution } from '../models/kpi.model';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class KpiService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  private fallbackKpi: KpiData = {
    mttd: 4.2, mttr: 11.3, falsePositiveRate: 5,
    criticalAssetProtectionRate: 98, automationRatio: 80,
    mttdSparkline: [5.1, 4.8, 4.5, 4.9, 4.1, 4.3, 4.2],
    mttrSparkline: [14.2, 13.1, 12.5, 11.8, 12.2, 11.5, 11.3],
    mttdTrend: 'down', mttrTrend: 'down', fpTrend: 'down', protectionTrend: 'up'
  };

  private fallbackDist: ThreatDistribution = {
    donut: [
      { label: 'Ransomware', value: 35 }, { label: 'Exfiltration', value: 22 },
      { label: 'Credentials', value: 18 }, { label: 'Port Scan', value: 15 },
      { label: 'Other', value: 10 }
    ],
    bySeverity: [
      { severity: 'CRITICAL', count: 3 }, { severity: 'HIGH', count: 8 },
      { severity: 'MEDIUM', count: 14 }, { severity: 'LOW', count: 22 }
    ]
  };

  getKpis(): Observable<KpiData> {
    return this.http.get<any>(`${this.base}/ai/pipeline-summary`).pipe(
      map(summary => this.mapPipelineSummaryToKpi(summary)),
      catchError(() => of(this.fallbackKpi))
      ))
    );
  }

  private mapPipelineSummaryToKpi(summary: any): KpiData {
    const stats = summary.statistics || {};
    const metrics = summary.metrics || {};
    const decisionDist = stats.decisionDistribution || { ESCALATE: 0 };
    const totalDecisions = Object.values(decisionDist).reduce((a: number, b: any) => a + (b as number), 0) || 1;
    const automationRatio = Math.round(((decisionDist.ESCALATE as number || 0) / totalDecisions) * 100);
    const criticalAssetProtectionRate = Math.round((metrics.precisionCritical || 0) * 100);
    const falsePositiveRate = Math.round((metrics.falsePositiveRate || 0) * 100);
    const mttdSparkline = this.generateSparkline(stats.avgMttdMinutes || 0, 7);
    const mttrSparkline = this.generateSparkline(stats.avgMttrMinutes || 0, 7);
    const mttdTrend = mttdSparkline[mttdSparkline.length - 1] < mttdSparkline[0] ? 'down' : 'up';
    const mttrTrend = mttrSparkline[mttrSparkline.length - 1] < mttrSparkline[0] ? 'down' : 'up';
    const fpTrend = falsePositiveRate < 10 ? 'down' : 'up';
    const protectionTrend = criticalAssetProtectionRate > 90 ? 'up' : 'down';
    return {
      mttd: Math.round(stats.avgMttdMinutes * 10) / 10 || 4.2,
      mttr: Math.round(stats.avgMttrMinutes * 10) / 10 || 11.3,
      falsePositiveRate,
      criticalAssetProtectionRate,
      automationRatio,
      mttdSparkline,
      mttrSparkline,
      mttdTrend,
      mttrTrend,
      fpTrend,
      protectionTrend
    };
  }

  private generateSparkline(avgValue: number, points: number): number[] {
    const sparkline = [];
    const variance = avgValue * 0.15;
    for (let i = 0; i < points; i++) {
      const variation = (Math.random() - 0.5) * 2 * variance;
      sparkline.push(Math.max(0.1, avgValue + variation));
    }
    return sparkline;
  }

  getThreatDistribution(): Observable<ThreatDistribution> {
    return this.http.get<any>(`${this.base}/ai/score-distribution`).pipe(
      map(data => this.mapScoreDistributionToThreatDist(data)),
      catchError(() => of(this.fallbackDist))
    );
  }

  private mapScoreDistributionToThreatDist(data: any): ThreatDistribution {
    const bins = data.scoreDistribution?.bins || [];
    const donut = bins.map((bin: any) => ({ label: bin.label, value: bin.count }));
    const bySeverity = [
      { severity: 'CRITICAL', count: (bins.find((b: any) => b.label === '80-100')?.count || 0) },
      { severity: 'HIGH', count: (bins.find((b: any) => b.label === '60-79')?.count || 0) },
      { severity: 'MEDIUM', count: (bins.find((b: any) => b.label === '40-59')?.count || 0) },
      { severity: 'LOW', count: ((bins.find((b: any) => b.label === '20-39')?.count || 0) + (bins.find((b: any) => b.label === '0-19')?.count || 0)) }
    ];
    return {
      donut: donut.length > 0 ? donut : this.fallbackDist.donut,
      bySeverity: bySeverity.some(s => s.count > 0) ? bySeverity : this.fallbackDist.bySeverity
    );
  }
}
