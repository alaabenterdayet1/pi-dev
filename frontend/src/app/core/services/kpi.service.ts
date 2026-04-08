import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
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
    return this.http.get<KpiData>(`${this.base}/kpis/current`).pipe(
      catchError(() => this.http.get<KpiData>('/assets/mock/kpis.json').pipe(
        catchError(() => of(this.fallbackKpi))
      ))
    );
  }

  getThreatDistribution(): Observable<ThreatDistribution> {
    return this.http.get<ThreatDistribution>(`${this.base}/analytics/threat-distribution`).pipe(
      catchError(() => of(this.fallbackDist))
    );
  }
}
