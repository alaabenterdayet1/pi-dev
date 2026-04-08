import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatSelectModule } from '@angular/material/select';
import { MatSliderModule } from '@angular/material/slider';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { NgApexchartsModule } from 'ng-apexcharts';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { AiScoringService } from '../../core/services/ai-scoring.service';
import { AiScore, ThreatFeatures, ModelMetrics, ScoreDistribution } from '../../core/models/ai-score.model';
import { AiScoreGaugeComponent } from '../../shared/components/ai-score-gauge/ai-score-gauge';

@Component({
  selector: 'app-ai-scoring',
  standalone: true,
  imports: [CommonModule, FormsModule, MatSelectModule, MatSliderModule, MatSlideToggleModule,
    MatInputModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule,
    NgApexchartsModule, AiScoreGaugeComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ai-scoring.html',
  styleUrl: './ai-scoring.css'
})
export class AiScoringComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private aiSvc = inject(AiScoringService);

  features: ThreatFeatures = {
    threatType: 'Ransomware', assetType: 'Patient DB', userRole: 'Doctor',
    alertSeverity: 3, iocPresence: false, historicalIncidents: 5
  };

  threatTypes = ['Ransomware', 'Exfiltration', 'Credentials', 'Port Scan', 'Malware', 'Phishing'];
  assetTypes = ['Patient DB', 'EHR', 'Emergency Workstation', 'IoMT', 'AD Server', 'DMZ'];
  userRoles = ['Doctor', 'Admin', 'Nurse', 'External', 'System'];

  result: AiScore | null = null;
  loading = false;
  metrics: ModelMetrics | null = null;
  distribution: ScoreDistribution | null = null;
  histogramChart: any = {};
  timelineChart: any = {};

  ngOnInit(): void {
    this.aiSvc.getModelMetrics().pipe(takeUntil(this.destroy$)).subscribe(m => {
      this.metrics = m; this.cdr.markForCheck();
    });
    this.aiSvc.getScoreDistribution().pipe(takeUntil(this.destroy$)).subscribe((data: any) => {
      this.distribution = data?.scoreDistribution ?? data;
      this.buildCharts();
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  calculate(): void {
    this.loading = true;
    this.aiSvc.calculateScore(this.features).pipe(takeUntil(this.destroy$)).subscribe(r => {
      this.result = r; this.loading = false; this.cdr.markForCheck();
    });
  }

  getScoreColor(s: number): string { return s >= 70 ? '#FF4560' : s >= 40 ? '#FF8C00' : '#00E396'; }

  private buildCharts(): void {
    if (!this.distribution?.bins?.length) return;
    this.histogramChart = {
      series: [{ name: 'Incidents', data: this.distribution.bins.map(b => b.count) }],
      chart: { type: 'bar', height: 180, background: 'transparent', toolbar: { show: false } },
      xaxis: { categories: this.distribution.bins.map(b => b.label), labels: { style: { colors: '#64748B', fontFamily: 'JetBrains Mono', fontSize: '10px' } } },
      yaxis: { labels: { style: { colors: '#64748B' } } },
      colors: ['#6366F1'],
      plotOptions: { bar: { borderRadius: 4, columnWidth: '70%' } },
      grid: { borderColor: '#1E2D4E' },
      theme: { mode: 'dark' },
      dataLabels: { enabled: false }
    };

    if (this.distribution.timeline?.length) {
      this.timelineChart = {
        series: [{ name: 'Score', data: this.distribution.timeline.map(t => ({ x: new Date(t.timestamp).getTime(), y: t.score })) }],
        chart: { type: 'scatter', height: 180, background: 'transparent', toolbar: { show: false } },
        xaxis: { type: 'datetime', labels: { style: { colors: '#64748B', fontFamily: 'JetBrains Mono', fontSize: '10px' } } },
        yaxis: { min: 0, max: 100, labels: { style: { colors: '#64748B' } } },
        colors: ['#00D4FF'],
        markers: { size: 6 },
        grid: { borderColor: '#1E2D4E' },
        theme: { mode: 'dark' }
      };
    }
  }
}
