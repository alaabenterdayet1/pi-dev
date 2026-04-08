import { Component, Input, OnChanges, ChangeDetectionStrategy } from '@angular/core';
import { NgApexchartsModule } from 'ng-apexcharts';

@Component({
  selector: 'app-ai-score-gauge',
  standalone: true,
  imports: [NgApexchartsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <apx-chart
      [series]="chartOptions.series"
      [chart]="chartOptions.chart"
      [plotOptions]="chartOptions.plotOptions"
      [labels]="chartOptions.labels"
      [fill]="chartOptions.fill"
      [stroke]="chartOptions.stroke"
      [theme]="chartOptions.theme"
      [grid]="chartOptions.grid"
    ></apx-chart>
  `
})
export class AiScoreGaugeComponent implements OnChanges {
  @Input() score: number = 0;
  @Input() height: number = 200;

  chartOptions: any = {};

  ngOnChanges(): void {
    const color = this.score >= 70 ? '#FF4560' : this.score >= 40 ? '#FF8C00' : '#00E396';
    this.chartOptions = {
      series: [this.score],
      chart: { type: 'radialBar', height: this.height, background: 'transparent', sparkline: { enabled: true } },
      plotOptions: {
        radialBar: {
          startAngle: -135, endAngle: 135,
          hollow: { size: '55%' },
          dataLabels: {
            name: { show: false },
            value: {
              fontSize: '28px', fontFamily: 'JetBrains Mono, monospace',
              color: color, fontWeight: 700,
              formatter: (val: number) => val.toString()
            }
          },
          track: { background: '#1E2D4E' }
        }
      },
      fill: { colors: [color] },
      stroke: { lineCap: 'round' },
      labels: ['Score'],
      theme: { mode: 'dark' },
      grid: { padding: { top: -10 } }
    };
  }
}
