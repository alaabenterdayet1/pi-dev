import { Component, Input, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-severity-badge',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="badge" [class]="'badge-' + severity.toLowerCase()">{{ severity }}</span>
  `,
  styles: [`
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(255,69,96,0.15); color: #FF4560; border: 1px solid rgba(255,69,96,0.4); }
    .badge-high     { background: rgba(255,140,0,0.15);  color: #FF8C00; border: 1px solid rgba(255,140,0,0.4); }
    .badge-medium   { background: rgba(255,215,0,0.15);  color: #FFD700; border: 1px solid rgba(255,215,0,0.4); }
    .badge-low      { background: rgba(0,227,150,0.15);  color: #00E396; border: 1px solid rgba(0,227,150,0.4); }
  `]
})
export class SeverityBadgeComponent {
  @Input() severity: string = 'LOW';
}
