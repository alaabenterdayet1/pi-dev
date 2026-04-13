import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

import { ValidationInsightSection } from '../../../core/utils/validation-guidance.util';

@Component({
  selector: 'app-validation-evidence',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './validation-evidence.html',
  styleUrl: './validation-evidence.css'
})
export class ValidationEvidenceComponent {
  @Input() headline: string = 'VALIDATION COVERAGE';
  @Input() compact: boolean = false;
  @Input() sections: ValidationInsightSection[] = [];

  trackByTitle = (_: number, item: ValidationInsightSection) => item.title;
  trackByLabel = (_: number, item: { label: string }) => item.label;
}
