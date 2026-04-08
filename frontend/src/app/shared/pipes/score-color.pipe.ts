import { Pipe, PipeTransform } from '@angular/core';

@Pipe({ name: 'scoreColor', standalone: true })
export class ScoreColorPipe implements PipeTransform {
  transform(score: number): string {
    if (score >= 70) return '#FF4560';
    if (score >= 40) return '#FF8C00';
    return '#00E396';
  }
}
