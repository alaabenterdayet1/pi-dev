import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { ToolsService } from '../../core/services/tools.service';
import { ToolStatus } from '../../core/models/tool-status.model';

@Component({
  selector: 'app-tools-status',
  standalone: true,
  imports: [CommonModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './tools-status.html',
  styleUrl: './tools-status.css'
})
export class ToolsStatusComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private toolsSvc = inject(ToolsService);

  tools: ToolStatus[] = [];
  loading = false;
  lastUpdated = '';

  trackByName = (_: number, t: ToolStatus) => t.name;

  ngOnInit(): void { this.load(); }
  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  load(): void {
    this.loading = true;
    this.toolsSvc.getToolsStatus().pipe(takeUntil(this.destroy$)).subscribe(data => {
      this.tools = data;
      this.loading = false;
      this.lastUpdated = new Date().toLocaleTimeString('en-GB', { hour12: false });
      this.cdr.markForCheck();
    });
  }

  getStatusColor(status: string): string {
    const map: Record<string,string> = { ONLINE:'#00E396', WARNING:'#FFD700', OFFLINE:'#FF4560', DEGRADED:'#FF8C00' };
    return map[status] ?? '#64748B';
  }
}
