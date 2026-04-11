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
  private readonly allowedToolLinks: Record<string, string> = {
    misp: 'http://192.168.1.60',
    cortex: 'http://192.168.1.45:9001',
    wazuh: 'http://192.168.1.36',
    'wazuh agent': 'http://192.168.1.36',
    iris: 'http://192.168.1.35:8000',
    n8n: 'http://192.168.1.85:5678',
    pfsense: 'http://192.168.1.1',
  };
  private readonly displayOrder = ['misp', 'wazuh', 'n8n', 'pfsense', 'cortex', 'iris', 'wazuh agent'];

  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private toolsSvc = inject(ToolsService);

  tools: ToolStatus[] = [];
  loading = false;
  lastUpdated = '';
  private expandedTools = new Set<string>();

  trackByName = (_: number, t: ToolStatus) => t.name;

  ngOnInit(): void { this.load(); }
  ngOnDestroy(): void { this.destroy$.next(); this.destroy$.complete(); }

  load(): void {
    this.loading = true;
    this.toolsSvc.getToolsStatus().pipe(takeUntil(this.destroy$)).subscribe(data => {
      const visibleTools = data.filter(tool => this.getToolUrl(tool.name) !== undefined);
      this.tools = visibleTools.sort((a, b) => this.getSortRank(a.name) - this.getSortRank(b.name));
      this.expandedTools = new Set(
        Array.from(this.expandedTools).filter((name) => this.tools.some((tool) => tool.name === name))
      );
      this.loading = false;
      this.lastUpdated = new Date().toLocaleTimeString('en-GB', { hour12: false });
      this.cdr.markForCheck();
    });
  }

  getStatusColor(status: string): string {
    const map: Record<string,string> = { ONLINE:'#00E396', WARNING:'#FFD700', OFFLINE:'#FF4560', DEGRADED:'#FF8C00' };
    return map[status] ?? '#64748B';
  }

  openTool(toolName: string): void {
    const url = this.getToolUrl(toolName);
    if (!url) {
      console.warn('Unknown tool name:', toolName);
      return;
    }

    window.open(url, '_blank', 'noopener,noreferrer');
  }

  getVisibleMetrics(tool: ToolStatus): ToolStatus['metrics'] {
    if (this.isExpanded(tool.name)) return tool.metrics;
    return tool.metrics.slice(0, 4);
  }

  hasMoreMetrics(tool: ToolStatus): boolean {
    return tool.metrics.length > 4;
  }

  isExpanded(toolName: string): boolean {
    return this.expandedTools.has(toolName);
  }

  toggleDetails(toolName: string): void {
    if (this.expandedTools.has(toolName)) {
      this.expandedTools.delete(toolName);
    } else {
      this.expandedTools.add(toolName);
    }
    this.cdr.markForCheck();
  }

  private getToolUrl(toolName: string): string | undefined {
    const normalized = String(toolName || '').trim().toLowerCase();
    const key = Object.keys(this.allowedToolLinks).find((entry) => normalized === entry || normalized.includes(entry));
    return key ? this.allowedToolLinks[key] : undefined;
  }

  private getSortRank(toolName: string): number {
    const normalized = String(toolName || '').trim().toLowerCase();
    const idx = this.displayOrder.findIndex((entry) => normalized === entry || normalized.includes(entry));
    return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
  }
}
