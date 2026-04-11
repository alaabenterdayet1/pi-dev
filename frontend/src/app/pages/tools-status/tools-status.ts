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

  private readonly extraTools: ToolStatus[] = [
    {
      name: 'IRIS',
      role: 'Incident Response Platform',
      network: 'SOC',
      ip: '192.168.1.35',
      status: 'ONLINE',
      icon: 'security',
      metrics: [
        { label: 'Cases Today', value: '14' },
        { label: 'Open Cases', value: '27' },
        { label: 'Pending Tasks', value: '9' },
      ],
    },
    {
      name: 'Wazuh Agent',
      role: 'Endpoint Agent',
      network: 'SOC',
      ip: '192.168.1.36',
      status: 'ONLINE',
      icon: 'memory',
      metrics: [
        { label: 'Agents', value: '8' },
        { label: 'Alerts Today', value: '342' },
        { label: 'Active', value: 'Yes' },
      ],
    },
  ];

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
      const visibleTools = data.filter(tool => this.getToolUrl(tool.name) !== undefined);
      this.tools = this.mergeMissingTools(visibleTools);
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

  private getToolUrl(toolName: string): string | undefined {
    const normalized = String(toolName || '').trim().toLowerCase();
    const key = Object.keys(this.allowedToolLinks).find((entry) => normalized === entry || normalized.includes(entry));
    return key ? this.allowedToolLinks[key] : undefined;
  }

  private mergeMissingTools(tools: ToolStatus[]): ToolStatus[] {
    const existing = new Set(tools.map(tool => this.normalizeToolName(tool.name)));
    const missing = this.extraTools.filter(tool => !existing.has(this.normalizeToolName(tool.name)));
    return [...tools, ...missing];
  }

  private normalizeToolName(toolName: string): string {
    return String(toolName || '').trim().toLowerCase();
  }
}
