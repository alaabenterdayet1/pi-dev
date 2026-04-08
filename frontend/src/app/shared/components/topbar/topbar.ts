import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, NavigationEnd, RouterModule } from '@angular/router';
import { Subject } from 'rxjs';
import { filter, takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-topbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './topbar.html',
  styleUrl: './topbar.css'
})
export class TopbarComponent implements OnInit, OnDestroy {
  private destroy$ = new Subject<void>();
  private cdr = inject(ChangeDetectorRef);
  private router = inject(Router);

  currentTime = '';
  pageTitle = 'Dashboard';

  private pageTitles: Record<string, string> = {
    '/dashboard': 'Dashboard',
    '/incidents': 'Incidents',
    '/ai-scoring': 'AI Scoring Center',
    '/tools': 'Tools Status'
  };

  ngOnInit(): void {
    this.updateTime();
    const interval = setInterval(() => {
      this.updateTime();
      this.cdr.markForCheck();
    }, 1000);

    this.router.events.pipe(
      filter(e => e instanceof NavigationEnd),
      takeUntil(this.destroy$)
    ).subscribe((e: any) => {
      const url = e.urlAfterRedirects.split('?')[0];
      this.pageTitle = this.pageTitles[url] ?? 'SOC Platform';
      this.cdr.markForCheck();
    });

    // Set initial title
    const current = this.router.url.split('?')[0];
    this.pageTitle = this.pageTitles[current] ?? 'Dashboard';
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  private updateTime(): void {
    this.currentTime = new Date().toLocaleTimeString('en-GB', { hour12: false });
  }
}
