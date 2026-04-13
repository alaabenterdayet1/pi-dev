import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { environment } from '../../../environments/environment';
import { AlertItem, AlertsResponse } from '../models/alert.model';

@Injectable({ providedIn: 'root' })
export class AlertsService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  getLatestAlerts(limit = 5): Observable<AlertItem[]> {
    return this.getAllAlerts().pipe(
      map((alerts) => alerts.slice(0, Math.max(1, limit))),
      catchError(() => of([]))
    );
  }

  getAllAlerts(): Observable<AlertItem[]> {
    return this.http.get<AlertsResponse>(`${this.base}/alerts`).pipe(
      map(res => res.data ?? []),
      catchError(() => of([]))
    );
  }
}
