import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { Incident } from '../models/incident.model';
import { AiScore } from '../models/ai-score.model';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class IncidentsService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  getIncidents(): Observable<Incident[]> {
    return this.http.get<Incident[]>(`${this.base}/incidents?limit=20&sort=priority`).pipe(
      catchError(() => this.http.get<Incident[]>('/assets/mock/incidents.json'))
    );
  }

  getIncidentById(id: string): Observable<Incident | undefined> {
    return this.getIncidents().pipe(
      map(incidents => incidents.find(i => i.id === id))
    );
  }

  getIncidentScore(id: string): Observable<AiScore> {
    const fallback: AiScore = {
      score: 85,
      decision: 'ISOLATE',
      confidence: 93,
      featureContributions: [
        { feature: 'Threat Type', points: 30, weight: 35 },
        { feature: 'Asset Type', points: 20, weight: 28 },
        { feature: 'IOC Presence', points: 15, weight: 18 },
        { feature: 'Alert Severity', points: 12, weight: 12 },
        { feature: 'Historical Data', points: 8, weight: 7 }
      ]
    };
    return this.http.get<AiScore>(`${this.base}/incidents/${id}/score`).pipe(
      catchError(() => of(fallback))
    );
  }

  respondToIncident(id: string, action: string): Observable<{ success: boolean }> {
    return this.http.post<{ success: boolean }>(
      `${this.base}/incidents/${id}/respond`,
      { action }
    ).pipe(catchError(() => of({ success: true })));
  }
}
