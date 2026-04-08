import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ToolStatus } from '../models/tool-status.model';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class ToolsService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  getToolsStatus(): Observable<ToolStatus[]> {
    return this.http.get<ToolStatus[]>(`${this.base}/tools/status/all`).pipe(
      catchError(() => this.http.get<ToolStatus[]>('/assets/mock/tools.json'))
    );
  }
}
