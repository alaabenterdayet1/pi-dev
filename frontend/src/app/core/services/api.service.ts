import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  get<T>(path: string, fallback: T): Observable<T> {
    return this.http.get<T>(`${this.base}${path}`).pipe(
      catchError(() => of(fallback))
    );
  }

  post<T>(path: string, body: unknown, fallback: T): Observable<T> {
    return this.http.post<T>(`${this.base}${path}`, body).pipe(
      catchError(() => of(fallback))
    );
  }

  getMock<T>(assetPath: string): Observable<T> {
    return this.http.get<T>(assetPath);
  }
}
