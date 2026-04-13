import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../../environments/environment';

export interface ChatAssistantResponse {
  reply?: string;
  message?: string;
  blocked?: boolean;
}

@Injectable({ providedIn: 'root' })
export class ChatAssistantService {
  private http = inject(HttpClient);
  private base = environment.apiBaseUrl;

  ask(message: string): Observable<ChatAssistantResponse> {
    return this.http
      .post<ChatAssistantResponse>(`${this.base}/chat/assistant`, { message })
      .pipe(
        catchError((error: HttpErrorResponse) =>
          of({
            message:
              error?.error?.message ||
              error?.message ||
              'Le service chatbot est indisponible pour le moment.',
          })
        )
      );
  }
}
