import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'dashboard',
    loadComponent: () => import('./pages/dashboard/dashboard').then(m => m.DashboardComponent)
  },
  {
    path: 'incidents',
    loadComponent: () => import('./pages/incidents/incidents').then(m => m.IncidentsComponent)
  },
  {
    path: 'ai-scoring',
    loadComponent: () => import('./pages/ai-scoring/ai-scoring').then(m => m.AiScoringComponent)
  },
  {
    path: 'tools',
    loadComponent: () => import('./pages/tools-status/tools-status').then(m => m.ToolsStatusComponent)
  },
  { path: '**', redirectTo: 'dashboard' }
];
