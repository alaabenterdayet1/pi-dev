import { AlertItem } from '../models/alert.model';

const clamp = (value: number, min: number, max: number): number => Math.max(min, Math.min(max, value));

const asNumber = (value: unknown): number | null => {
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
};

const getField = (alert: AlertItem, keys: string[]): unknown => {
  const source = alert as unknown as Record<string, unknown>;
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null) {
      return source[key];
    }
  }
  return null;
};

const normalizeMinutes = (value: number, min: number, max: number): number => {
  return Math.round(clamp(value, min, max) * 10) / 10;
};

export const getAlertMttd = (alert: AlertItem): number => {
  const provided = asNumber(getField(alert, ['mttd_minutes']));
  if (provided !== null) {
    return normalizeMinutes(provided, 1, 240);
  }

  const ruleLevel = asNumber(getField(alert, ['rule_level'])) ?? 0;
  const firedTimes = Math.max(1, asNumber(getField(alert, ['fired_times'])) ?? 1);
  const malicious = asNumber(getField(alert, ['vt_malicious'])) ?? 0;
  const suspicious = asNumber(getField(alert, ['vt_suspicious'])) ?? 0;

  const derived = 3.5
    + Math.max(0, 18 - ruleLevel) * 0.18
    + Math.min(8, Math.log2(firedTimes + 1) * 0.75)
    + Math.min(2, malicious * 0.1)
    + Math.min(1.5, suspicious * 0.08);

  return normalizeMinutes(derived, 1, 240);
};

export const getAlertMttr = (alert: AlertItem): number => {
  const provided = asNumber(getField(alert, ['mttr_minutes']));
  if (provided !== null) {
    return normalizeMinutes(provided, 1, 240);
  }

  const mttd = getAlertMttd(alert);
  const firedTimes = Math.max(1, asNumber(getField(alert, ['fired_times'])) ?? 1);
  const decision = String(getField(alert, ['ai_decision']) || '').trim().toUpperCase();
  const severity = String(getField(alert, ['ai_classification', 'severity', 'iris_severity_name']) || '').trim().toUpperCase();
  const action = String(getField(alert, ['fw_action_type']) || '').trim().toLowerCase();
  const failedAttempts = asNumber(getField(alert, ['failed_attempts', 'failed_logins', 'auth_failures'])) ?? 0;

  const severityBonus = severity === 'CRITICAL'
    ? 8
    : severity === 'HIGH'
      ? 5
      : severity === 'MEDIUM'
        ? 3
        : 1;

  const decisionBonus = decision === 'ISOLATE'
    ? 10
    : decision === 'ESCALATE'
      ? 7
      : decision === 'INVESTIGATE'
        ? 4
        : 2;

  const actionBonus = action === 'block' ? 4 : 0;
  const derived = mttd + severityBonus + decisionBonus + actionBonus + Math.min(10, firedTimes * 0.6) + Math.min(6, failedAttempts * 0.7);

  return normalizeMinutes(derived, mttd, 240);
};

export const buildAlertSparkline = (value: number, seed: string, points = 7): number[] => {
  const normalizedSeed = seed || 'alert';
  let hash = 0;
  for (let i = 0; i < normalizedSeed.length; i++) {
    hash = (hash * 31 + normalizedSeed.charCodeAt(i)) >>> 0;
  }

  const amplitude = Math.max(0.2, value * 0.12);
  const series: number[] = [];

  for (let index = 0; index < points; index++) {
    const phase = (hash % 7) + index;
    const variation = Math.sin(phase) * amplitude * 0.6 + Math.cos(phase / 2) * amplitude * 0.4;
    series.push(Math.max(0.1, Math.round((value + variation) * 10) / 10));
  }

  return series;
};