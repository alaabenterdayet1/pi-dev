const fs = require('fs/promises');
const path = require('path');

const REPORT_PATH = path.resolve(__dirname, '..', '..', '..', 'ai-model', 'alert_scoring_report.json');

const featureImportance = [
  { feature: 'Rule Level', importance: 35 },
  { feature: 'Fired Times', importance: 25 },
  { feature: 'VT Malicious', importance: 20 },
  { feature: 'VT Suspicious', importance: 10 },
  { feature: 'IOC / Context', importance: 10 },
];

let reportCache = null;
let reportCacheMtimeMs = 0;

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const readReport = async () => {
  const stat = await fs.stat(REPORT_PATH);
  if (reportCache && stat.mtimeMs === reportCacheMtimeMs) return reportCache;

  const raw = await fs.readFile(REPORT_PATH, 'utf-8');
  reportCache = JSON.parse(raw);
  reportCacheMtimeMs = stat.mtimeMs;
  return reportCache;
};

const normalizeId = (value) => {
  if (!value) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'object' && value.$oid) return String(value.$oid).trim();
  return String(value).trim();
};

const normalizeSeverity = (value) => {
  const severity = String(value || '').trim().toUpperCase();
  if (severity === 'MEDUIM') return 'MEDIUM';
  if (severity === 'INFORMATIONAL' || severity === 'INFO') return 'LOW';
  if (severity === 'CRITICAL' || severity === 'HIGH' || severity === 'MEDIUM' || severity === 'LOW') {
    return severity;
  }
  return value;
};

const buildAlertReportMap = async () => {
  const report = await readReport();
  const alerts = Array.isArray(report.alerts) ? report.alerts : [];
  const byId = new Map();
  const byRuleAndSource = new Map();

  for (const alert of alerts) {
    const id = normalizeId(alert.id);
    if (id) byId.set(id, alert);

    const ruleId = normalizeId(alert.rule_id);
    const srcIp = normalizeId(alert.src_ip);
    if (ruleId || srcIp) {
      byRuleAndSource.set(`${ruleId}::${srcIp}`, alert);
    }
  }

  return { byId, byRuleAndSource };
};

const mapReportToAlert = (alertDoc, reportAlert) => {
  const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
  if (!reportAlert) return alert;

  return {
    ...alert,
    ai_classification: reportAlert.severity_name ? normalizeSeverity(reportAlert.severity_name) : alert.ai_classification,
    ai_decision: reportAlert.ai_decision ?? alert.ai_decision,
    ai_confidence: reportAlert.ai_confidence ?? alert.ai_confidence,
    ai_risk_score: reportAlert.ai_risk_score ?? alert.ai_risk_score,
    ai_recommendation: reportAlert.ai_recommendation ?? alert.ai_recommendation,
    mttd_minutes: reportAlert.mttd_minutes ?? alert.mttd_minutes,
    mttr_minutes: reportAlert.mttr_minutes ?? alert.mttr_minutes,
    severity: normalizeSeverity(reportAlert.severity_name ?? alert.severity),
  };
};

const enrichAlertFromReport = async (alertDoc) => {
  const { byId, byRuleAndSource } = await buildAlertReportMap();
  const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
  const id = normalizeId(alert._id);
  const ruleId = normalizeId(alert.rule_id);
  const srcIp = normalizeId(alert.src_ip);
  const reportAlert = byId.get(id) || byRuleAndSource.get(`${ruleId}::${srcIp}`);
  return mapReportToAlert(alert, reportAlert);
};

const enrichAlertsFromReport = async (alerts) => {
  const { byId, byRuleAndSource } = await buildAlertReportMap();
  return alerts.map((alertDoc) => {
    const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
    const id = normalizeId(alert._id);
    const ruleId = normalizeId(alert.rule_id);
    const srcIp = normalizeId(alert.src_ip);
    const reportAlert = byId.get(id) || byRuleAndSource.get(`${ruleId}::${srcIp}`);
    return mapReportToAlert(alert, reportAlert);
  });
};

const getMetrics = async () => {
  const report = await readReport();
  return {
    accuracy: Number(((report.metrics?.model_accuracy ?? 0) * 100).toFixed(1)),
    falsePositiveRate: Number(((report.metrics?.false_positive_rate ?? 0) * 100).toFixed(1)),
    precisionCritical: Number(((report.metrics?.precision_critical ?? 0) * 100).toFixed(1)),
    featureImportance,
  };
};

const getScoreDistribution = async () => {
  const report = await readReport();
  const alerts = Array.isArray(report.alerts) ? report.alerts : [];
  const scores = alerts
    .map((alert) => Number(alert.ai_risk_score))
    .filter((score) => Number.isFinite(score));

  const binDefs = [
    { label: '0-19', min: 0, max: 19 },
    { label: '20-39', min: 20, max: 39 },
    { label: '40-59', min: 40, max: 59 },
    { label: '60-79', min: 60, max: 79 },
    { label: '80-100', min: 80, max: 100 },
  ];

  const bins = binDefs.map((bin) => ({
    label: bin.label,
    count: scores.filter((score) => score >= bin.min && score <= bin.max).length,
  }));

  const timeline = alerts.map((alert, index) => ({
    timestamp: new Date(Date.now() - (alerts.length - index) * 60 * 60 * 1000).toISOString(),
    score: clamp(Number(alert.ai_risk_score) || 0, 0, 100),
    decision: String(alert.ai_decision || 'MONITOR'),
  }));

  return { bins, timeline };
};

const getPipelineSummary = async () => {
  const report = await readReport();
  const metrics = report.metrics || {};
  const statistics = report.statistics || {};
  const training = report.training_dataset || {};
  const decisionDistribution = statistics.decision_distribution || {};

  return {
    generatedAt: report.metadata?.generated_at || null,
    modelType: report.metadata?.model_type || 'RandomForestRegressor',
    modelSource: report.metadata?.model_source || 'pre-trained',
    metrics: {
      modelAccuracy: Number(metrics.model_accuracy ?? 0),
      falsePositiveRate: Number(metrics.false_positive_rate ?? 0),
      precisionCritical: Number(metrics.precision_critical ?? 0),
      mae: Number(metrics.mae ?? 0),
      r2Score: Number(metrics.r2_score ?? 0),
    },
    statistics: {
      totalAlerts: Number(statistics.total_alerts ?? 0),
      avgMttdMinutes: Number(statistics.avg_mttd_minutes ?? 0),
      avgMttrMinutes: Number(statistics.avg_mttr_minutes ?? 0),
      avgAiScore: Number(statistics.avg_ai_score ?? 0),
      decisionDistribution: {
        ISOLATE: Number(decisionDistribution.ISOLATE ?? 0),
        ESCALATE: Number(decisionDistribution.ESCALATE ?? 0),
        INVESTIGATE: Number(decisionDistribution.INVESTIGATE ?? 0),
        MONITOR: Number(decisionDistribution.MONITOR ?? 0),
      },
    },
    trainingDataset: {
      realRows: Number(training.real_rows ?? 0),
      syntheticRows: Number(training.synthetic_rows ?? 0),
      totalRows: Number(training.total_rows ?? 0),
    },
  };
};

const scoreThreatFeatures = (features) => {
  const threatType = String(features?.threatType || '').toLowerCase();
  const assetType = String(features?.assetType || '').toLowerCase();
  const userRole = String(features?.userRole || '').toLowerCase();
  const alertSeverity = clamp(Number(features?.alertSeverity) || 1, 1, 4);
  const iocPresence = Boolean(features?.iocPresence);
  const historicalIncidents = clamp(Number(features?.historicalIncidents) || 0, 0, 50);

  const threatPts = ['ransomware', 'exfiltration', 'malware'].includes(threatType)
    ? 30
    : threatType === 'credentials'
      ? 18
      : threatType === 'phishing'
        ? 14
        : 8;

  const assetPts = ['patient db', 'ehr', 'emergency workstation', 'iotm'].includes(assetType)
    ? 22
    : assetType === 'ad server'
      ? 16
      : 8;

  const userPts = ['external', 'system'].includes(userRole)
    ? 18
    : userRole === 'admin'
      ? 12
      : userRole === 'doctor' || userRole === 'nurse'
        ? 8
        : 5;

  const severityPts = alertSeverity * 10;
  const iocPts = iocPresence ? 15 : 0;
  const historyPts = Math.min(historicalIncidents * 0.8, 15);

  const score = Math.round(clamp(threatPts + assetPts + userPts + severityPts + iocPts + historyPts, 0, 100));

  let decision = 'MONITOR';
  if (score >= 85) decision = 'ISOLATE';
  else if (score >= 65) decision = 'ESCALATE';
  else if (score >= 40) decision = 'INVESTIGATE';

  const confidence = Math.round(clamp(55 + score * 0.35, 55, 98));

  return {
    score,
    decision,
    confidence,
    featureContributions: [
      { feature: 'Threat Type', points: threatPts, weight: 30 },
      { feature: 'Asset Type', points: assetPts, weight: 22 },
      { feature: 'User Role', points: userPts, weight: 15 },
      { feature: 'Alert Severity', points: severityPts, weight: 20 },
      { feature: 'IOC Presence', points: iocPts, weight: 8 },
      { feature: 'Historical Incidents', points: Math.round(historyPts), weight: 5 },
    ],
  };
};

module.exports = {
  getMetrics,
  getScoreDistribution,
  getPipelineSummary,
  enrichAlertFromReport,
  enrichAlertsFromReport,
  scoreThreatFeatures,
};