const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const toNumber = (value, fallback = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

const normalizeSeverityName = (name) => (name || '').toString().trim().toUpperCase();

const classifyAlert = (alert) => {
  const level = toNumber(alert.rule_level, 0);
  const firedTimes = toNumber(alert.fired_times, 0);
  const vtMalicious = toNumber(alert.vt_malicious, 0);
  const vtSuspicious = toNumber(alert.vt_suspicious, 0);
  const irisSeverity = normalizeSeverityName(alert.iris_severity_name);
  const fwAction = (alert.fw_action_type || '').toString().toLowerCase();

  // Weighted risk score inspired by the training features in the Python model.
  let riskScore = 0;
  riskScore += clamp((level / 15) * 40, 0, 40);
  riskScore += clamp((firedTimes / 25) * 20, 0, 20);
  riskScore += clamp((vtMalicious / 10) * 25, 0, 25);
  riskScore += clamp((vtSuspicious / 20) * 10, 0, 10);
  if (fwAction === 'block') riskScore += 5;

  if (irisSeverity === 'CRITICAL') riskScore = Math.max(riskScore, 90);
  if (irisSeverity === 'HIGH') riskScore = Math.max(riskScore, 75);
  if (irisSeverity === 'MEDIUM') riskScore = Math.max(riskScore, 50);
  if (irisSeverity === 'INFORMATIONAL' || irisSeverity === 'LOW') riskScore = Math.max(riskScore, 20);

  const score = Math.round(clamp(riskScore, 0, 100));

  let classification = 'LOW';
  if (score >= 85) classification = 'CRITICAL';
  else if (score >= 65) classification = 'HIGH';
  else if (score >= 40) classification = 'MEDIUM';

  const recommendations = {
    CRITICAL: {
      decision: 'ISOLATE',
      recommendation: 'Isoler l hote impacte, bloquer la source, ouvrir un ticket P1 et escalader au SOC L3 immediatement.'
    },
    HIGH: {
      decision: 'ESCALATE',
      recommendation: 'Bloquer ou limiter la source, renforcer l authentification utilisateur et lancer une investigation prioritaire.'
    },
    MEDIUM: {
      decision: 'INVESTIGATE',
      recommendation: 'Analyser les journaux, verifier l activite utilisateur, surveiller 24h et preparer des regles de detection complementaires.'
    },
    LOW: {
      decision: 'MONITOR',
      recommendation: 'Conserver en surveillance, enrichir le contexte IOC et reevaluer si la frequence augmente.'
    }
  };

  const { decision, recommendation } = recommendations[classification];
  const confidence = clamp(55 + Math.round(score * 0.4), 55, 98);

  return {
    ai_classification: classification,
    ai_decision: decision,
    ai_confidence: confidence,
    ai_risk_score: score,
    ai_recommendation: recommendation,
  };
};

const enrichAlertWithAi = (alertDoc) => {
  const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : alertDoc;
  return {
    ...alert,
    ...classifyAlert(alert),
  };
};

const enrichAlertsWithAi = (alerts) => alerts.map(enrichAlertWithAi);

module.exports = {
  classifyAlert,
  enrichAlertWithAi,
  enrichAlertsWithAi,
};