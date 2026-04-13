const Alert = require('../models/Alert');
const path = require('path');
const fs = require('fs/promises');
const { execFile } = require('child_process');
const { promisify } = require('util');
const {
  enrichAlertFromReport,
  enrichAlertsFromReport,
  scoreThreatFeatures,
} = require('../services/aiScoringService');
const { enrichAlertWithInternalCorrelation } = require('../services/internalCorrelationEnrichmentService');
const { enrichAlertWithExternalContext } = require('../services/externalEnrichmentService');

const execFileAsync = promisify(execFile);

const stripAiFields = (alertDoc) => {
  const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
  return alert;
};

const toArray = (value) => {
  if (Array.isArray(value)) return value.map((entry) => String(entry)).filter(Boolean);
  if (value === undefined || value === null) return [];
  const text = String(value).trim();
  return text ? [text] : [];
};

const mergeEnrichmentView = (alert) => {
  const internalSources = toArray(alert.internal_enrichment_sources);
  const externalSources = toArray(alert.external_enrichment_sources);
  const sources = Array.from(new Set([...internalSources, ...externalSources]));
  const checked = Array.from(new Set([
    ...toArray(alert.internal_enrichment_checked),
    ...toArray(alert.external_enrichment_checked),
  ]));

  const internalStatus = String(alert.internal_enrichment_status || '').trim();
  const externalStatus = String(alert.external_enrichment_status || '').trim();
  const hasInternal = internalSources.length > 0;
  const hasExternal = externalSources.length > 0;

  let status = 'database-only';
  if (hasInternal && hasExternal) status = 'combined-enrichment';
  else if (hasInternal) status = internalStatus || 'internal-correlation';
  else if (hasExternal) status = externalStatus || 'external-fallback';
  else if (internalStatus === 'database-sufficient' || externalStatus === 'database-sufficient') status = 'database-sufficient';
  else if (internalStatus === 'no-indicator' || externalStatus === 'no-indicator') status = 'no-indicator';
  else if (internalStatus === 'private-indicator' || externalStatus === 'private-indicator') status = 'private-indicator';
  else if (internalStatus === 'internal-unavailable') status = 'internal-unavailable';
  else if (externalStatus === 'external-unavailable') status = 'external-unavailable';
  else if (internalStatus) status = internalStatus;
  else if (externalStatus) status = externalStatus;

  const summaryParts = [
    alert.internal_enrichment_summary ? `Internal: ${alert.internal_enrichment_summary}` : '',
    alert.external_enrichment_summary ? `External: ${alert.external_enrichment_summary}` : '',
  ].filter(Boolean);

  return {
    ...alert,
    enrichment_indicator:
      alert.internal_enrichment_indicator ||
      alert.external_enrichment_indicator ||
      alert.src_ip ||
      alert.target_ip ||
      alert.iris_alert_source ||
      '',
    enrichment_status: status,
    enrichment_sources: sources,
    enrichment_checked: checked,
    enrichment_summary: summaryParts.join(' ') || 'No enrichment summary is available.',
    enrichment_fetched_at:
      alert.external_enrichment_fetched_at ||
      alert.internal_enrichment_fetched_at ||
      '',
  };
};

const getLatestAlerts = async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 5, 50));
    const alerts = await Alert.find().sort({ _id: -1 }).limit(limit);
    const sanitizedAlerts = await enrichAlertsFromReport(alerts);

    res.status(200).json({
      count: sanitizedAlerts.length,
      limit,
      data: sanitizedAlerts,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ _id: -1 });
    const sanitizedAlerts = await enrichAlertsFromReport(alerts);

    res.status(200).json({
      count: sanitizedAlerts.length,
      data: sanitizedAlerts,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAlertContextById = async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    const reportEnriched = await enrichAlertFromReport(alert);
    const internalEnriched = await enrichAlertWithInternalCorrelation(reportEnriched);
    const externalEnriched = await enrichAlertWithExternalContext(internalEnriched, {
      force: String(req.query.force || 'false').toLowerCase() === 'true',
    });
    const threatContext = mergeEnrichmentView(externalEnriched);

    res.status(200).json({
      message: 'Alert context loaded successfully',
      data: threatContext,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const classifyAlertById = async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    const ai = await enrichAlertFromReport(alert);
    const calculated = scoreThreatFeatures(alert.toObject());
    const updated = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          ai_classification: ai.ai_classification || calculated.decision,
          ai_decision: ai.ai_decision || calculated.decision,
          ai_confidence: ai.ai_confidence ?? calculated.confidence,
          ai_risk_score: ai.ai_risk_score ?? calculated.score,
          ai_recommendation: ai.ai_recommendation || 'See AI scoring report',
        },
      },
      { new: true }
    );

    res.status(200).json({
      message: 'Alert classified successfully',
      data: await enrichAlertFromReport(updated),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const updateAlertStatus = async (req, res) => {
  try {
    const allowed = ['OPEN', 'INVESTIGATING', 'CLOSED'];
    const nextStatus = String(req.body?.status || '').toUpperCase();

    if (!allowed.includes(nextStatus)) {
      return res.status(400).json({ message: 'Invalid status. Use OPEN, INVESTIGATING, or CLOSED.' });
    }

    const changedAt = new Date().toISOString();
    const updated = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          alert_status: nextStatus,
          alert_status_updated_at: changedAt,
        },
        $push: {
          alert_status_history: {
            status: nextStatus,
            changed_at: changedAt,
          },
        },
      },
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: 'Alert not found' });
    }

    res.status(200).json({
      message: 'Alert status updated successfully',
      data: updated,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const resolveDbNameFromUri = (mongoUri) => {
  if (!mongoUri) return 'HealthcareSoc_db';
  const match = mongoUri.match(/mongodb(?:\+srv)?:\/\/[^/]+\/([^?]+)/i);
  if (!match || !match[1]) return 'HealthcareSoc_db';
  return match[1];
};

const runPythonWithFallback = async (scriptPath, args) => {
  const workspacePython = path.resolve(__dirname, '..', '..', '..', '.venv', 'Scripts', 'python.exe');
  const attempts = [
    { bin: workspacePython, args: [scriptPath, ...args] },
    { bin: process.env.PYTHON_BIN || 'python', args: [scriptPath, ...args] },
    { bin: 'py', args: ['-3', scriptPath, ...args] },
  ];

  let lastError = null;
  for (const attempt of attempts) {
    try {
      const result = await execFileAsync(attempt.bin, attempt.args, {
        cwd: path.resolve(__dirname, '..', '..', '..'),
        timeout: 10 * 60 * 1000,
        maxBuffer: 10 * 1024 * 1024,
      });
      return result;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError;
};

const runAlertScoringPipeline = async (req, res) => {
  try {
    const writeBack = String(req.query.writeBack || req.body?.writeBack || 'false').toLowerCase() === 'true';
    const retrainClassifier = String(req.query.retrainClassifier || req.body?.retrainClassifier || 'true').toLowerCase() !== 'false';
    const syntheticSize = Math.max(
      1000,
      Number(req.query.syntheticSize || req.body?.syntheticSize) || 1200
    );
    const mongoUri = process.env.MONGO_URI || '';
    const dbName = resolveDbNameFromUri(mongoUri);

    const scriptPath = path.resolve(__dirname, '..', '..', '..', 'ai-model', 'alert_scoring_pipeline.py');
    const reportPath = path.resolve(__dirname, '..', '..', '..', 'ai-model', 'alert_scoring_report.json');
    const datasetPath = path.resolve(__dirname, '..', '..', '..', 'ai-model', 'generated_alert_dataset.json');

    const args = [
      '--output', reportPath,
      '--dataset-output', datasetPath,
      '--synthetic-size', String(syntheticSize),
      '--db', dbName,
      '--collection', 'Alerts'
    ];
    if (mongoUri) args.push('--mongo-uri', mongoUri);
    if (writeBack) args.push('--write-back');
    if (retrainClassifier) args.push('--retrain-classifier');

    const { stdout, stderr } = await runPythonWithFallback(scriptPath, args);
    const reportRaw = await fs.readFile(reportPath, 'utf-8');
    const report = JSON.parse(reportRaw);

    res.status(200).json({
      message: 'AI scoring pipeline executed successfully',
      writeBack,
      retrainClassifier,
      syntheticSize,
      report,
      runtime: {
        stdout: (stdout || '').trim(),
        stderr: (stderr || '').trim(),
      },
    });
  } catch (error) {
    res.status(500).json({
      message: 'Failed to execute AI scoring pipeline',
      details: error.message,
      stderr: error.stderr || '',
      stdout: error.stdout || '',
    });
  }
};

module.exports = {
  getLatestAlerts,
  getAllAlerts,
  getAlertContextById,
  classifyAlertById,
  updateAlertStatus,
  runAlertScoringPipeline,
};
