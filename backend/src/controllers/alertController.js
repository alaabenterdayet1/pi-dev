const Alert = require('../models/Alert');
const path = require('path');
const fs = require('fs/promises');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { classifyAlert } = require('../services/alertAiService');

const execFileAsync = promisify(execFile);

const stripAiFields = (alertDoc) => {
  const alert = typeof alertDoc.toObject === 'function' ? alertDoc.toObject() : { ...alertDoc };
  delete alert.ai_classification;
  delete alert.ai_decision;
  delete alert.ai_confidence;
  delete alert.ai_risk_score;
  delete alert.ai_recommendation;
  return alert;
};

const getLatestAlerts = async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 5, 50));
    const alerts = await Alert.find().sort({ _id: -1 }).limit(limit);
    const sanitizedAlerts = alerts.map(stripAiFields);

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
    const sanitizedAlerts = alerts.map(stripAiFields);

    res.status(200).json({
      count: sanitizedAlerts.length,
      data: sanitizedAlerts,
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

    const ai = classifyAlert(alert.toObject());
    const updated = await Alert.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          ai_classification: ai.ai_classification,
          ai_decision: ai.ai_decision,
          ai_confidence: ai.ai_confidence,
          ai_risk_score: ai.ai_risk_score,
          ai_recommendation: ai.ai_recommendation,
        },
      },
      { new: true }
    );

    res.status(200).json({
      message: 'Alert classified successfully',
      data: updated,
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

    const updated = await Alert.findByIdAndUpdate(
      req.params.id,
      { $set: { alert_status: nextStatus } },
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

    const { stdout, stderr } = await runPythonWithFallback(scriptPath, args);
    const reportRaw = await fs.readFile(reportPath, 'utf-8');
    const report = JSON.parse(reportRaw);

    res.status(200).json({
      message: 'AI scoring pipeline executed successfully',
      writeBack,
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
  classifyAlertById,
  updateAlertStatus,
  runAlertScoringPipeline,
};