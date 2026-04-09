const Alert = require('../models/Alert');
const { enrichAlertsWithAi, classifyAlert } = require('../services/alertAiService');

const getLatestAlerts = async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 5, 50));
    const alerts = await Alert.find().sort({ _id: -1 }).limit(limit);
    const enrichedAlerts = enrichAlertsWithAi(alerts);

    res.status(200).json({
      count: enrichedAlerts.length,
      limit,
      data: enrichedAlerts,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ _id: -1 });
    const enrichedAlerts = enrichAlertsWithAi(alerts);

    res.status(200).json({
      count: enrichedAlerts.length,
      data: enrichedAlerts,
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

module.exports = {
  getLatestAlerts,
  getAllAlerts,
  classifyAlertById,
};