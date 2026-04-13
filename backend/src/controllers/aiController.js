const {
  getMetrics,
  getScoreDistribution,
  getPipelineSummary,
  scoreThreatFeatures,
} = require('../services/aiScoringService');

const getModelMetrics = async (_req, res) => {
  try {
    const metrics = await getMetrics();
    res.status(200).json(metrics);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getModelDistribution = async (_req, res) => {
  try {
    const scoreDistribution = await getScoreDistribution();
    res.status(200).json({ scoreDistribution });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const calculateScore = async (req, res) => {
  try {
    const result = scoreThreatFeatures(req.body || {});
    res.status(200).json(result);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getPipelineSummaryController = async (_req, res) => {
  try {
    const summary = await getPipelineSummary();
    res.status(200).json(summary);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getModelMetrics,
  getModelDistribution,
  getPipelineSummaryController,
  calculateScore,
};