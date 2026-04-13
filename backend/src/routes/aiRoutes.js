const express = require('express');
const {
  getModelMetrics,
  getModelDistribution,
  getPipelineSummaryController,
  calculateScore,
} = require('../controllers/aiController');

const router = express.Router();

router.get('/model-metrics', getModelMetrics);
router.get('/score-distribution', getModelDistribution);
router.get('/pipeline-summary', getPipelineSummaryController);
router.post('/score', calculateScore);

module.exports = router;