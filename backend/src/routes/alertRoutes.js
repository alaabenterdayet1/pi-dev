const express = require('express');
const { getLatestAlerts, getAllAlerts, getAlertContextById, classifyAlertById, updateAlertStatus, runAlertScoringPipeline } = require('../controllers/alertController');
const { getAllClassifications } = require('../controllers/classificationController');

const router = express.Router();

router.get('/', getAllAlerts);
router.get('/latest', getLatestAlerts);
router.get('/classification', getAllClassifications);
router.get('/:id/context', getAlertContextById);
router.post('/ai/run-scoring', runAlertScoringPipeline);
router.post('/:id/classify', classifyAlertById);
router.patch('/:id/status', updateAlertStatus);

module.exports = router;
