const express = require('express');
const { getLatestAlerts, getAllAlerts, classifyAlertById, updateAlertStatus, runAlertScoringPipeline } = require('../controllers/alertController');

const router = express.Router();

router.get('/', getAllAlerts);
router.get('/latest', getLatestAlerts);
router.post('/ai/run-scoring', runAlertScoringPipeline);
router.post('/:id/classify', classifyAlertById);
router.patch('/:id/status', updateAlertStatus);

module.exports = router;