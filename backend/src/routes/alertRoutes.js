const express = require('express');
const { getLatestAlerts, getAllAlerts, classifyAlertById } = require('../controllers/alertController');

const router = express.Router();

router.get('/', getAllAlerts);
router.get('/latest', getLatestAlerts);
router.post('/:id/classify', classifyAlertById);

module.exports = router;