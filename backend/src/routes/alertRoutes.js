const express = require('express');
const { getLatestAlerts, getAllAlerts } = require('../controllers/alertController');

const router = express.Router();

router.get('/', getAllAlerts);
router.get('/latest', getLatestAlerts);

module.exports = router;