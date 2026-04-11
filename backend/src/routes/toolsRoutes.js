const express = require('express');
const { getToolsStatus } = require('../controllers/toolsController');

const router = express.Router();

router.get('/status/all', getToolsStatus);

module.exports = router;
