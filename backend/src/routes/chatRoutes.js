const express = require('express');
const { askAssistant } = require('../controllers/chatController');

const router = express.Router();

router.post('/assistant', askAssistant);

module.exports = router;
