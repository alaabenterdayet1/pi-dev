const Alert = require('../models/Alert');

const getLatestAlerts = async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 5, 50));
    const alerts = await Alert.find().sort({ _id: -1 }).limit(limit);

    res.status(200).json({
      count: alerts.length,
      limit,
      data: alerts,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllAlerts = async (req, res) => {
  try {
    const alerts = await Alert.find().sort({ _id: -1 });

    res.status(200).json({
      count: alerts.length,
      data: alerts,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getLatestAlerts,
  getAllAlerts,
};