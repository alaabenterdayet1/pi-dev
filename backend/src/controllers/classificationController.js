const Classification = require('../models/Classification');

const getAllClassifications = async (req, res) => {
  try {
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 0, 500));
    const query = Classification.find().sort({ _id: -1 });

    if (limit > 0) {
      query.limit(limit);
    }

    const classifications = await query;

    res.status(200).json({
      count: classifications.length,
      data: classifications,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getAllClassifications,
};