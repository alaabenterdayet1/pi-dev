const Classification = require('../models/Classification');

const getAllClassifications = async (req, res) => {
  try {
    const requested = Number(req.query.limit);
    const limit = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.trunc(requested), 500)
      : 0;
    const query = Classification.find({
      severity: { $nin: [null, ''] },
      confidence: { $nin: [null, ''] },
      status: { $regex: /^success\s*$/i },
    }).sort({ _id: -1 });

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