const mongoose = require('mongoose');

const classificationSchema = new mongoose.Schema(
  {},
  {
    strict: false,
    timestamps: false,
    collection: 'Classification',
  }
);

module.exports = mongoose.model('Classification', classificationSchema);
