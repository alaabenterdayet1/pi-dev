const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema(
  {},
  {
    strict: false,
    timestamps: false,
    collection: 'Alerts',
  }
);

module.exports = mongoose.model('Alert', alertSchema);