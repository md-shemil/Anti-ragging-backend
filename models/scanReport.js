const mongoose = require('mongoose');

const scanReportSchema = new mongoose.Schema({
  originalFilename: { type: String, required: true },
  fileHash: { type: String, required: true },
  scanStatus: { type: String, required: true },
  virusTotalLink: { type: String, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Optional, if user is linked
});

const ScanReport = mongoose.model('ScanReport', scanReportSchema);

module.exports = ScanReport;
