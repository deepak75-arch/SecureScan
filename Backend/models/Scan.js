
import mongoose from "mongoose";

// Original scanner evidence for each consolidated finding.
const findingSourceSchema = new mongoose.Schema({
  scanner: String,
  ruleId: String,

  severity: {
    type: String,
    enum: ["critical", "high", "medium", "low", "info"],
    default: "info",
  },

  confidence: {
    type: String,
    default: "unknown",
  },

  description: String,
  recommendation: String,

  line: Number,
  column: Number,
  endLine: Number,

  cwe: {
    type: [String],
    default: [],
  },

  owasp: {
    type: [String],
    default: [],
  },

  references: {
    type: [String],
    default: [],
  },
}, { _id: false });
const remediationSchema = new mongoose.Schema({
  available: {
    type: Boolean,
    default: false,
  },

  title: String,
  summary: String,
  cweGuidance: String,

  steps: {
    type: [String],
    default: [],
  },

  exampleLanguage: String,
  insecureExample: String,
  secureExample: String,

  references: {
    type: [String],
    default: [],
  },
}, { _id: false });
// Main consolidated finding.
const findingSchema = new mongoose.Schema({
  ruleId: String,

  ruleIds: {
    type: [String],
    default: [],
  },

  title: {
    type: String,
    required: true,
  },

  description: String,

  severity: {
    type: String,
    enum: ["critical", "high", "medium", "low", "info"],
    default: "info",
  },

  filePath: String,
  line: Number,
  column: Number,
  endLine: Number,

  recommendation: String,
  scanner: String,

  scanners: {
    type: [String],
    default: [],
  },

  sources: {
    type: [findingSourceSchema],
    default: [],
  },

  confidence: {
    type: String,
    default: "unknown",
  },

  cwe: {
    type: [String],
    default: [],
  },

  owasp: {
    type: [String],
    default: [],
  },

  references: {
    type: [String],
    default: [],
  },
}, { _id: false });

// Individual scanner execution details.
const scannerExecutionSchema = new mongoose.Schema({
  scanner: {
    type: String,
    required: true,
  },

  status: {
    type: String,
    enum: ["completed", "failed", "skipped"],
    required: true,
  },

  totalFindings: {
    type: Number,
    default: 0,
  },

  scannedFiles: {
    type: Number,
    default: null,
  },

  skippedFiles: {
    type: Number,
    default: null,
  },

  message: {
    type: String,
    default: "",
  },
}, { _id: false });

// Main scan document.
const scanSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },

  accessTokenHash: {
    type: String,
    required: true,
    select: false,
  },

  uploadId: {
    type: String,
    required: true,
    index: true,
  },

  projectName: {
    type: String,
    default: "Untitled Project",
  },

  status: {
    type: String,
    enum: ["queued", "scanning", "completed", "failed"],
    default: "queued",
  },

  startedAt: Date,
  completedAt: Date,

  totalFiles: {
    type: Number,
    default: 0,
  },

  findings: {
    type: [findingSchema],
    default: [],
  },

  scannerExecutions: {
    type: [scannerExecutionSchema],
    default: [],
  },

  detectedLanguages: {
    type: [String],
    default: [],
  },

  errorMessage: String,

}, {
  timestamps: true,
});

const Scan = mongoose.model("Scan", scanSchema);

export default Scan;
