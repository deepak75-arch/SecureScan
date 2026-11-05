import mongoose from "mongoose";

const findingSchema = new mongoose.Schema(
  {
    ruleId: String,
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
    recommendation: String,
    scanner: String,
  },
  { _id: false }
);

const scanSchema = new mongoose.Schema(
  {
    scanId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // Only the SHA-256 hash is stored. Never store the raw token.
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

    errorMessage: String,
  },
  {
    timestamps: true,
  }
);

const Scan = mongoose.model("Scan", scanSchema);

export default Scan;