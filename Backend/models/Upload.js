import mongoose from "mongoose";

const uploadedFileSchema = new mongoose.Schema(
  {
    storedName: {
      type: String,
      required: true,
    },
    originalName: {
      type: String,
      required: true,
    },
    relativePath: {
      type: String,
      required: true,
    },
    extension: {
      type: String,
      required: true,
    },
    size: {
      type: Number,
      required: true,
    },
  },
  { _id: false }
);

const uploadSchema = new mongoose.Schema(
  {
    uploadId: {
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

    projectName: {
      type: String,
      default: "Untitled Project",
      trim: true,
      maxlength: 100,
    },

    status: {
      type: String,
      enum: [
        "quarantined",
        "extracted",
        "queued",
        "scanning",
        "completed",
        "failed",
      ],
      default: "quarantined",
    },

    // Identifies the scan currently holding this upload's lock.
    // Null means that no scan is currently active.
    activeScanId: {
      type: String,
      default: null,
      index: true,
    },

    // Records when the active scan lock was acquired.
    activeScanStartedAt: {
      type: Date,
      default: null,
    },

    totalFiles: {
      type: Number,
      required: true,
      min: 0,
    },

    totalSize: {
      type: Number,
      required: true,
      min: 0,
    },

    files: {
      type: [uploadedFileSchema],
      default: [],
    },

    extraction: {
      status: {
        type: String,
        enum: ["pending", "completed", "failed"],
        default: "pending",
      },

      extractedAt: Date,
      totalFiles: Number,
      totalSize: Number,
    },
  },
  { timestamps: true }
);

const Upload = mongoose.model("Upload", uploadSchema);

export default Upload;