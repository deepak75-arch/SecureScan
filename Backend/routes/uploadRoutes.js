
import express from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import {
  randomUUID,
  randomBytes,
  createHash,
} from "node:crypto";
import { fileURLToPath } from "node:url";

import requireUploadConsent from "../middleware/requireUploadConsent.js";
import requireUploadAccess from "../middleware/requireUploadAccess.js";
import Upload from "../models/Upload.js";
import { extractZipSafely } from "../utils/safeZip.js";

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPLOAD_ROOT = path.resolve(__dirname, "../uploads");

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const MAX_TOTAL_SIZE = 200 * 1024 * 1024;
const MAX_FILES = 20;

// Supported upload extensions.
const ALLOWED_EXTENSIONS = new Set([
  // ZIP
  ".zip",

  // JavaScript / TypeScript
  ".js", ".jsx", ".mjs", ".cjs",
  ".ts", ".tsx",

  // Python / Java
  ".py", ".java",

  // C / C++ / C#
  ".c", ".h", ".cpp", ".hpp", ".cc",
  ".cs",

  // Other programming languages
  ".php", ".go", ".rb",

  // Web technologies
  ".html", ".htm", ".css", ".scss", ".sass",

  // Configuration and data
  ".json", ".xml", ".yml", ".yaml", ".toml",

  // Database and shell
  ".sql", ".sh", ".bash",
]);

function getExtension(filename) {
  return path.extname(filename).toLowerCase();
}

function isValidRelativePath(relativePath) {
  if (
    typeof relativePath !== "string" ||
    !relativePath ||
    relativePath.includes("\0") ||
    relativePath.includes("\\") ||
    path.isAbsolute(relativePath) ||
    /^[a-zA-Z]:/.test(relativePath)
  ) {
    return false;
  }

  const parts = relativePath.split("/");

  return parts.every(
    (part) =>
      part &&
      part !== "." &&
      part !== ".." &&
      !part.includes(":") &&
      !/[. ]$/.test(part)
  );
}

function validateUploadId(uploadId) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    uploadId
  );
}

// Ensure the upload root exists before Multer saves files.
async function prepareUploadDirectory(req, res, next) {
  try {
    await fs.promises.mkdir(UPLOAD_ROOT, {
      recursive: true,
      mode: 0o700,
    });

    next();
  } catch (error) {
    next(error);
  }
}

// Create a unique directory for each upload.
function prepareUpload(req, res, next) {
  try {
    req.uploadId = randomUUID();
    req.uploadDirectory = path.join(
      UPLOAD_ROOT,
      req.uploadId
    );

    fs.mkdirSync(req.uploadDirectory, {
      recursive: false,
      mode: 0o700,
    });

    next();
  } catch (error) {
    next(error);
  }
}

// Multer storage configuration.
const storage = multer.diskStorage({
  destination(req, file, callback) {
    callback(null, req.uploadDirectory);
  },

  filename(req, file, callback) {
    const extension = getExtension(file.originalname);

    callback(null, `${randomUUID()}${extension}`);
  },
});

const upload = multer({
  storage,

  limits: {
    fileSize: MAX_FILE_SIZE,
    files: MAX_FILES,
    fields: 5,
  },

  fileFilter(req, file, callback) {
    const extension = getExtension(file.originalname);

    if (!ALLOWED_EXTENSIONS.has(extension)) {
      return callback(
        new Error(
          `Unsupported file type: ${extension || "unknown"}`
        )
      );
    }

    callback(null, true);
  },
});

async function readManifest(uploadDirectory) {
  const manifestPath = path.join(
    uploadDirectory,
    "manifest.json"
  );

  const content = await fs.promises.readFile(
    manifestPath,
    "utf8"
  );

  return JSON.parse(content);
}

// ======================================================
// POST /api/uploads
// Upload individual source files or one ZIP archive.
// ======================================================

router.post(
  "/",
  requireUploadConsent,
  prepareUploadDirectory,
  prepareUpload,
  (req, res, next) => {
    upload.array("files", MAX_FILES)(
      req,
      res,
      async (uploadError) => {
        if (uploadError) {
          await fs.promises.rm(req.uploadDirectory, {
            recursive: true,
            force: true,
          }).catch(() => {});

          return next(uploadError);
        }

        try {
          const files = req.files || [];

          if (files.length === 0) {
            await fs.promises.rm(req.uploadDirectory, {
              recursive: true,
              force: true,
            });

            return res.status(400).json({
              success: false,
              message: "Please upload at least one file.",
            });
          }

          const totalSize = files.reduce(
            (total, file) => total + file.size,
            0
          );

          if (totalSize > MAX_TOTAL_SIZE) {
            await fs.promises.rm(req.uploadDirectory, {
              recursive: true,
              force: true,
            });

            return res.status(413).json({
              success: false,
              message: "Total upload size exceeds 200 MB.",
            });
          }

          // Validate filenames and create manifest entries.
          const manifestFiles = files.map((file) => {
            const relativePath = file.originalname.replace(
              /\\/g,
              "/"
            );

            if (!isValidRelativePath(relativePath)) {
              throw new Error("Invalid uploaded file path.");
            }

            return {
              storedName: file.filename,
              originalName: path.basename(relativePath),
              relativePath,
              extension: getExtension(file.originalname),
              size: file.size,
            };
          });

          // ZIP archives must be uploaded separately.
          const zipFiles = manifestFiles.filter(
            (file) => file.extension === ".zip"
          );

          if (
            zipFiles.length > 0 &&
            manifestFiles.length !== 1
          ) {
            await fs.promises.rm(req.uploadDirectory, {
              recursive: true,
              force: true,
            });

            return res.status(400).json({
              success: false,
              message:
                "Upload a ZIP archive separately from individual source files.",
            });
          }

          const projectName =
            typeof req.body.projectName === "string" &&
            req.body.projectName.trim()
              ? req.body.projectName.trim().slice(0, 100)
              : "Untitled Project";

          const isZipUpload = zipFiles.length === 1;

          let uploadStatus = "quarantined";

          let extraction = {
            status: "pending",
          };

          // Prepare individual source files directly for scanning.
          if (!isZipUpload) {
            const extractedDirectory = path.join(
              req.uploadDirectory,
              "extracted"
            );

            await fs.promises.mkdir(extractedDirectory, {
              recursive: false,
              mode: 0o700,
            });

            for (const file of manifestFiles) {
              const sourcePath = path.join(
                req.uploadDirectory,
                file.storedName
              );

              const destinationPath = path.join(
                extractedDirectory,
                file.storedName
              );

              await fs.promises.rename(
                sourcePath,
                destinationPath
              );
            }

            uploadStatus = "extracted";

            extraction = {
              status: "completed",
              extractedAt: new Date(),
              totalFiles: manifestFiles.length,
              totalSize,
            };
          }

          // Create upload manifest.
          const manifest = {
            uploadId: req.uploadId,
            projectName,
            status: uploadStatus,
            uploadedAt: new Date().toISOString(),
            totalFiles: manifestFiles.length,
            totalSize,
            files: manifestFiles,
            extraction,
          };

          await fs.promises.writeFile(
            path.join(req.uploadDirectory, "manifest.json"),
            JSON.stringify(manifest, null, 2),
            {
              mode: 0o600,
              flag: "wx",
            }
          );

          // Generate a secure upload access token.
          const accessToken = randomBytes(32).toString("hex");

          // Store only the SHA-256 hash in MongoDB.
          const accessTokenHash = createHash("sha256")
            .update(accessToken)
            .digest("hex");

          const savedUpload = await Upload.create({
            uploadId: req.uploadId,
            accessTokenHash,
            projectName,
            status: uploadStatus,
            totalFiles: manifestFiles.length,
            totalSize,
            files: manifestFiles,
            extraction,
          });

          return res.status(201).json({
            success: true,

            message: isZipUpload
              ? "ZIP file uploaded successfully. Extraction is required."
              : "Source files uploaded and prepared for scanning.",

            upload: {
              uploadId: savedUpload.uploadId,
              projectName: savedUpload.projectName,
              status: savedUpload.status,
              totalFiles: savedUpload.totalFiles,
              totalSize: savedUpload.totalSize,
              extraction: savedUpload.extraction,
              createdAt: savedUpload.createdAt,

              // Raw token is returned only once.
              accessToken,
            },
          });
        } catch (error) {
          await fs.promises.rm(req.uploadDirectory, {
            recursive: true,
            force: true,
          }).catch(() => {});

          await Upload.deleteOne({
            uploadId: req.uploadId,
          }).catch(() => {});

          next(error);
        }
      }
    );
  }
);

// ======================================================
// POST /api/uploads/:uploadId/extract
// Safely extract an uploaded ZIP archive.
// Requires the upload access token.
// ======================================================

router.post(
  "/:uploadId/extract",
  requireUploadAccess,
  async (req, res, next) => {
    let extractionDirectory;

    try {
      const { uploadId } = req.params;

      if (!validateUploadId(uploadId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid upload ID.",
        });
      }

      const uploadRecord = await Upload.findOne({
        uploadId,
      });

      if (!uploadRecord) {
        return res.status(404).json({
          success: false,
          message: "Upload not found.",
        });
      }

      if (uploadRecord.extraction?.status === "completed") {
        return res.status(409).json({
          success: false,
          message:
            "This upload has already been prepared or extracted.",
        });
      }

      const uploadDirectory = path.resolve(
        UPLOAD_ROOT,
        uploadId
      );

      const manifest = await readManifest(uploadDirectory);

      const zipFiles = manifest.files.filter(
        (file) => file.extension === ".zip"
      );

      if (
        zipFiles.length !== 1 ||
        manifest.files.length !== 1
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Exactly one ZIP file is required for extraction.",
        });
      }

      const zipFile = zipFiles[0];

      if (!/^[a-f0-9-]+\.zip$/i.test(zipFile.storedName)) {
        return res.status(400).json({
          success: false,
          message: "Invalid stored ZIP filename.",
        });
      }

      const zipPath = path.resolve(
        uploadDirectory,
        zipFile.storedName
      );

      if (path.dirname(zipPath) !== uploadDirectory) {
        return res.status(400).json({
          success: false,
          message: "Invalid ZIP file location.",
        });
      }

      await fs.promises.access(
        zipPath,
        fs.constants.R_OK
      );

      extractionDirectory = path.join(
        uploadDirectory,
        "extracted"
      );

      const result = await extractZipSafely(
        zipPath,
        extractionDirectory
      );

      const updatedManifest = {
        ...manifest,
        status: "extracted",
        extraction: {
          status: "completed",
          extractedAt: new Date().toISOString(),
          totalFiles: result.totalFiles,
          totalSize: result.totalSize,
        },
      };

      await fs.promises.writeFile(
        path.join(uploadDirectory, "manifest.json"),
        JSON.stringify(updatedManifest, null, 2),
        { mode: 0o600 }
      );

      const updatedUpload = await Upload.findOneAndUpdate(
        { uploadId },
        {
          $set: {
            status: "extracted",
            "extraction.status": "completed",
            "extraction.extractedAt": new Date(),
            "extraction.totalFiles": result.totalFiles,
            "extraction.totalSize": result.totalSize,
          },
        },
        {
          new: true,
          runValidators: true,
        }
      );

      if (!updatedUpload) {
        throw new Error(
          "Upload record not found in MongoDB."
        );
      }

      return res.status(200).json({
        success: true,
        message: "ZIP extracted successfully.",
        uploadId,
        extraction: {
          totalFiles: result.totalFiles,
          totalSize: result.totalSize,
          files: result.files,
        },
      });
    } catch (error) {
      if (extractionDirectory) {
        await fs.promises.rm(extractionDirectory, {
          recursive: true,
          force: true,
        }).catch(() => {});
      }

      next(error);
    }
  }
);

// ======================================================
// GET /api/uploads
// Public upload history is disabled.
// ======================================================

router.get("/", (req, res) => {
  return res.status(403).json({
    success: false,
    message: "Public upload history is disabled.",
  });
});

// ======================================================
// GET /api/uploads/:uploadId
// Retrieve one upload record.
// Requires the upload access token.
// ======================================================

router.get(
  "/:uploadId",
  requireUploadAccess,
  async (req, res, next) => {
    try {
      const { uploadId } = req.params;

      if (!validateUploadId(uploadId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid upload ID.",
        });
      }

      const uploadRecord = await Upload.findOne({
        uploadId,
      }).select("-files");

      if (!uploadRecord) {
        return res.status(404).json({
          success: false,
          message: "Upload not found.",
        });
      }

      return res.status(200).json({
        success: true,
        upload: uploadRecord,
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
