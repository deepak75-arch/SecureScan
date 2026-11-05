
import path from "node:path";
import fs from "node:fs/promises";
import {
  randomUUID,
  randomBytes,
  createHash,
} from "node:crypto";
import { fileURLToPath } from "node:url";

import Scan from "../models/Scan.js";
import Upload from "../models/Upload.js";

import { runPythonScanners } from "./pythonScanner.js";
import { runGitleaks } from "./gitleaksScanner.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BACKEND_ROOT = path.resolve(__dirname, "..");
const UPLOAD_ROOT = path.join(BACKEND_ROOT, "uploads");

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// --------------------------------------------------
// 1. Path validation helper
// --------------------------------------------------

function isPathInside(parent, target) {
  const relativePath = path.relative(parent, target);

  return (
    relativePath !== "" &&
    !relativePath.startsWith("..") &&
    !path.isAbsolute(relativePath)
  );
}

// --------------------------------------------------
// 2. Normalize scanner severity
// --------------------------------------------------

function normalizeSeverity(severity, scanner) {
  const value = String(severity || "").toLowerCase();

  if (scanner === "Gitleaks") return "high";

  if (["critical", "high"].includes(value)) {
    return value;
  }

  if (["medium", "moderate", "warning"].includes(value)) {
    return "medium";
  }

  if (value === "low") return "low";

  if (["info", "informational"].includes(value)) {
    return "info";
  }

  if (value === "error") return "high";

  return "info";
}

// --------------------------------------------------
// 3. Normalize findings
// --------------------------------------------------

function normalizeFinding(finding, scanner) {
  return {
    ruleId: finding.ruleId || "unknown",
    title: finding.title || "Security issue detected",
    description: finding.description || "",
    severity: normalizeSeverity(finding.severity, scanner),
    filePath: finding.filePath || "",
    line: Number.isInteger(finding.line)
      ? finding.line
      : undefined,
    column: Number.isInteger(finding.column)
      ? finding.column
      : undefined,
    recommendation: finding.recommendation || "",
    scanner,
  };
}

// --------------------------------------------------
// 4. Update scan record
// --------------------------------------------------

async function updateScan(scanId, update) {
  const result = await Scan.findOneAndUpdate(
    { scanId },
    update,
    {
      returnDocument: "after",
      runValidators: true,
    }
  );

  if (!result) {
    throw new Error("Scan record could not be updated.");
  }

  return result;
}

// --------------------------------------------------
// 5. Update upload status
// --------------------------------------------------

async function updateUploadStatus(uploadId, scanId, status) {
  const result = await Upload.findOneAndUpdate(
    {
      uploadId,
      activeScanId: scanId,
    },
    {
      $set: {
        status,
      },
    },
    {
      returnDocument: "after",
      runValidators: true,
    }
  );

  if (!result) {
    throw new Error("Upload scan lock could not be verified.");
  }

  return result;
}

// --------------------------------------------------
// 6. Release upload scan lock
// --------------------------------------------------

async function releaseUploadLock(uploadId, scanId, status) {
  const result = await Upload.findOneAndUpdate(
    {
      uploadId,
      activeScanId: scanId,
    },
    {
      $set: {
        status,
        activeScanId: null,
        activeScanStartedAt: null,
      },
    },
    {
      returnDocument: "after",
      runValidators: true,
    }
  );

  if (!result) {
    console.error(
      `[Scan ${scanId}] Upload lock was not found during release.`
    );
  }

  return result;
}

// --------------------------------------------------
// 7. Validate extracted directory
// --------------------------------------------------

async function validateTargetDirectory(uploadId) {
  const uploadDirectory = path.resolve(
    UPLOAD_ROOT,
    uploadId
  );

  if (!isPathInside(path.resolve(UPLOAD_ROOT), uploadDirectory)) {
    throw new Error("Invalid upload directory.");
  }

  const targetDirectory = path.join(
    uploadDirectory,
    "extracted"
  );

  const uploadStats = await fs.lstat(uploadDirectory);

  if (
    uploadStats.isSymbolicLink() ||
    !uploadStats.isDirectory()
  ) {
    throw new Error("Invalid upload directory.");
  }

  const targetStats = await fs.lstat(targetDirectory);

  if (
    targetStats.isSymbolicLink() ||
    !targetStats.isDirectory()
  ) {
    throw new Error("Extracted project directory is invalid.");
  }

  const realUploadRoot = await fs.realpath(UPLOAD_ROOT);
  const realUploadDirectory = await fs.realpath(uploadDirectory);
  const realTargetDirectory = await fs.realpath(targetDirectory);

  if (
    !isPathInside(realUploadRoot, realUploadDirectory) ||
    !isPathInside(realUploadDirectory, realTargetDirectory)
  ) {
    throw new Error("Invalid extracted project path.");
  }

  return {
    uploadDirectory: realUploadDirectory,
    targetDirectory: realTargetDirectory,
  };
}

// --------------------------------------------------
// 8. Background scan execution
// --------------------------------------------------

async function executeScan(
  scanId,
  uploadId,
  targetDirectory,
  reportPath
) {
  let finalUploadStatus = "failed";

  const log = (message) => {
    console.log(`[Scan ${scanId}] ${message}`);
  };

  log("Background scan started.");

  try {
    // Update both records to scanning.
    await updateScan(scanId, {
      $set: {
        status: "scanning",
        startedAt: new Date(),
      },
    });

    await updateUploadStatus(
      uploadId,
      scanId,
      "scanning"
    );

    log("Scan status updated.");

    // Prepare report directory.
    await fs.mkdir(path.dirname(reportPath), {
      recursive: true,
      mode: 0o700,
    });

    // Start both scanners independently.
    log("Starting Python scanners.");

    const pythonPromise = runPythonScanners(uploadId);

    log("Starting Gitleaks.");

    const gitleaksPromise = runGitleaks(
      targetDirectory,
      reportPath
    );

    const results = await Promise.allSettled([
      pythonPromise,
      gitleaksPromise,
    ]);

    const findings = [];
    const errors = [];

    // --------------------------------------------------
    // Process Python results
    // --------------------------------------------------

    if (results[0].status === "fulfilled") {
      const pythonResult = results[0].value;

      if (Array.isArray(pythonResult.scanners)) {
        for (const scannerResult of pythonResult.scanners) {
          const scannerName =
            scannerResult.scanner || "Python scanner";

          log(`${scannerName}: ${scannerResult.status}`);

          // Preserve findings even when a scanner is partial.
          for (const finding of scannerResult.findings || []) {
            findings.push(
              normalizeFinding(
                finding,
                scannerName
              )
            );
          }

          if (scannerResult.status !== "completed") {
            errors.push(
              `${scannerName}: ${
                scannerResult.error || "Scan failed."
              }`
            );
          }
        }

        if (
          pythonResult.status === "partial" ||
          pythonResult.success === false
        ) {
          if (errors.length === 0) {
            errors.push(
              "One or more Python scanners did not complete."
            );
          }
        }
      } else {
        errors.push(
          "Python scanner returned an invalid result."
        );
      }
    } else {
      const errorMessage =
        results[0].reason?.message || "Unknown error.";

      console.error(
        `[Scan ${scanId}] Python scanner error:`,
        errorMessage
      );

      errors.push(`Python scanners failed: ${errorMessage}`);
    }

    // --------------------------------------------------
    // Process Gitleaks results
    // --------------------------------------------------

    if (results[1].status === "fulfilled") {
      const gitleaksResult = results[1].value;

      log(
        `Gitleaks completed: ${
          gitleaksResult.totalFindings || 0
        } findings.`
      );

      for (const finding of gitleaksResult.findings || []) {
        findings.push(
          normalizeFinding(
            finding,
            "Gitleaks"
          )
        );
      }
    } else {
      const errorMessage =
        results[1].reason?.message || "Unknown error.";

      console.error(
        `[Scan ${scanId}] Gitleaks error:`,
        errorMessage
      );

      errors.push(`Gitleaks scanning failed: ${errorMessage}`);
    }

    // --------------------------------------------------
    // Save final results
    // --------------------------------------------------

    const failed = errors.length > 0;

    finalUploadStatus = failed ? "failed" : "completed";

    const update = {
      $set: {
        status: finalUploadStatus,
        completedAt: new Date(),
        findings,
      },
    };

    if (failed) {
      update.$set.errorMessage = errors
        .join("; ")
        .slice(0, 2000);
    } else {
      update.$unset = {
        errorMessage: 1,
      };
    }

    await updateScan(scanId, update);

    log(`Final status: ${finalUploadStatus}`);
    log(`Total findings: ${findings.length}`);

  } catch (error) {
    console.error(
      `[Scan ${scanId}] Background execution failed:`,
      error.stack || error.message
    );

    finalUploadStatus = "failed";

    try {
      await updateScan(scanId, {
        $set: {
          status: "failed",
          completedAt: new Date(),
          errorMessage:
            "An internal error occurred during scanning.",
        },
      });
    } catch (dbError) {
      console.error(
        `[Scan ${scanId}] Could not save failed status:`,
        dbError.message
      );
    }

  } finally {
    // Delete temporary Gitleaks report.
    try {
      await fs.rm(reportPath, {
        force: true,
      });
    } catch (error) {
      console.error(
        `[Scan ${scanId}] Report cleanup failed:`,
        error.message
      );
    }

    // Always attempt to release the upload lock.
    try {
      await releaseUploadLock(
        uploadId,
        scanId,
        finalUploadStatus
      );
    } catch (error) {
      console.error(
        `[Scan ${scanId}] Could not release upload lock:`,
        error.message
      );
    }

    log("Background scan execution finished.");
  }
}

// --------------------------------------------------
// 9. Start a new scan
// --------------------------------------------------

export async function startScan(uploadId) {
  if (
    typeof uploadId !== "string" ||
    !UUID_PATTERN.test(uploadId)
  ) {
    throw new Error("Invalid upload ID.");
  }

  const upload = await Upload.findOne({ uploadId });

  if (!upload) {
    throw new Error("Upload not found.");
  }

  if (upload.extraction?.status !== "completed") {
    throw new Error("Extract the ZIP before starting a scan.");
  }

  const {
    uploadDirectory,
    targetDirectory,
  } = await validateTargetDirectory(uploadId);

  // Generate identifiers and token before acquiring the lock.
  const scanId = randomUUID();

  const accessToken = randomBytes(32).toString("hex");

  const accessTokenHash = createHash("sha256")
    .update(accessToken)
    .digest("hex");

  // Atomically claim the upload.
  // Only one request can acquire this lock.
  const claimedUpload = await Upload.findOneAndUpdate(
    {
      uploadId,
      "extraction.status": "completed",
      activeScanId: null,
    },
    {
      $set: {
        activeScanId: scanId,
        activeScanStartedAt: new Date(),
        status: "queued",
      },
    },
    {
      returnDocument: "after",
      runValidators: true,
    }
  );

  if (!claimedUpload) {
    const currentUpload = await Upload.findOne({ uploadId });

    if (!currentUpload) {
      throw new Error("Upload not found.");
    }

    if (currentUpload.extraction?.status !== "completed") {
      throw new Error("Extract the ZIP before starting a scan.");
    }

    if (currentUpload.activeScanId) {
      throw new Error(
        "A scan is already active for this upload."
      );
    }

    throw new Error(
      "Could not acquire the scan lock. Please retry."
    );
  }

  try {
    // Create the scan record after acquiring the lock.
    const scan = await Scan.create({
      scanId,
      uploadId,
      accessTokenHash,
      projectName: claimedUpload.projectName,
      status: "queued",
      totalFiles: claimedUpload.extraction.totalFiles || 0,
      findings: [],
    });

    const reportPath = path.join(
      uploadDirectory,
      "reports",
      `${scanId}-gitleaks.json`
    );

    logScanCreated(scanId);

    // Schedule background execution.
    setImmediate(() => {
      executeScan(
        scanId,
        uploadId,
        targetDirectory,
        reportPath
      ).catch((error) => {
        console.error(
          `[Scan ${scanId}] Unexpected background error:`,
          error.message
        );
      });
    });

    // Return the raw token only once.
    return {
      success: true,
      message: "Security scan has been queued.",
      accessToken,
      scan: {
        scanId: scan.scanId,
        uploadId: scan.uploadId,
        projectName: scan.projectName,
        status: scan.status,
        totalFiles: scan.totalFiles,
      },
    };

  } catch (error) {
    // Roll back the lock if scan creation fails.
    await releaseUploadLock(
      uploadId,
      scanId,
      upload.status || "extracted"
    );

    throw error;
  }
}

// --------------------------------------------------
// 10. Log scan creation
// --------------------------------------------------

function logScanCreated(scanId) {
  console.log(`[Scan ${scanId}] Scan record created.`);
}
