import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

const GITLEAKS_PATH = process.env.GITLEAKS_PATH?.trim();

const SCAN_TIMEOUT_MS = 120000;
const MAX_STDERR_SIZE = 20000;

// --------------------------------------------------
// 1. Validate target directory
// --------------------------------------------------

async function validateTargetDirectory(targetDir) {
  if (typeof targetDir !== "string" || !targetDir.trim()) {
    throw new Error("Invalid scan directory.");
  }

  const absoluteTarget = path.resolve(targetDir);

  const stats = await fs.lstat(absoluteTarget);

  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error("Scan target must be a valid directory.");
  }

  const realTarget = await fs.realpath(absoluteTarget);

  return realTarget;
}

// --------------------------------------------------
// 2. Validate report path
// --------------------------------------------------

async function prepareReportPath(reportPath) {
  if (typeof reportPath !== "string" || !reportPath.trim()) {
    throw new Error("Invalid Gitleaks report path.");
  }

  const absoluteReport = path.resolve(reportPath);
  const reportDirectory = path.dirname(absoluteReport);

  await fs.mkdir(reportDirectory, {
    recursive: true,
    mode: 0o700,
  });

  const realReportDirectory = await fs.realpath(reportDirectory);

  return path.join(
    realReportDirectory,
    path.basename(absoluteReport)
  );
}

// --------------------------------------------------
// 3. Run Gitleaks
// --------------------------------------------------

export async function runGitleaks(targetDir, reportPath) {
  if (!GITLEAKS_PATH) {
    throw new Error(
      "GITLEAKS_PATH is not configured in the backend environment."
    );
  }

  const absoluteTarget =
    await validateTargetDirectory(targetDir);

  const absoluteReport =
    await prepareReportPath(reportPath);

  const args = [
    "dir",
    absoluteTarget,
    "--report-format=json",
    `--report-path=${absoluteReport}`,
    "--redact=100",
    "--no-banner",
    "--exit-code=0",
    "--timeout=90",
  ];

  return new Promise((resolve, reject) => {
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const scanner = spawn(
      GITLEAKS_PATH,
      args,
      {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "ignore", "pipe"],
      }
    );

    function finish(error, result) {
      if (settled) return;

      settled = true;
      clearTimeout(timer);

      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    }

    const timer = setTimeout(() => {
      timedOut = true;

      // Request termination. Wait for the close event
      // before settling the scan promise.
      scanner.kill();
    }, SCAN_TIMEOUT_MS);

    scanner.stderr.on("data", (chunk) => {
      stderr += chunk.toString();

      if (stderr.length > MAX_STDERR_SIZE) {
        stderr = stderr.slice(-MAX_STDERR_SIZE);
      }
    });

    scanner.on("error", (error) => {
      finish(
        new Error(
          `Could not start Gitleaks: ${error.message}`
        )
      );
    });

    scanner.on("close", async (code) => {
      if (timedOut) {
        finish(new Error("Gitleaks scan timed out."));
        return;
      }

      if (code !== 0) {
        finish(
          new Error(
            `Gitleaks exited with code ${code}. ${stderr}`
          )
        );
        return;
      }

      try {
        const content = await fs.readFile(
          absoluteReport,
          "utf8"
        );

        const rawFindings = JSON.parse(content);

        if (!Array.isArray(rawFindings)) {
          throw new Error(
            "Unexpected Gitleaks report format."
          );
        }

        const findings = rawFindings.map((item) => ({
          ruleId: item.RuleID || "unknown",
          title:
            item.Description ||
            "Potential exposed secret",
          description:
            "Potential secret or credential detected.",
          severity: "high",
          filePath: item.File || "",
          line: item.StartLine || null,
          column: item.StartColumn || null,
          recommendation:
            "Remove the exposed credential and rotate it if it is real.",
          scanner: "Gitleaks",
          secretRedacted: true,
        }));

        finish(null, {
          scanner: "Gitleaks",
          status: "completed",
          totalFindings: findings.length,
          findings,
        });
      } catch (error) {
        finish(
          new Error(
            `Could not process Gitleaks report: ${error.message}`
          )
        );
      }
    });
  });
}