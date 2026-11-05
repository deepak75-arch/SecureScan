import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BACKEND_ROOT = path.resolve(__dirname, "..");
const UPLOAD_ROOT = path.join(BACKEND_ROOT, "uploads");
const PYTHON_ROOT = path.join(BACKEND_ROOT, "python-scanner");

const DEFAULT_PYTHON_PATH = path.join(
  PYTHON_ROOT,
  ".venv",
  "Scripts",
  "python.exe"
);

const PYTHON_PATH =
  process.env.PYTHON_PATH?.trim() ||
  DEFAULT_PYTHON_PATH;

const MAIN_SCRIPT = path.join(
  PYTHON_ROOT,
  "main.py"
);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SCAN_TIMEOUT_MS = 240000;
const MAX_STDOUT_SIZE = 10 * 1024 * 1024;
const MAX_STDERR_SIZE = 20000;

// --------------------------------------------------
// 1. Validate upload directory
// --------------------------------------------------

async function validateUploadDirectory(uploadId) {
  if (
    typeof uploadId !== "string" ||
    !UUID_PATTERN.test(uploadId)
  ) {
    throw new Error("Invalid upload ID.");
  }

  const absoluteUploadRoot = path.resolve(UPLOAD_ROOT);
  const uploadDirectory = path.resolve(
    absoluteUploadRoot,
    uploadId
  );

  if (
    path.dirname(uploadDirectory) !== absoluteUploadRoot
  ) {
    throw new Error("Invalid upload directory.");
  }

  const uploadStats = await fs.lstat(uploadDirectory);

  if (
    uploadStats.isSymbolicLink() ||
    !uploadStats.isDirectory()
  ) {
    throw new Error("Invalid upload directory.");
  }

  const targetDirectory = path.join(
    uploadDirectory,
    "extracted"
  );

  const targetStats = await fs.lstat(targetDirectory);

  if (
    targetStats.isSymbolicLink() ||
    !targetStats.isDirectory()
  ) {
    throw new Error(
      "Extracted project directory is invalid."
    );
  }

  const realUploadRoot = await fs.realpath(
    absoluteUploadRoot
  );

  const realUploadDirectory = await fs.realpath(
    uploadDirectory
  );

  const realTargetDirectory = await fs.realpath(
    targetDirectory
  );

  if (
    path.dirname(realUploadDirectory) !== realUploadRoot ||
    path.dirname(realTargetDirectory) !== realUploadDirectory
  ) {
    throw new Error(
      "Invalid extracted project path."
    );
  }

  return realTargetDirectory;
}

// --------------------------------------------------
// 2. Validate Python executable and script
// --------------------------------------------------

async function validatePythonEnvironment() {
  const pythonStats = await fs.stat(PYTHON_PATH);

  if (!pythonStats.isFile()) {
    throw new Error(
      "Configured Python executable is invalid."
    );
  }

  const scriptStats = await fs.stat(MAIN_SCRIPT);

  if (!scriptStats.isFile()) {
    throw new Error(
      "Python scanner main.py was not found."
    );
  }
}

// --------------------------------------------------
// 3. Run Python scanners
// --------------------------------------------------

export async function runPythonScanners(uploadId) {
  const targetDirectory =
    await validateUploadDirectory(uploadId);

  await validatePythonEnvironment();

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let outputExceeded = false;

    const child = spawn(
      PYTHON_PATH,
      [
        MAIN_SCRIPT,
        targetDirectory,
      ],
      {
        cwd: PYTHON_ROOT,
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          PYTHONUNBUFFERED: "1",
        },
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

      // Wait for the process close event before
      // settling the promise.
      child.kill();
    }, SCAN_TIMEOUT_MS);

    // --------------------------------------------------
    // Capture stdout
    // --------------------------------------------------

    child.stdout.on("data", (chunk) => {
      if (settled) return;

      stdout += chunk.toString();

      if (stdout.length > MAX_STDOUT_SIZE) {
        outputExceeded = true;
        child.kill();
      }
    });

    // --------------------------------------------------
    // Capture stderr
    // --------------------------------------------------

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();

      if (stderr.length > MAX_STDERR_SIZE) {
        stderr = stderr.slice(-MAX_STDERR_SIZE);
      }
    });

    // --------------------------------------------------
    // Handle process startup failure
    // --------------------------------------------------

    child.on("error", (error) => {
      finish(
        new Error(
          `Could not start Python scanner: ${error.message}`
        )
      );
    });

    // --------------------------------------------------
    // Handle process completion
    // --------------------------------------------------

    child.on("close", (code) => {
      if (timedOut) {
        finish(
          new Error("Python scanning process timed out.")
        );
        return;
      }

      if (outputExceeded) {
        finish(
          new Error(
            "Python scanner output exceeded the allowed limit."
          )
        );
        return;
      }

      let result;

      try {
        result = JSON.parse(stdout);
      } catch {
        finish(
          new Error(
            `Could not parse Python scanner JSON output. Exit code: ${code}. ${stderr}`
          )
        );
        return;
      }

      // Validate the expected output structure.
      if (
        !result ||
        typeof result !== "object" ||
        !Array.isArray(result.scanners)
      ) {
        finish(
          new Error(
            "Python scanner returned an invalid result structure."
          )
        );
        return;
      }

      // main.py intentionally exits with code 1 when
      // one or more scanners fail. Valid JSON must still
      // be returned so scanRunner.js can preserve findings
      // from successful scanners.
      if (code !== 0 && code !== 1) {
        finish(
          new Error(
            `Python scanner exited unexpectedly with code ${code}. ${stderr}`
          )
        );
        return;
      }

      finish(null, result);
    });
  });
}