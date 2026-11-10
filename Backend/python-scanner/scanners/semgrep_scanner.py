
import json
import os
import shutil
import subprocess
import sys

from pathlib import Path


def resolve_semgrep():
    """
    Locate the Semgrep executable on Windows, Linux or Docker.
    """

    configured_path = os.getenv("SEMGREP_PATH")

    if configured_path:
        path = Path(configured_path)
        if path.is_file():
            return str(path)

    executable = shutil.which("semgrep")

    if executable:
        return executable

    if sys.platform == "win32":
        candidates = [
            Path(sys.prefix) / "Scripts" / "semgrep.exe",
            Path(sys.prefix) / "Scripts" / "semgrep",
        ]
    else:
        candidates = [
            Path(sys.prefix) / "bin" / "semgrep",
            Path(sys.prefix) / "Scripts" / "semgrep",
        ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def normalize_severity(severity):
    severity = str(severity or "WARNING").upper()

    severity_mapping = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }

    return severity_mapping.get(severity, "medium")


# INSERT THE NEW FUNCTION HERE
def get_code_snippet(file_path, start_line, end_line=None):
    try:
        path = Path(file_path)

        lines = path.read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

        if not isinstance(start_line, int) or start_line < 1:
            return ""

        end_line = end_line or start_line

        start = max(1, start_line - 2)
        end = min(len(lines), end_line + 2)

        return "\n".join(
            f"{i}: {lines[i - 1]}"
            for i in range(start, end + 1)
        )

    except (OSError, TypeError, ValueError):
        return ""


def scan_semgrep(target_dir):
    """
    Scan a project using Semgrep.

    Supports multiple programming languages through Semgrep rules.
    Returns normalized findings and scan coverage information.
    """

    target_dir = Path(target_dir).resolve()

    # Validate project directory
    if not target_dir.exists() or not target_dir.is_dir():
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": f"Invalid scan directory: {target_dir}",
            "totalFindings": 0,
            "findings": [],
        }

    # Locate Semgrep
    semgrep_exe = resolve_semgrep()

    if not semgrep_exe:
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": "Semgrep executable not found.",
            "totalFindings": 0,
            "findings": [],
        }

    # Semgrep automatic configuration requires metrics enabled.
    command = [
        semgrep_exe,
        "scan",
        "--config",
        "auto",
        "--json",
        "--metrics=on",
        "--no-git-ignore",
        "--disable-version-check",
        str(target_dir),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

        # Parse JSON even if Semgrep returns a non-zero exit code.
        try:
            report = json.loads(result.stdout or "{}")

        except json.JSONDecodeError:
            return {
                "scanner": "Semgrep",
                "status": "failed",
                "error": (
                    result.stderr.strip()
                    or "Semgrep returned an invalid JSON report."
                ),
                "exitCode": result.returncode,
                "totalFindings": 0,
                "findings": [],
            }

        # Normalize findings
        findings = []

        for item in report.get("results", []):

            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            start = item.get("start") or {}
            end = item.get("end") or {}

            findings.append({
                "scanner": "Semgrep",

                "ruleId": item.get(
                    "check_id",
                    "unknown-rule"
                ),

                "title": item.get(
                    "check_id",
                    "Security issue"
                ),

                "description": extra.get(
                    "message",
                    "Potential security issue detected."
                ),

                "severity": normalize_severity(
                    extra.get("severity")
                ),

                "filePath": item.get("path"),

                "line": start.get("line"),

                "column": start.get("col"),

                "endLine": end.get("line"),

                "code": get_code_snippet(
                item.get("path"),
                start.get("line"),
                end.get("line")
            ),

                "cwe": metadata.get("cwe", []),

                "owasp": metadata.get("owasp", []),

                "confidence": metadata.get(
                    "confidence",
                    "unknown"
                ),

                "references": metadata.get(
                    "references",
                    []
                ),

                "recommendation": (
                    metadata.get("remediation")
                    or metadata.get("fix")
                    or "Review the affected code and apply a secure coding fix."
                ),
            })

        # Collect scanner errors
        scanner_errors = [
            error.get("message", str(error))
            if isinstance(error, dict)
            else str(error)
            for error in report.get("errors", [])
        ]

        # Collect coverage information
        paths = report.get("paths") or {}

        scanned_paths = paths.get("scanned", [])
        skipped_paths = paths.get("skipped", [])

        # A scan is successful only if:
        # 1. Semgrep returns exit code 0.
        # 2. No scanner errors are reported.
        # 3. At least one file was scanned.
        scan_completed = (
            result.returncode == 0
            and not scanner_errors
            and len(scanned_paths) > 0
        )

        return {
            "scanner": "Semgrep",

            "status": (
                "completed" if scan_completed else "failed"
            ),

            "exitCode": result.returncode,

            "totalFindings": len(findings),

            "findings": findings,

            "coverage": {
                "scannedFiles": len(scanned_paths),
                "skippedFiles": len(skipped_paths),
                "skippedDetails": skipped_paths,
            },

            "warnings": scanner_errors,

            **(
                {
                    "error": (
                        result.stderr.strip()
                        or "Semgrep scan did not complete successfully."
                    )
                }
                if not scan_completed
                else {}
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": "Semgrep scan timed out after 300 seconds.",
            "totalFindings": 0,
            "findings": [],
        }

    except OSError as error:
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": str(error),
            "totalFindings": 0,
            "findings": [],
        }
