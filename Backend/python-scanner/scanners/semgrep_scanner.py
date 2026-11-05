
import json
import subprocess
import sys
import shutil
from pathlib import Path


def scan_semgrep(target_dir):
    if sys.platform == "win32":
        semgrep_exe = str(
            Path(sys.prefix) / "Scripts" / "semgrep.exe"
    )
    else:
        semgrep_exe = shutil.which("semgrep")

    if not semgrep_exe or not Path(semgrep_exe).exists():
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": "Semgrep executable not found in Python environment.",
            "findings": [],
    }



    command = [
        semgrep_exe,
        "scan",
        "--config",
        "auto",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        str(target_dir),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        report = json.loads(result.stdout or "{}")

        findings = []

        for item in report.get("results", []):
            extra = item.get("extra", {})

            findings.append({
                "scanner": "Semgrep",
                "ruleId": item.get("check_id"),
                "title": item.get("check_id", "Security issue"),
                "description": extra.get("message", ""),
                "severity": extra.get("severity", "WARNING").lower(),
                "filePath": item.get("path"),
                "line": item.get("start", {}).get("line"),
                "column": item.get("start", {}).get("col"),
                "recommendation": extra.get("metadata", {}).get(
                    "remediation", ""
                ),
            })

        # Do not treat a non-zero exit code alone as a failure:
        # Semgrep can return non-zero when findings or errors occur.
        # A valid JSON report is parsed and its errors are checked below.
        errors = report.get("errors", [])

        if errors:
            return {
                "scanner": "Semgrep",
                "status": "failed",
                "error": "; ".join(
                    str(error.get("message", error))
                    for error in errors
                ),
                "totalFindings": len(findings),
                "findings": findings,
            }

        return {
            "scanner": "Semgrep",
            "status": "completed",
            "totalFindings": len(findings),
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": "Semgrep scan timed out.",
            "findings": [],
        }

    except (json.JSONDecodeError, OSError) as error:
        return {
            "scanner": "Semgrep",
            "status": "failed",
            "error": str(error),
            "findings": [],
        }
