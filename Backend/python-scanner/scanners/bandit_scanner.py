
import json
import subprocess
import sys


def scan_bandit(target_dir):

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(target_dir),
        "-f",
        "json",
        "--exclude",
        ".venv,venv,node_modules,__pycache__,dist,build",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

        try:
            report = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return {
                "scanner": "Bandit",
                "status": "failed",
                "error": (
                    result.stderr.strip()
                    or "Bandit returned invalid JSON."
                ),
                "totalFindings": 0,
                "findings": [],
            }

        findings = []

        for item in report.get("results", []):

            findings.append({
                "scanner": "Bandit",
                "ruleId": item.get("test_id"),
                "title": item.get(
                    "test_name",
                    "Python security issue"
                ),
                "description": item.get("issue_text", ""),
                "severity": item.get(
                    "issue_severity", "LOW"
                ).lower(),
                "confidence": item.get(
                    "issue_confidence", "UNKNOWN"
                ).lower(),
                "filePath": item.get("filename"),
                "line": item.get("line_number"),
                "column": item.get("col_offset"),
                "code": item.get("code", ""),
                "cwe": item.get("issue_cwe", {}),
                "recommendation": item.get("more_info", ""),
            })

        return {
            "scanner": "Bandit",
            "status": "completed",
            "exitCode": result.returncode,
            "totalFindings": len(findings),
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "Bandit",
            "status": "failed",
            "error": "Bandit scan timed out.",
            "totalFindings": 0,
            "findings": [],
        }

    except OSError as error:
        return {
            "scanner": "Bandit",
            "status": "failed",
            "error": str(error),
            "totalFindings": 0,
            "findings": [],
        }
