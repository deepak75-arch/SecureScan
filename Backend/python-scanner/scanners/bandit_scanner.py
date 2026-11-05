
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
        ".venv,venv,node_modules,__pycache__",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        report = json.loads(result.stdout or "{}")

        findings = []

        for item in report.get("results", []):
            findings.append({
                "scanner": "Bandit",
                "ruleId": item.get("test_id"),
                "title": item.get("test_name", "Python security issue"),
                "description": item.get("issue_text", ""),
                "severity": item.get("issue_severity", "LOW").lower(),
                "filePath": item.get("filename"),
                "line": item.get("line_number"),
                "column": item.get("col_offset"),
                "recommendation": item.get("more_info", ""),
            })

        # Bandit commonly returns exit code 1 when findings exist.
        # Therefore, findings alone should not mark the scan as failed.
        return {
            "scanner": "Bandit",
            "status": "completed",
            "totalFindings": len(findings),
            "findings": findings,
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "Bandit",
            "status": "failed",
            "error": "Bandit scan timed out.",
            "findings": [],
        }

    except (json.JSONDecodeError, OSError) as error:
        return {
            "scanner": "Bandit",
            "status": "failed",
            "error": str(error),
            "findings": [],
        }
