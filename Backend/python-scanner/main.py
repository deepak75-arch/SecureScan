
import json
import sys
from pathlib import Path

from scanners.bandit_scanner import scan_bandit
from scanners.semgrep_scanner import scan_semgrep


def main():
    if len(sys.argv) != 2:
        print(json.dumps({
            "success": False,
            "error": "Usage: python main.py <project_directory>"
        }))
        sys.exit(1)

    target_dir = Path(sys.argv[1]).resolve()

    if not target_dir.is_dir():
        print(json.dumps({
            "success": False,
            "error": "Project directory does not exist."
        }))
        sys.exit(1)

    # Run the scanners independently.
    semgrep_result = scan_semgrep(str(target_dir))
    bandit_result = scan_bandit(str(target_dir))

    results = [semgrep_result, bandit_result]

    all_findings = []

    for result in results:
        all_findings.extend(result.get("findings", []))

    completed = all(
        result["status"] == "completed"
        for result in results
    )

    output = {
        "success": completed,
        "projectDirectory": str(target_dir),
        "status": "completed" if completed else "partial",
        "scanners": results,
        "totalFindings": len(all_findings),
        "findings": all_findings,
    }

    # stdout contains JSON only, so Node.js can parse it.
    print(json.dumps(output))

    if not completed:
        sys.exit(1)


if __name__ == "__main__":
    main()
