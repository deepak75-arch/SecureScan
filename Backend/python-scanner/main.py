
import json
import sys
from pathlib import Path

from scanners.bandit_scanner import scan_bandit
from scanners.semgrep_scanner import scan_semgrep


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".c": "C",
    ".h": "C/C++",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".html": "HTML",
    ".vue": "Vue",
    ".sql": "SQL",
}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}


def discover_languages(target_dir):
    languages = set()
    python_files = 0
    total_source_files = 0

    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue

        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        language = LANGUAGE_EXTENSIONS.get(path.suffix.lower())

        if language:
            languages.add(language)
            total_source_files += 1

            if language == "Python":
                python_files += 1

    return {
        "languages": sorted(languages),
        "pythonFiles": python_files,
        "totalSourceFiles": total_source_files,
    }


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

    coverage = discover_languages(target_dir)

    scanner_results = []

    # Semgrep supports multiple languages.
    semgrep_result = scan_semgrep(str(target_dir))
    scanner_results.append(semgrep_result)

    # Bandit only analyzes Python source files.
    if coverage["pythonFiles"] > 0:
        bandit_result = scan_bandit(str(target_dir))
        scanner_results.append(bandit_result)
    else:
        scanner_results.append({
            "scanner": "Bandit",
            "status": "skipped",
            "reason": "No Python source files were found.",
            "totalFindings": 0,
            "findings": [],
        })

    all_findings = []

    for result in scanner_results:
        all_findings.extend(result.get("findings", []))

    failed_scanners = [
        result["scanner"]
        for result in scanner_results
        if result["status"] == "failed"
    ]

    completed_scanners = [
        result["scanner"]
        for result in scanner_results
        if result["status"] == "completed"
    ]

    if failed_scanners and completed_scanners:
        overall_status = "partial"
    elif failed_scanners:
        overall_status = "failed"
    else:
        overall_status = "completed"

    output = {
        "success": overall_status == "completed",
        "status": overall_status,
        "projectDirectory": str(target_dir),

        "coverage": {
            "detectedLanguages": coverage["languages"],
            "totalSourceFiles": coverage["totalSourceFiles"],
            "pythonFiles": coverage["pythonFiles"],
        },

        "scanners": scanner_results,
        "totalFindings": len(all_findings),
        "findings": all_findings,
    }

    # stdout must contain JSON only.
    print(json.dumps(output))

    if overall_status != "completed":
        sys.exit(1)


if __name__ == "__main__":
    main()
