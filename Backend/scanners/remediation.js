// Backend/scanners/remediation.js

const REMEDIATION_GUIDES = {
  "CWE-89": {
    title: "SQL Injection",
    summary:
      "Untrusted input is incorporated into an SQL query. An attacker may manipulate the query to access or modify database records.",
    cweGuidance:
      "CWE-89: Never construct SQL commands by concatenating or formatting untrusted input. Use parameterized queries or a trusted ORM.",
    steps: [
      "Replace dynamic SQL string concatenation with parameterized queries.",
      "Pass user-controlled values as query parameters.",
      "Use an ORM where appropriate.",
      "Apply least-privilege permissions to the database account.",
      "Validate input according to the expected business format. Do not rely on validation as a replacement for parameterization."
    ],
    examples: {
      ".py": {
        language: "Python",
        insecure: `query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)`,
        secure: `query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (username,))`
      },
      ".js": {
        language: "JavaScript",
        insecure: `const query = "SELECT * FROM users WHERE name = '" + username + "'";
db.query(query);`,
        secure: `const query = "SELECT * FROM users WHERE name = ?";
db.query(query, [username]);`
      },
      ".ts": {
        language: "TypeScript",
        insecure: `const query = \`SELECT * FROM users WHERE name = '\${username}'\`;
db.query(query);`,
        secure: `const query = "SELECT * FROM users WHERE name = ?";
db.query(query, [username]);`
      },
      ".java": {
        language: "Java",
        insecure: `String query = "SELECT * FROM users WHERE name = '" + username + "'";
Statement stmt = connection.createStatement();
stmt.executeQuery(query);`,
        secure: `String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
stmt.executeQuery();`
      },
      ".php": {
        language: "PHP",
        insecure: `$query = "SELECT * FROM users WHERE name = '$username'";
mysqli_query($connection, $query);`,
        secure: `$stmt = $connection->prepare(
    "SELECT * FROM users WHERE name = ?"
);
$stmt->bind_param("s", $username);
$stmt->execute();`
      },
      ".cs": {
        language: "C#",
        insecure: `string query = "SELECT * FROM Users WHERE Name = '" + username + "'";
using var command = new SqlCommand(query, connection);`,
        secure: `string query = "SELECT * FROM Users WHERE Name = @name";
using var command = new SqlCommand(query, connection);
command.Parameters.AddWithValue("@name", username);`
      },
      ".go": {
        language: "Go",
        insecure: `query := fmt.Sprintf(
    "SELECT * FROM users WHERE name = '%s'", username,
)
db.Query(query)`,
        secure: `query := "SELECT * FROM users WHERE name = ?"
db.Query(query, username)`
      }
    }
  },

  "CWE-78": {
    title: "OS Command Injection",
    summary:
      "Untrusted input is passed to an operating-system command. This may allow an attacker to execute unintended commands.",
    cweGuidance:
      "CWE-78: Avoid constructing shell commands from user-controlled strings. Prefer safe APIs and pass executable arguments separately.",
    steps: [
      "Avoid shell=True or equivalent shell execution when possible.",
      "Use APIs that do not invoke a command shell.",
      "Pass executable arguments as separate array elements.",
      "Validate input against a strict allowlist.",
      "Use fixed executable paths and restrict the commands the application can invoke."
    ],
    examples: {
      ".py": {
        language: "Python",
        insecure: `subprocess.call("ping " + host, shell=True)`,
        secure: `subprocess.run(
    ["ping", "-c", "1", host],
    shell=False,
    check=True
)`
      },
      ".js": {
        language: "JavaScript",
        insecure: `exec("ping " + host);`,
        secure: `execFile("ping", ["-c", "1", host], (error, stdout) => {
    if (error) {
        throw error;
    }
});`
      }
    }
  },

  "CWE-95": {
    title: "Eval Injection",
    summary:
      "Dynamic input is evaluated as executable code. If an attacker controls that input, arbitrary code may execute.",
    cweGuidance:
      "CWE-95: Avoid evaluating dynamically constructed code. Parse data using safe parsers and use explicit application logic.",
    steps: [
      "Remove eval() or equivalent dynamic code execution.",
      "Use JSON.parse() when the input is JSON data.",
      "Use a parser designed for the required data format.",
      "Validate parsed data against an expected schema.",
      "Never treat user input as executable application code."
    ],
    examples: {
      ".js": {
        language: "JavaScript",
        insecure: `const result = eval(userInput);`,
        secure: `const result = JSON.parse(userInput);`
      },
      ".ts": {
        language: "TypeScript",
        insecure: `const result = eval(userInput);`,
        secure: `const result: unknown = JSON.parse(userInput);`
      }
    }
  },

  "CWE-502": {
    title: "Insecure Deserialization",
    summary:
      "The application deserializes data that may be untrusted. Crafted serialized objects can trigger unsafe behavior during deserialization.",
    cweGuidance:
      "CWE-502: Do not deserialize untrusted data using object-deserialization mechanisms that can instantiate arbitrary objects.",
    steps: [
      "Avoid pickle or equivalent unsafe object deserialization for untrusted input.",
      "Prefer JSON or another data-only serialization format.",
      "Validate the structure and types of deserialized data.",
      "Apply size and resource limits to incoming data.",
      "Authenticate and authorize the source of sensitive data."
    ],
    examples: {
      ".py": {
        language: "Python",
        insecure: `data = pickle.loads(user_supplied_data)`,
        secure: `import json

data = json.loads(user_supplied_data)
if not isinstance(data, dict):
    raise ValueError("Invalid data format")`
      }
    }
  },

  "CWE-798": {
    title: "Hardcoded Credentials",
    summary:
      "Credentials or sensitive authentication values are embedded directly in source code. They may be exposed through repositories, logs, or application packages.",
    cweGuidance:
      "CWE-798: Do not hardcode passwords, API keys, or authentication tokens. Store secrets in a protected secret-management system.",
    steps: [
      "Remove the hardcoded credential from source code.",
      "Rotate the credential if it may have been exposed.",
      "Load secrets from environment variables or a secrets manager.",
      "Restrict access to secrets using least privilege.",
      "Add secret scanning to the development and CI/CD workflow."
    ],
    examples: {
      ".py": {
        language: "Python",
        insecure: `API_KEY = "actual-secret-value"`,
        secure: `import os

API_KEY = os.environ["API_KEY"]`
      },
      ".js": {
        language: "JavaScript",
        insecure: `const apiKey = "actual-secret-value";`,
        secure: `const apiKey = process.env.API_KEY;

if (!apiKey) {
    throw new Error("API_KEY is not configured");
}`
      }
    }
  }
};

const GITLEAKS_GUIDE = {
  title: "Exposed Secret or Credential",
  summary:
    "A potential secret was detected in the repository. If it is genuine, an unauthorized person may use it to access a service or system.",
  cweGuidance:
    "Protect credentials throughout their lifecycle. Remove exposed secrets from source control and rotate any credential that may have been compromised.",
  steps: [
    "Identify the type and owner of the detected credential.",
    "Revoke or rotate it immediately if it is genuine.",
    "Remove the secret from the source code and replace it with a secure secret reference.",
    "Review repository history and access logs for possible exposure.",
    "Store replacement credentials in a secrets manager or protected environment configuration."
  ],
  examples: {
    ".env": {
      language: "Environment configuration",
      insecure: `API_KEY=actual-secret-value`,
      secure: `API_KEY=<load-from-secret-manager>`
    }
  }
};

const EXTENSION_LANGUAGE = {
  ".py": "python",
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".java": "java",
  ".php": "php",
  ".cs": "csharp",
  ".go": "go"
};

function normalizeCweIds(cwe) {
  const values = Array.isArray(cwe)
    ? cwe
    : cwe == null
      ? []
      : [cwe];

  return [
    ...new Set(
      values.flatMap((value) => {
        const text =
          typeof value === "object"
            ? JSON.stringify(value)
            : String(value);

        return (
          text.match(/CWE-\d+/gi) || []
        ).map((id) => id.toUpperCase());
      })
    )
  ];
}

function getRuleId(finding) {
  return String(finding.ruleId || "").toLowerCase();
}

function getGuide(finding) {
  const ruleId = getRuleId(finding);
  const scanner = String(finding.scanner || "").toLowerCase();

  // Gitleaks findings may not contain CWE metadata.
  if (scanner === "gitleaks") {
    return GITLEAKS_GUIDE;
  }

  // Rule-specific mappings take precedence.
  if (
    ["b301"].includes(ruleId) ||
    ruleId.includes("pickle")
  ) {
    return REMEDIATION_GUIDES["CWE-502"];
  }

  if (
    ["b602", "b603", "b605", "b607"].includes(ruleId) ||
    ruleId.includes("subprocess-shell-true")
  ) {
    return REMEDIATION_GUIDES["CWE-78"];
  }

  if (
    ruleId.includes("eval-detected") ||
    ruleId.includes("eval")
  ) {
    return REMEDIATION_GUIDES["CWE-95"];
  }

  const cweIds = normalizeCweIds(finding.cwe);

  for (const cweId of cweIds) {
    if (REMEDIATION_GUIDES[cweId]) {
      return REMEDIATION_GUIDES[cweId];
    }
  }

  return null;
}

export function getRemediation(finding) {
  const guide = getGuide(finding);

  if (!guide) {
    return {
      available: false,
      title: "Remediation guidance unavailable",
      summary:
        "No rule-specific remediation guide is currently configured for this finding.",
      cweGuidance:
        "Review the scanner description and the referenced CWE documentation.",
      steps: [
        "Inspect the affected code and verify the finding.",
        "Consult the scanner rule documentation.",
        "Apply a secure coding fix appropriate to the programming language."
      ],
      insecureExample: "",
      secureExample: "",
      exampleLanguage: "",
      references: finding.references || []
    };
  }

  const extension = finding.filePath
    ? finding.filePath
        .toLowerCase()
        .match(/\.[a-z0-9]+$/)?.[0]
    : "";

  const example = guide.examples?.[extension] || null;

  return {
    available: true,
    title: guide.title,
    summary: guide.summary,
    cweGuidance: guide.cweGuidance,
    steps: guide.steps,
    exampleLanguage:
      example?.language ||
      EXTENSION_LANGUAGE[extension] ||
      "General",
    insecureExample: example?.insecure || "",
    secureExample: example?.secure || "",
    references: finding.references || []
  };
}