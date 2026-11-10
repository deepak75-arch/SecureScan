# 🛡️ SecureScan

### Automated Application Security Scanning and Vulnerability Assessment Platform

SecureScan AI is a web-based application security scanning platform designed to identify potential security vulnerabilities, insecure coding practices, and exposed secrets in source code projects.

The platform allows developers to upload individual source files, ZIP archives, or complete project folders and automatically analyzes them using integrated security scanning tools. It provides a centralized dashboard, detailed vulnerability findings, remediation recommendations, and downloadable PDF security assessment reports.

---

## 🚀 Key Features

- **Multi-file and Project Upload:** Upload individual files, ZIP archives, or complete source code folders.
- **Automated Security Scanning:** Integrates multiple security analysis tools into a unified scanning workflow.
- **Static Application Security Testing (SAST):** Detects insecure coding patterns and potential vulnerabilities.
- **Multi-language Support:** Supports source code analysis across several programming languages.
- **Secret Detection:** Identifies potentially exposed API keys, credentials, and sensitive information.
- **Vulnerability Classification:** Categorizes findings based on severity: Critical, High, Medium, Low, and Informational.
- **Remediation Guidance:** Provides vulnerability-specific recommendations and secure coding examples where available.
- **Security Dashboard:** Displays scan statistics, findings, and scan results.
- **Detailed Scan Reports:** Provides detailed vulnerability information, affected file paths, line numbers, and recommendations.
- **PDF Report Generation:** Generates downloadable security assessment reports.
- **Private Scan Access:** Uses authorization tokens to protect access to uploaded projects and scan results.

---

## 🏗️ System Architecture

```text
                 ┌─────────────────────────┐
                 │      React Frontend     │
                 │                         │
                 │ Dashboard / Upload      │
                 │ Scan Results / Reports  │
                 └────────────┬────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │     Node.js Backend     │
                 │      Express.js API     │
                 │                         │
                 │ Upload Management      │
                 │ Scan Orchestration     │
                 │ Authentication         │
                 │ Report Generation      │
                 └────────────┬────────────┘
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
       ┌──────────────────┐        ┌──────────────────┐
       │  Python Scanner  │        │  Gitleaks        │
       │                  │        │                  │
       │  Semgrep         │        │  Secret Detection│
       │  Bandit          │        │                  │
       └────────┬─────────┘        └─────────┬────────┘
                │                            │
                └─────────────┬──────────────┘
                              ▼
                 ┌─────────────────────────┐
                 │        MongoDB          │
                 │                         │
                 │ Scan Results            │
                 │ Findings                │
                 │ Scanner Execution Data │
                 └─────────────────────────┘
```

---

## 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Frontend | React.js, Vite, JavaScript, CSS |
| Backend | Node.js, Express.js |
| Database | MongoDB |
| Python Integration | Python |
| SAST | Semgrep |
| Python Security Analysis | Bandit |
| Secret Detection | Gitleaks |
| PDF Generation | PDFKit |
| Authentication | Token-based scan access |
| Deployment | Netlify, Render |

---

## 🔍 Integrated Security Scanners

### 1. Semgrep
Performs static analysis to identify insecure coding patterns and potential vulnerabilities across supported programming languages.

### 2. Bandit
Analyzes Python source code to identify common security issues, including insecure function usage, unsafe subprocess operations, and potential injection vulnerabilities.

### 3. Gitleaks
Scans project files for potentially exposed secrets, credentials, API keys, and other sensitive information.

---

## 💻 Supported Languages

The scanner pipeline is configured to recognize source files including:

- Python
- JavaScript
- TypeScript
- Java
- C
- C++
- C#
- PHP
- Go
- Ruby
- Rust
- Kotlin
- Swift
- HTML
- Vue
- SQL

Actual vulnerability coverage depends on the configured scanner and its supported rules.

---

## 📊 Vulnerability Assessment

Findings are organized by severity:

| Severity | Description |
|---|---|
| Critical | Extremely serious security issues requiring immediate attention |
| High | Significant vulnerabilities that should be addressed promptly |
| Medium | Security weaknesses requiring remediation |
| Low | Lower-impact security issues |
| Informational | Security observations and recommendations |

Each finding can include:

- Vulnerability title
- Description
- Severity
- Scanner source
- Affected file
- Line number
- CWE classification
- OWASP classification
- Remediation recommendation
- Secure coding guidance, where available

---

## ⚙️ Installation and Setup

### Prerequisites

Install the following before running the project:

- Node.js
- npm
- Python 3
- MongoDB
- Git
- Semgrep
- Bandit
- Gitleaks

### 1. Clone the Repository

```bash
git clone https://github.com/deepak75-arch/SecureScan.git
cd SecureScan
```

### 2. Frontend Setup

```bash
cd frontend
npm install
```

Create a `.env` file inside the frontend directory:

```env
VITE_API_URL=http://localhost:5000
```

Start the frontend development server:

```bash
npm run dev
```

### 3. Backend Setup

Open another terminal:

```bash
cd Backend
npm install
```

Configure the backend environment variables in `Backend/.env`:

```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
FRONTEND_URL=http://localhost:5173
```

Use your actual database connection string. Never commit `.env` files or credentials to GitHub.

Start the backend:

```bash
npm run dev
```

### 4. Python Scanner Setup

Open another terminal:

```bash
cd Backend/python-scanner
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

Run the scanner:

```bash
python main.py "path/to/project"
```

Ensure Semgrep, Bandit, and Gitleaks are installed and configured according to the scanner integration requirements.

---

## ☁️ Deployment

SecureScan AI uses the following deployment architecture:

| Component | Platform |
|---|---|
| Frontend | Netlify |
| Backend | Render |
| Database | MongoDB |

**Live Application:** [SecureScan AI](https://securescan987.netlify.app/)

The frontend communicates with the deployed backend through the configured API URL.

---

## 🔐 Security Considerations

- Uploaded files are subject to file type and size validation.
- Upload authorization is required before project uploads.
- Scan access is protected using private access tokens.
- Sensitive tokens are not intended to be exposed in public scan history.
- Environment variables are used for deployment configuration.
- Automated scan results should be manually reviewed before treating findings as confirmed vulnerabilities.

---

## 🎯 Project Objective

The primary objective of SecureScan AI is to simplify application security assessment by combining multiple security scanning tools into one centralized platform.

It aims to help developers identify potential vulnerabilities earlier in the development lifecycle, understand security risks, and apply appropriate remediation techniques.

---

## 🔮 Future Enhancements

- Integration of additional security scanning engines.
- Enhanced vulnerability correlation and deduplication.
- Advanced vulnerability visualization and analytics.
- More detailed remediation examples across programming languages.
- CI/CD pipeline integration.
- Continuous security monitoring.

---

## 👨‍💻 Author

**Deepak R**

Computer Science and Engineering

GitHub: [deepak75-arch](https://github.com/deepak75-arch)

---

## 📄 License

This project is developed as an academic and portfolio project. Add an appropriate open-source license before permitting reuse or redistribution.
