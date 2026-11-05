import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Download,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  LoaderCircle,
  RefreshCw,
} from "lucide-react";

import {
  getScanAccessToken,
  removeScanAccess,
} from "../utils/scanAccess";

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

const severityOptions = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

function formatDate(dateValue) {
  if (!dateValue) return "—";

  return new Date(dateValue).toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function ScanDetails() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [filter, setFilter] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);

  const fetchScan = useCallback(async () => {
    try {
      const accessToken = getScanAccessToken(scanId);

      if (!accessToken) {
        throw new Error(
          "Private scan access is unavailable in this browser session. Start a new scan to receive access."
        );
      }

      const response = await fetch(
        `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
          cache: "no-store",
        }
      );

      const data = await response.json().catch(() => ({}));

      if (response.status === 401) {
        removeScanAccess(scanId);
        throw new Error(
          "Scan authorization is invalid or expired. Start a new scan to receive a new access token."
        );
      }

      if (!response.ok || !data.success) {
        throw new Error(
          data.message || `Unable to load scan details (HTTP ${response.status}).`
        );
      }

      setScan(data.scan || data);
      setError("");
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      fetchScan();
    }, 0);

    return () => window.clearTimeout(timer);
  }, [fetchScan]);

  // Refresh automatically while the scan is still running.
  useEffect(() => {
    if (!scan || !["queued", "scanning"].includes(scan.status)) {
      return;
    }

    const timer = setInterval(fetchScan, 3000);

    return () => clearInterval(timer);
  }, [scan, fetchScan]);

  const findings = scan?.findings || [];

  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  findings.forEach((finding) => {
    const severity = String(
      finding.severity || "info"
    ).toLowerCase();

    if (
      Object.prototype.hasOwnProperty.call(
        severityCounts,
        severity
      )
    ) {
      severityCounts[severity] += 1;
    } else {
      severityCounts.info += 1;
    }
  });

  const filteredFindings = findings.filter((finding) => {
    return (
      filter === "All" ||
      String(finding.severity).toLowerCase() ===
        filter.toLowerCase()
    );
  });

  const downloadReport = async () => {
    try {
      setDownloading(true);
      setError("");

      const accessToken = getScanAccessToken(scanId);

      if (!accessToken) {
        throw new Error(
          "Private report access is unavailable in this browser session."
        );
      }

      const response = await fetch(
        `${API_BASE_URL}/api/reports/${encodeURIComponent(scanId)}/pdf`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
          cache: "no-store",
        }
      );

      if (!response.ok) {
        let message = "Unable to download the PDF report.";

        try {
          const data = await response.json();
          message = data.message || message;
        } catch {
          // The response may be a PDF or non-JSON error.
        }

        throw new Error(message);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = `Secure-Scan-${scanId}.pdf`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 1000);
    } catch (err) {
      setError(err.message || "Report download failed.");
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <section className="content">
        <p>
          <LoaderCircle size={18} className="spin" />
          Loading scan details...
        </p>
      </section>
    );
  }

  if (error && !scan) {
    return (
      <section className="content">
        <button
          className="secondary-button"
          onClick={() => navigate("/history")}
        >
          <ArrowLeft size={16} />
          Back to History
        </button>

        <p className="demo-notice">{error}</p>

        <button
          className="secondary-button"
          onClick={() => {
            setLoading(true);
            fetchScan();
          }}
        >
          <RefreshCw size={16} />
          Try Again
        </button>
      </section>
    );
  }

  if (!scan) return null;

  const status = scan.status || "unknown";

  return (
    <section className="content">
      <div className="page-heading">
        <button
          className="secondary-button"
          onClick={() => navigate("/history")}
        >
          <ArrowLeft size={16} />
          Back to History
        </button>

        <span className="eyebrow">WORKSPACE / SCAN DETAILS</span>

        <h1>{scan.projectName || "Untitled Project"}</h1>

        <p>Scan ID: {scan.scanId || scanId}</p>
      </div>

      <div className="table-toolbar">
        <div>
          <h3>Security assessment</h3>

          <p>
            Started: {formatDate(scan.startedAt || scan.createdAt)}
          </p>

          {scan.completedAt && (
            <p>Completed: {formatDate(scan.completedAt)}</p>
          )}
        </div>

        <span
          className={`status-badge ${
            status === "completed"
              ? "completed"
              : status === "failed"
              ? "failed"
              : "scanning"
          }`}
        >
          {status === "completed" ? (
            <CheckCircle2 size={14} />
          ) : status === "failed" ? (
            <XCircle size={14} />
          ) : (
            <LoaderCircle size={14} className="spin" />
          )}

          {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
      </div>

      {["queued", "scanning"].includes(status) && (
        <p className="demo-notice">
          Your security scan is still running. This page refreshes automatically.
        </p>
      )}

      {status === "failed" && (
        <p className="demo-notice">
          Scan failed: {scan.errorMessage || "An unknown error occurred."}
        </p>
      )}

      <div className="stats">
        <div className="stat-card">
          <span>Total Files</span>
          <h2>{scan.totalFiles ?? 0}</h2>
        </div>

        <div className="stat-card">
          <span>Total Findings</span>
          <h2>{findings.length}</h2>
        </div>

        <div className="stat-card">
          <span>Critical Issues</span>
          <h2>{severityCounts.critical}</h2>
        </div>

        <div className="stat-card">
          <span>High Issues</span>
          <h2>{severityCounts.high}</h2>
        </div>
      </div>

      <div className="stats">
        {["critical", "high", "medium", "low", "info"].map(
          (severity) => (
            <div className="stat-card" key={severity}>
              <span>
                {severity.charAt(0).toUpperCase() + severity.slice(1)}
              </span>

              <h2>{severityCounts[severity]}</h2>
            </div>
          )
        )}
      </div>

      <div className="table-container">
        <div className="table-toolbar">
          <div>
            <h3>Security Findings</h3>
            <p>Review detected issues and recommended fixes.</p>
          </div>

          <select
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          >
            {severityOptions.map((severity) => (
              <option key={severity} value={severity}>
                {severity === "All"
                  ? "All Severities"
                  : severity}
              </option>
            ))}
          </select>
        </div>

        {filteredFindings.length === 0 ? (
          <p className="no-results">
            {findings.length === 0
              ? status === "completed"
                ? "No findings were reported by the configured scanners."
                : "No findings are available yet."
              : "No findings match this severity filter."}
          </p>
        ) : (
          <div className="finding-list">
            {filteredFindings.map((finding, index) => (
              <article
                className="finding-card"
                key={`${finding._id || finding.ruleId || "finding"}-${index}`}
              >
                <div className="finding-heading">
                  <div>
                    <h3>
                      {finding.title ||
                        finding.ruleId ||
                        "Security Finding"}
                    </h3>

                    <span
                      className={`severity-badge ${String(
                        finding.severity || "info"
                      ).toLowerCase()}`}
                    >
                      {finding.severity || "Info"}
                    </span>
                  </div>

                  <span>{finding.scanner || "Scanner"}</span>
                </div>

                <p>
                  {finding.description || "No description provided."}
                </p>

                <p>
                  <strong>File:</strong>{" "}
                  {finding.filePath || "Not specified"}
                </p>

                <p>
                  <strong>Location:</strong>{" "}
                  {finding.line
                    ? `Line ${finding.line}`
                    : "Not specified"}
                  {finding.column
                    ? `, Column ${finding.column}`
                    : ""}
                </p>

                <div>
                  <strong>Recommendation</strong>

                  <p>
                    {finding.recommendation ||
                      "Review this finding and apply the appropriate security fix."}
                  </p>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>

      <div className="security-info">
        <ShieldCheck size={22} />

        <div>
          <strong>Security assessment notice</strong>

          <p>
            Results represent findings from the configured scanners.
            A scan with zero findings does not guarantee that the project
            is free from vulnerabilities.
          </p>
        </div>
      </div>

      {error && <p className="demo-notice">{error}</p>}

      <button
        className="primary-button"
        onClick={downloadReport}
        disabled={downloading || status !== "completed"}
      >
        {downloading ? (
          <LoaderCircle size={17} className="spin" />
        ) : (
          <Download size={17} />
        )}

        {downloading
          ? "Downloading..."
          : "Download PDF Report"}
      </button>
    </section>
  );
}

export default ScanDetails;