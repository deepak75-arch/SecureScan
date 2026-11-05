
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  FileText,
  Download,
  CalendarDays,
  ShieldCheck,
  AlertCircle,
} from "lucide-react";

import {
  fetchAuthorizedScans,
  getScanAccessToken,
} from "../utils/scanAccess";

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

function Reports() {
  const [search, setSearch] = useState("");
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloadingId, setDownloadingId] = useState(null);

  const navigate = useNavigate();

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        setError("");

        const authorizedScans =
          await fetchAuthorizedScans(API_BASE_URL);

        setReports(authorizedScans);
      } catch (err) {
        setError(err.message || "Something went wrong.");
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  const completedReports = reports.filter(
    (report) => report.status === "completed"
  );

  const filtered = completedReports.filter((report) =>
    (report.projectName || "")
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  const totalCritical = completedReports.reduce(
    (total, report) =>
      total + (report.severityCounts?.critical || 0),
    0
  );

  const latestReport = completedReports[0];

  const formatDate = (date) => {
    if (!date) return "Date unavailable";

    return new Date(date).toLocaleDateString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  };

  const downloadReport = async (scanId) => {
    try {
      setDownloadingId(scanId);
      setError("");

      const accessToken = getScanAccessToken(scanId);

      if (!accessToken) {
        throw new Error(
          "Report access is unavailable in this browser session. Run a new scan to obtain access."
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
        throw new Error("Unable to download the PDF report.");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = `Secure-Scan-${scanId}.pdf`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || "PDF download failed.");
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <section className="content">
      <div className="page-heading">
        <span className="eyebrow">WORKSPACE / REPORTS</span>
        <h1>Security Reports</h1>
        <p>
          Review vulnerability findings and download security assessment reports.
        </p>
      </div>

      {/* Statistics */}
      <div className="stats">
        <div className="stat-card">
          <FileText size={22} />
          <div>
            <span>Total Reports</span>
            <h2>{completedReports.length}</h2>
          </div>
        </div>

        <div className="stat-card">
          <CalendarDays size={22} />
          <div>
            <span>Latest Report</span>
            <h2>
              {latestReport
                ? formatDate(latestReport.completedAt)
                : "—"}
            </h2>
          </div>
        </div>

        <div className="stat-card">
          <AlertCircle size={22} />
          <div>
            <span>Critical Findings</span>
            <h2>{totalCritical}</h2>
          </div>
        </div>
      </div>

      {/* Reports */}
      <div className="table-container">
        <div className="table-toolbar">
          <div>
            <h3>Generated reports</h3>
            <p>Download your completed security assessments.</p>
          </div>

          <div className="search-box">
            <Search size={17} />
            <input
              placeholder="Search reports..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        {error && (
          <p className="no-results" role="alert">
            {error}
          </p>
        )}

        {loading ? (
          <p className="no-results">
            Loading security reports...
          </p>
        ) : filtered.length === 0 ? (
          <p className="no-results">
            {search
              ? "No matching reports found."
              : "No completed security reports yet. Run a scan to generate your first report."}
          </p>
        ) : (
          <div className="report-grid">
            {filtered.map((report) => {
              const counts = report.severityCounts || {};

              return (
                <div className="report-card" key={report.scanId}>
                  <div className="report-card-header">
                    <div className="report-icon">
                      <FileText size={23} />
                    </div>

                    <span className="report-id">
                      {report.scanId.slice(0, 8).toUpperCase()}
                    </span>
                  </div>

                  <h3>
                    {report.projectName || "Untitled Project"}
                  </h3>

                  <p className="report-date">
                    <CalendarDays size={14} />
                    {formatDate(report.completedAt)}
                  </p>

                  <div className="report-findings">
                    <div>
                      <span className="critical">
                        {counts.critical || 0}
                      </span>
                      <small>Critical</small>
                    </div>

                    <div>
                      <span className="high">
                        {counts.high || 0}
                      </span>
                      <small>High</small>
                    </div>

                    <div>
                      <span className="medium">
                        {counts.medium || 0}
                      </span>
                      <small>Medium</small>
                    </div>

                    <div>
                      <span className="low">
                        {counts.low || 0}
                      </span>
                      <small>Low</small>
                    </div>
                  </div>

                  <div className="report-score">
                    <span>Total findings</span>
                    <strong>
                      {report.totalFindings || 0}
                    </strong>
                  </div>

                  <div className="report-actions">
                    <button
                      className="primary-button"
                      onClick={() => downloadReport(report.scanId)}
                      disabled={downloadingId !== null}
                    >
                      {downloadingId === report.scanId ? (
                        <>Preparing PDF...</>
                      ) : (
                        <>
                          <Download size={15} />
                          Download PDF
                        </>
                      )}
                    </button>

                    <button
                      className="secondary-button"
                      onClick={() =>
                        navigate(
                          `/scans/${encodeURIComponent(report.scanId)}`
                        )
                      }
                    >
                      View Details
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <p className="demo-notice">
        <ShieldCheck size={15} />
        Reports are generated from completed security scans.
      </p>
    </section>
  );
}

export default Reports;
