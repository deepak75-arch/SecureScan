import { useEffect, useMemo, useState } from "react";
import {
  Search,
  Eye,
  CheckCircle2,
  XCircle,
  Clock,
  LoaderCircle,
} from "lucide-react";

import { fetchAuthorizedScans } from "../utils/scanAccess";

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

function formatDate(dateValue) {
  if (!dateValue) return "—";

  return new Date(dateValue).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

function formatStatus(status) {
  const labels = {
    completed: "Completed",
    failed: "Failed",
    scanning: "Scanning",
    queued: "Queued",
  };

  return labels[status] || status;
}

function ScanHistory() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchScans = async () => {
      try {
        setLoading(true);
        setError("");

        const authorizedScans =
          await fetchAuthorizedScans(API_BASE_URL);

        setScans(authorizedScans);
      } catch (err) {
        setError(err.message || "Unable to load scan history.");
      } finally {
        setLoading(false);
      }
    };

    fetchScans();
  }, []);

  const filtered = useMemo(() => {
    return scans.filter((scan) => {
      const projectName =
        scan.projectName || "Untitled Project";

      const status = formatStatus(scan.status);

      return (
        projectName.toLowerCase().includes(search.toLowerCase()) &&
        (filter === "All" || status === filter)
      );
    });
  }, [scans, search, filter]);

  const totalScans = scans.length;

  const completedScans = scans.filter(
    (scan) => scan.status === "completed"
  ).length;

  const totalFindings = scans.reduce(
    (total, scan) => total + (scan.totalFindings || 0),
    0
  );

  return (
    <section className="content">
      <div className="page-heading">
        <span className="eyebrow">WORKSPACE / HISTORY</span>
        <h1>Scan History</h1>
        <p>Track and review your previous security scans.</p>
      </div>

      <div className="stats">
        <div className="stat-card">
          <span>Total Scans</span>
          <h2>{totalScans.toString().padStart(2, "0")}</h2>
        </div>

        <div className="stat-card">
          <span>Completed Scans</span>
          <h2>{completedScans.toString().padStart(2, "0")}</h2>
        </div>

        <div className="stat-card">
          <span>Total Findings</span>
          <h2>{totalFindings.toString().padStart(2, "0")}</h2>
        </div>
      </div>

      <div className="table-container">
        <div className="table-toolbar">
          <div>
            <h3>Previous scans</h3>
            <p>Review previous security assessments.</p>
          </div>

          <div className="table-controls">
            <div className="search-box">
              <Search size={17} />

              <input
                placeholder="Search projects..."
                value={search}
                onChange={(event) =>
                  setSearch(event.target.value)
                }
              />
            </div>

            <select
              value={filter}
              onChange={(event) =>
                setFilter(event.target.value)
              }
            >
              <option value="All">All Status</option>
              <option value="Completed">Completed</option>
              <option value="Scanning">Scanning</option>
              <option value="Queued">Queued</option>
              <option value="Failed">Failed</option>
            </select>
          </div>
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Project</th>
                <th>Date</th>
                <th>Files</th>
                <th>Findings</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" className="no-results">
                    <LoaderCircle size={18} className="spin" />
                    Loading scan history...
                  </td>
                </tr>
              ) : error ? (
                <tr>
                  <td colSpan="7" className="no-results">
                    {error}
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan="7" className="no-results">
                    No scans found in this browser session.
                  </td>
                </tr>
              ) : (
                filtered.map((scan) => {
                  const severityCounts =
                    scan.severityCounts || {};

                  const status = formatStatus(scan.status);

                  return (
                    <tr key={scan.scanId}>
                      <td>{scan.scanId}</td>

                      <td className="project-name">
                        {scan.projectName || "Untitled Project"}
                      </td>

                      <td>
                        {formatDate(
                          scan.createdAt || scan.startedAt
                        )}
                      </td>

                      <td>{scan.totalFiles ?? 0}</td>

                      <td>
                        <span className="critical">
                          {severityCounts.critical || 0} Critical
                        </span>
                        {" / "}
                        <span className="high">
                          {severityCounts.high || 0} High
                        </span>
                      </td>

                      <td>
                        <span
                          className={`status-badge ${
                            scan.status === "completed"
                              ? "completed"
                              : scan.status === "failed"
                              ? "failed"
                              : "scanning"
                          }`}
                        >
                          {scan.status === "completed" ? (
                            <CheckCircle2 size={13} />
                          ) : scan.status === "failed" ? (
                            <XCircle size={13} />
                          ) : (
                            <Clock size={13} />
                          )}

                          {status}
                        </span>
                      </td>

                      <td>
                        <a
                          className="icon-button"
                          title="View scan"
                          href={`/scans/${encodeURIComponent(scan.scanId)}`}
                          aria-label="View scan"
                        >
                          <Eye size={17} />
                        </a>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="demo-notice">
        Scan history displays scans whose private access tokens are saved
        in this browser session.
      </p>
    </section>
  );
}

export default ScanHistory;