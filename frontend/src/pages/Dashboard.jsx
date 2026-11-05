import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  UploadCloud,
  FolderUp,
  FileCode2,
  Trash2,
  ShieldCheck,
  ScanSearch,
  FileText,
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
} from "lucide-react";

import {
  saveScanAccess,
  getScanAccessToken,
  fetchAuthorizedScans,
} from "../utils/scanAccess";
import {
  saveUploadAccess,
  getUploadAccessToken,
} from "../utils/uploadAccess";

const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:5000";

const allowedExtensions = [
  ".zip", ".js", ".jsx", ".ts", ".tsx", ".py",
  ".java", ".php", ".go", ".html", ".css",
  ".json", ".yml", ".yaml", ".toml", ".xml",
  ".sql", ".sh", ".c", ".cpp", ".cs",
];

function Dashboard() {
  const navigate = useNavigate();

  const [files, setFiles] = useState([]);
  const [uploadConsent, setUploadConsent] = useState(false);
  const [projectName, setProjectName] = useState("");
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [error, setError] = useState("");

  const [stats, setStats] = useState({
    totalScans: 0,
    totalFindings: 0,
    completedScans: 0,
    generatedReports: 0,
  });

  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  // Load only scans accessible in this browser session.
  useEffect(() => {
    const fetchDashboardStats = async () => {
      try {
        const scans = await fetchAuthorizedScans(API_BASE_URL);

        const completed = scans.filter(
          (scan) => scan.status === "completed"
        );

        const findings = scans.reduce(
          (total, scan) => total + (scan.totalFindings || 0),
          0
        );

        setStats({
          totalScans: scans.length,
          totalFindings: findings,
          completedScans: completed.length,
          generatedReports: completed.length,
        });
      } catch (err) {
        console.error("Dashboard stats error:", err);
      }
    };

    fetchDashboardStats();
  }, []);

  const validateFiles = (selectedFiles) => {
    const validFiles = [];
    const errors = [];

    Array.from(selectedFiles).forEach((file) => {
      const fileName = file.name.toLowerCase();
      const extension = "." + fileName.split(".").pop();

      if (!allowedExtensions.includes(extension)) {
        errors.push(`${file.name}: Unsupported file type`);
      } else if (file.size === 0) {
        errors.push(`${file.name}: Empty files are not allowed`);
      } else if (file.size > 50 * 1024 * 1024) {
        errors.push(`${file.name}: File exceeds 50 MB`);
      } else {
        validFiles.push(file);
      }
    });

    if (errors.length) {
      alert(errors.join("\n"));
    }

    setFiles((previous) => {
      const existing = new Set(
        previous.map(
          (file) =>
            `${file.name}-${file.size}-${file.lastModified}`
        )
      );

      const newFiles = validFiles.filter(
        (file) =>
          !existing.has(
            `${file.name}-${file.size}-${file.lastModified}`
          )
      );

      return [...previous, ...newFiles];
    });

    setError("");
  };

  const removeFile = (index) => {
    setFiles((previous) =>
      previous.filter((_, i) => i !== index)
    );
  };

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;

    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }

    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    validateFiles(event.dataTransfer.files);
  };

const startScan = async () => {
  if (!uploadConsent) {
    setError(
      "Please confirm that you have permission to scan these files."
    );
    return;
  }

  if (!files.length) {
    setError("Please upload files before starting a scan.");
    return;
  }

  const zipFiles = files.filter((file) =>
    file.name.toLowerCase().endsWith(".zip")
  );

  if (zipFiles.length > 0 && files.length > 1) {
    setError(
      "Please upload one ZIP archive at a time. Do not mix ZIP files with individual source files."
    );
    return;
  }

  const totalSize = files.reduce(
    (sum, file) => sum + file.size,
    0
  );

  if (totalSize > 200 * 1024 * 1024) {
    setError("The total upload size cannot exceed 200 MB.");
    return;
  }

  try {
    setScanning(true);
    setError("");
    setScanMessage("Uploading your project...");

    // STEP 1: Upload files.
    const formData = new FormData();

    formData.append(
      "projectName",
      projectName.trim() || "Untitled Project"
    );

    files.forEach((file) => {
      formData.append(
        "files",
        file,
        file.webkitRelativePath || file.name
      );
    });

    const uploadResponse = await fetch(
      `${API_BASE_URL}/api/uploads`,
      {
        method: "POST",
        headers: {
          "X-Upload-Consent": String(uploadConsent),
        },
        body: formData,
      }
    );

    const uploadData = await uploadResponse.json();

    if (!uploadResponse.ok || !uploadData.success) {
      throw new Error(
        uploadData.message || "Project upload failed."
      );
    }

    // Get upload ID and token from backend.
    const uploadId = uploadData.upload?.uploadId;
    const uploadAccessToken = uploadData.upload?.accessToken;

    if (!uploadId || !uploadAccessToken) {
      throw new Error(
        "Upload ID or authorization token was not returned by the backend."
      );
    }

    // STEP 2: Save upload token in sessionStorage.
    saveUploadAccess(uploadId, uploadAccessToken);

    // STEP 3: Retrieve the saved upload token.
    const storedUploadToken =
      getUploadAccessToken(uploadId);

    if (!storedUploadToken) {
      throw new Error(
        "Could not retrieve the upload authorization token."
      );
    }

    // STEP 4: Extract ZIP archive if necessary.
    if (zipFiles.length === 1) {
      setScanMessage("Extracting ZIP archive...");

      const extractResponse = await fetch(
        `${API_BASE_URL}/api/uploads/${encodeURIComponent(uploadId)}/extract`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${storedUploadToken}`,
          },
          cache: "no-store",
        }
      );

      const extractData = await extractResponse.json();

      if (!extractResponse.ok || !extractData.success) {
        throw new Error(
          extractData.message || "Project extraction failed."
        );
      }
    }

    // STEP 5: Start security scan.
    setScanMessage("Starting security scanners...");

    const scanResponse = await fetch(
      `${API_BASE_URL}/api/scans/${encodeURIComponent(uploadId)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${storedUploadToken}`,
        },
        cache: "no-store",
      }
    );

    const scanData = await scanResponse.json();

    if (!scanResponse.ok || !scanData.success) {
      throw new Error(
        scanData.message || "Could not start the security scan."
      );
    }

    // STEP 6: Normalize common API response shapes.
    // Supports { scan, accessToken }, { data: { ... } }, and { result: { ... } }.
    const responseData = scanData.data || scanData;
    const scanPayload = responseData.scan || responseData.result || responseData;

    const scanId =
      scanPayload.scanId ||
      responseData.scanId ||
      scanData.scan?.scanId ||
      scanData.scanId ||
      scanData.result?.scanId;

    const scanAccessToken =
      responseData.accessToken ||
      scanPayload.accessToken ||
      scanData.accessToken ||
      scanData.scan?.accessToken ||
      scanData.result?.accessToken;

    if (!scanId) {
      throw new Error(
        "Scan started, but the scan ID was not returned by the backend."
      );
    }

    if (!scanAccessToken) {
      throw new Error(
        "The scan started, but the backend did not return a private scan access token. Check the POST /api/scans/:uploadId response."
      );
    }

    // STEP 7: Save and verify the private scan token in this browser tab.
    saveScanAccess(String(scanId), scanAccessToken);

    const verifiedToken = getScanAccessToken(String(scanId));
    if (!verifiedToken || verifiedToken !== scanAccessToken) {
      throw new Error(
        "The scan access token could not be saved in this browser session."
      );
    }

    // STEP 8: Navigate in the same tab so sessionStorage remains available.
    setScanMessage("Scan started successfully. Opening results...");
    navigate(`/scans/${encodeURIComponent(scanId)}`);

  } catch (err) {
    console.error("Scan initiation error:", err);

    setError(
      err.message ||
      "Something went wrong while starting the scan."
    );

    setScanMessage("");

  } finally {
    setScanning(false);
  }
};

  return (
    <section className="content">
      <div className="page-heading">
        <span className="eyebrow">WORKSPACE / DASHBOARD</span>
        <h1>Security Dashboard</h1>
        <p>
          Upload your source code and analyze it for security vulnerabilities.
        </p>
      </div>

      <div className="stats">
        <div className="stat-card">
          <div>
            <span>Total Scans</span>
            <h2>{stats.totalScans}</h2>
            <small>Scans accessible in this session</small>
          </div>
          <ScanSearch size={24} />
        </div>

        <div className="stat-card">
          <div>
            <span>Security Issues</span>
            <h2>{stats.totalFindings}</h2>
            <small>Findings from accessible scans</small>
          </div>
          <AlertTriangle size={24} />
        </div>

        <div className="stat-card">
          <div>
            <span>Completed Scans</span>
            <h2>{stats.completedScans}</h2>
            <small>Successfully completed</small>
          </div>
          <CheckCircle2 size={24} />
        </div>

        <div className="stat-card">
          <div>
            <span>Available Reports</span>
            <h2>{stats.generatedReports}</h2>
            <small>Reports available to download</small>
          </div>
          <FileText size={24} />
        </div>
      </div>

      <div className="upload-section">
        <div className="upload-consent">
          <label>
            <input
              type="checkbox"
              checked={uploadConsent}
              onChange={(event) => {
                setUploadConsent(event.target.checked);
                setError("");
              }}
              disabled={scanning}
            />

            I confirm that I own these files or have permission
            to scan them, and I authorize SecureScan to analyze
            their contents.
          </label>
        </div>

        <div className="section-heading">
          <div>
            <h2>Upload Project</h2>
            <p>
              Select a ZIP archive, individual files, or an entire project folder.
            </p>
          </div>

          <span className="secure-label">
            <ShieldCheck size={15} />
            Secure upload
          </span>
        </div>

        <div style={{ marginBottom: "16px" }}>
          <label htmlFor="projectName">Project Name</label>
          <input
            id="projectName"
            type="text"
            placeholder="Enter your project name"
            value={projectName}
            onChange={(event) =>
              setProjectName(event.target.value)
            }
            disabled={scanning}
            style={{
              display: "block",
              width: "100%",
              maxWidth: "420px",
              padding: "12px",
              marginTop: "8px",
            }}
          />
        </div>

        <div
          className={`upload-box ${dragging ? "dragging" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
        >
          <div className="upload-icon">
            <UploadCloud size={34} />
          </div>

          <h3>Drag and drop your project here</h3>
          <p>Upload a ZIP archive or supported source code files</p>

          <div className="upload-buttons">
            <button
              className="primary-button"
              onClick={() => fileInputRef.current?.click()}
              disabled={scanning}
            >
              <FileCode2 size={16} />
              Browse Files
            </button>

            <button
              className="secondary-button"
              onClick={() => folderInputRef.current?.click()}
              disabled={scanning}
            >
              <FolderUp size={16} />
              Upload Folder
            </button>
          </div>

          <small>
            Supported: ZIP, JS, JSX, TS, TSX, Python, Java, PHP, HTML, CSS and more
          </small>

          <small>Maximum file size: 50 MB per file</small>

          <input
            ref={fileInputRef}
            type="file"
            multiple
            accept={allowedExtensions.join(",")}
            hidden
            disabled={scanning}
            onChange={(event) => {
              validateFiles(event.target.files);
              event.target.value = "";
            }}
          />

          <input
            ref={folderInputRef}
            type="file"
            webkitdirectory=""
            directory=""
            multiple
            hidden
            disabled={scanning}
            onChange={(event) => {
              validateFiles(event.target.files);
              event.target.value = "";
            }}
          />
        </div>
      </div>

      {files.length > 0 && (
        <div className="selected-files">
          <div className="files-heading">
            <div>
              <h3>Selected Files</h3>
              <p>{files.length} file(s) ready for scanning</p>
            </div>

            <button
              className="clear-button"
              onClick={() => setFiles([])}
              disabled={scanning}
            >
              Clear all
            </button>
          </div>

          <div className="file-list">
            {files.map((file, index) => (
              <div
                className="file-item"
                key={`${file.name}-${index}`}
              >
                <div className="file-details">
                  <div className="file-icon">
                    <FileCode2 size={19} />
                  </div>

                  <div>
                    <strong>
                      {file.webkitRelativePath || file.name}
                    </strong>
                    <small>{formatSize(file.size)}</small>
                  </div>
                </div>

                <button
                  className="remove-button"
                  onClick={() => removeFile(index)}
                  title="Remove file"
                  disabled={scanning}
                >
                  <Trash2 size={17} />
                </button>
              </div>
            ))}
          </div>

          <div className="scan-footer">
            <span>{files.length} file(s) selected</span>

            <button
              className="primary-button scan-button"
              onClick={startScan}
              disabled={
                scanning ||
                !uploadConsent ||
                files.length === 0
              }
            >
              {scanning ? (
                <LoaderCircle size={17} className="spin" />
              ) : (
                <ScanSearch size={17} />
              )}

              {scanning ? "Processing..." : "Start Security Scan"}
            </button>
          </div>
        </div>
      )}

      {scanMessage && (
        <p className="demo-notice">{scanMessage}</p>
      )}

      {error && (
        <p className="demo-notice" role="alert">
          {error}
        </p>
      )}

      <div className="security-info">
        <ShieldCheck size={22} />
        <div>
          <strong>Your source code security matters</strong>
          <p>
            Uploaded projects are analyzed for potential security
            vulnerabilities and coding issues. Files are not executed
            during scanning.
          </p>
        </div>
      </div>
    </section>
  );
}

export default Dashboard;