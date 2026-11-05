
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { ShieldCheck, LayoutDashboard, Clock, FileText } from "lucide-react";
import "./App.css";

import BrandHeader from "./components/BrandHeader";
import Dashboard from "./pages/Dashboard";
import ScanHistory from "./pages/ScanHistory";
import Reports from "./pages/Reports";
import ScanDetails from "./pages/ScanDetails";

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar">
          <BrandHeader />

          <div className="sidebar-label">WORKSPACE</div>

          <nav>
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <LayoutDashboard size={19} />
              Dashboard
            </NavLink>

            <NavLink
              to="/history"
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <Clock size={19} />
              Scan History
            </NavLink>

            <NavLink
              to="/reports"
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <FileText size={19} />
              Reports
            </NavLink>
          </nav>

          <div className="sidebar-bottom">
            <div className="security-note">
              <ShieldCheck size={20} />
              <strong>Secure by design</strong>
              <p>Automated source code security analysis.</p>
            </div>
            <div className="version">SecureScan AI · v1.0</div>
          </div>
        </aside>

        <main className="main">
          <header className="topbar">
            <strong>SecureScan AI / Security Workspace</strong>
            <span className="engine-status">
              <span className="status-dot"></span>
              Scanner integration pending
            </span>
          </header>

          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/history" element={<ScanHistory />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/scans/:scanId" element={<ScanDetails />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
