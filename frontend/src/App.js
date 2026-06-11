import { useState, useEffect } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

const severityColor = (s) => {
  if (s === "ERROR") return "#e74c3c";
  if (s === "WARNING") return "#f39c12";
  return "#3498db";
};

const statusColor = (s) => {
  if (s === "SAFE") return "#2ecc71";
  if (s === "NEEDS_REVIEW") return "#e74c3c";
  return "#95a5a6";
};

export default function App() {
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [patch, setPatch] = useState(null);
  const [stats, setStats] = useState(null);
  const [activeFinding, setActiveFinding] = useState(null);

  useEffect(() => {
    axios.get(`${API}/scans`).then(r => setScans(r.data));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, []);

  const loadScan = (id) => {
    axios.get(`${API}/scans/${id}`).then(r => {
      setSelected(r.data);
      setPatch(null);
      setActiveFinding(null);
    });
  };

  const loadPatch = (findingId) => {
    setActiveFinding(findingId);
    axios.get(`${API}/findings/${findingId}/patch`).then(r => setPatch(r.data));
  };

  return (
    <div style={{ fontFamily: "monospace", background: "#0d1117", minHeight: "100vh", color: "#c9d1d9", padding: "24px" }}>
      <h1 style={{ color: "#58a6ff", borderBottom: "1px solid #30363d", paddingBottom: "12px" }}>
        Intelligent CI/CD Dashboard
      </h1>

      {stats && (
        <div style={{ display: "flex", gap: "16px", marginBottom: "24px", flexWrap: "wrap" }}>
          {[
            ["Total Scans", stats.total_scans],
            ["Total Findings", stats.total_findings],
            ["Total Patches", stats.total_patches],
            ["Safe", stats.safe_patches],
            ["Needs Review", stats.needs_review_patches]
          ].map(([label, val]) => (
            <div key={label} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "8px", padding: "16px 24px" }}>
              <div style={{ fontSize: "24px", fontWeight: "bold", color: "#58a6ff" }}>{val}</div>
              <div style={{ fontSize: "12px", color: "#8b949e" }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: "24px" }}>
        <div>
          <h3 style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>Recent Scans</h3>
          {scans.map(s => (
            <div key={s.id} onClick={() => loadScan(s.id)}
              style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "12px", marginBottom: "8px", cursor: "pointer" }}>
              <div style={{ fontSize: "12px", color: "#58a6ff", wordBreak: "break-all" }}>
                {s.repo_url.replace("https://github.com/", "")}
              </div>
              <div style={{ fontSize: "11px", color: "#8b949e", marginTop: "4px" }}>
                {s.branch} · {new Date(s.created_at).toLocaleString()}
              </div>
            </div>
          ))}
        </div>

        <div>
          {selected && (
            <>
              <h3 style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>Findings</h3>
              {selected.findings.length === 0 && <p style={{ color: "#8b949e" }}>No findings for this scan.</p>}
              {selected.findings.map(f => (
                <div key={f.id} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "16px", marginBottom: "12px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                    <span style={{ color: severityColor(f.severity), fontWeight: "bold", fontSize: "12px" }}>{f.severity}</span>
                    <span style={{ color: "#8b949e", fontSize: "11px" }}>{f.file_path.split("/").pop()}:{f.line_number}</span>
                  </div>
                  <div style={{ fontSize: "13px", marginBottom: "8px" }}>{f.message}</div>
                  <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "8px" }}>{f.rule_id}</div>
                  <button onClick={() => loadPatch(f.id)}
                    style={{ background: "#21262d", border: "1px solid #30363d", color: "#58a6ff", padding: "6px 12px", borderRadius: "4px", cursor: "pointer", fontSize: "12px" }}>
                    View Patch
                  </button>

                  {activeFinding === f.id && patch && (
                    <div style={{ marginTop: "12px" }}>
                      <div style={{ display: "flex", gap: "8px", marginBottom: "8px", alignItems: "center" }}>
                        <span style={{ background: statusColor(patch.sandbox_status), color: "#fff", padding: "2px 8px", borderRadius: "4px", fontSize: "11px" }}>
                          {patch.sandbox_status}
                        </span>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                        <div>
                          <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>ORIGINAL</div>
                          <pre style={{ background: "#0d1117", border: "1px solid #e74c3c", borderRadius: "4px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "300px" }}>
                            {patch.original_code}
                          </pre>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>PATCHED</div>
                          <pre style={{ background: "#0d1117", border: "1px solid #2ecc71", borderRadius: "4px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "300px" }}>
                            {patch.patched_code}
                          </pre>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
