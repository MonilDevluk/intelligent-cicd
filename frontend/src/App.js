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
  const [patches, setPatches] = useState({});
  const [stats, setStats] = useState(null);
  const [activeFinding, setActiveFinding] = useState(null);

  useEffect(() => {
    axios.get(`${API}/scans`).then(r => setScans(r.data));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, []);

  const loadScan = (id) => {
    axios.get(`${API}/scans/${id}`).then(r => {
      setSelected(r.data);
      setPatches({});
      setActiveFinding(null);
    });
  };

  const loadPatches = (findingId) => {
    setActiveFinding(findingId);
    axios.get(`${API}/findings/${findingId}/patches`).then(r => {
      setPatches(prev => ({ ...prev, [findingId]: r.data }));
    });
  };

  const PatchBlock = ({ label, patch, borderColor }) => (
    <div style={{ flex: 1 }}>
      <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontWeight: "bold", color: borderColor, textTransform: "uppercase" }}>{label} Prompt</span>
        {patch && (
          <span style={{ background: statusColor(patch.sandbox_status), color: "#fff", padding: "2px 8px", borderRadius: "4px", fontSize: "10px" }}>
            {patch.sandbox_status}
          </span>
        )}
      </div>
      <pre style={{ background: "#0d1117", border: `1px solid ${borderColor}`, borderRadius: "4px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "280px", margin: 0 }}>
        {patch ? patch.patched_code : "No patch available"}
      </pre>
    </div>
  );

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
              <h3 style={{ color: "#8b949e", fontSize: "12px", textTransform: "uppercase" }}>
                Findings — {selected.scan?.repo_url?.replace("https://github.com/", "")}
              </h3>
              {selected.findings.length === 0 && <p style={{ color: "#8b949e" }}>No findings for this scan.</p>}
              {selected.findings.map(f => (
                <div key={f.id} style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: "6px", padding: "16px", marginBottom: "12px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                    <span style={{ color: severityColor(f.severity), fontWeight: "bold", fontSize: "12px" }}>{f.severity}</span>
                    <span style={{ color: "#8b949e", fontSize: "11px" }}>{f.file_path.split("/").pop()}:{f.line_number}</span>
                  </div>
                  <div style={{ fontSize: "13px", marginBottom: "4px" }}>{f.message}</div>
                  <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "12px" }}>{f.rule_id}</div>

                  <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "4px", padding: "12px", marginBottom: "12px" }}>
                    <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>ORIGINAL (Vulnerable)</div>
                    <pre style={{ fontSize: "11px", margin: 0, overflow: "auto", maxHeight: "200px", color: "#e74c3c" }}>
                      {f.code_snippet}
                    </pre>
                  </div>

                  <button onClick={() => loadPatches(f.id)}
                    style={{ background: "#21262d", border: "1px solid #30363d", color: "#58a6ff", padding: "6px 12px", borderRadius: "4px", cursor: "pointer", fontSize: "12px", marginBottom: "12px" }}>
                    {activeFinding === f.id ? "Hide Patches" : "View Patches"}
                  </button>

                  {activeFinding === f.id && patches[f.id] && (
                    <div style={{ display: "flex", gap: "12px" }}>
                      <PatchBlock label="Minimal" patch={patches[f.id].minimal} borderColor="#f39c12" />
                      <PatchBlock label="Enriched" patch={patches[f.id].enriched} borderColor="#2ecc71" />
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
