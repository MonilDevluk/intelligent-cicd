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
  if (s === "UNVERIFIED") return "#f39c12";
  return "#95a5a6";
};

export default function App() {
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [patches, setPatches] = useState({});
  const [stats, setStats] = useState(null);
  const [activeFinding, setActiveFinding] = useState(null);
  const [activeTab, setActiveTab] = useState({});

  useEffect(() => {
    axios.get(`${API}/scans`).then(r => setScans(r.data));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, []);

  const loadScan = (id) => {
    axios.get(`${API}/scans/${id}`).then(r => {
      setSelected(r.data);
      setPatches({});
      setActiveFinding(null);
      setActiveTab({});
    });
  };

  const loadPatches = (findingId) => {
    if (activeFinding === findingId) {
      setActiveFinding(null);
      return;
    }
    setActiveFinding(findingId);
    setActiveTab(prev => ({ ...prev, [findingId]: "minimal" }));
    axios.get(`${API}/findings/${findingId}/patches`).then(r => {
      setPatches(prev => ({ ...prev, [findingId]: r.data }));
    });
  };

  const PatchPanel = ({ findingId, condition }) => {
    const patch = patches[findingId]?.[condition];
    if (!patch) return <div style={{ color: "#8b949e", padding: "12px" }}>No patch available for this condition.</div>;

    const borderColor = condition === "minimal" ? "#f39c12" : "#2ecc71";

    return (
      <div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "12px", flexWrap: "wrap" }}>
          <span style={{ background: statusColor(patch.sandbox_status), color: "#fff", padding: "3px 10px", borderRadius: "4px", fontSize: "11px", fontWeight: "bold" }}>
            {patch.sandbox_status}
          </span>
          {patch.pr_url && (
            <a href={patch.pr_url} target="_blank" rel="noreferrer"
              style={{ background: "#238636", color: "#fff", padding: "3px 12px", borderRadius: "4px", fontSize: "11px", textDecoration: "none", fontWeight: "bold" }}>
              ⬆ View PR on GitHub
            </a>
          )}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
          <div>
            <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>PATCHED CODE</div>
            <pre style={{ background: "#0d1117", border: `1px solid ${borderColor}`, borderRadius: "4px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "250px", margin: 0 }}>
              {patch.patched_code}
            </pre>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>AUTO-GENERATED TEST</div>
            <pre style={{ background: "#0d1117", border: "1px solid #58a6ff", borderRadius: "4px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "250px", margin: 0 }}>
              {patch.generated_test || "No test generated"}
            </pre>
          </div>
        </div>

        {patch.test_output && (
          <div>
            <div style={{ fontSize: "11px", color: "#8b949e", marginBottom: "4px" }}>TEST OUTPUT</div>
            <pre style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: "4px", padding: "8px", fontSize: "10px", overflow: "auto", maxHeight: "100px", margin: 0, color: "#8b949e" }}>
              {patch.test_output}
            </pre>
          </div>
        )}
      </div>
    );
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

                  <div style={{ background: "#0d1117", border: "1px solid #e74c3c", borderRadius: "4px", padding: "12px", marginBottom: "12px" }}>
                    <div style={{ fontSize: "11px", color: "#e74c3c", marginBottom: "4px", fontWeight: "bold" }}>ORIGINAL — Vulnerable Code</div>
                    <pre style={{ fontSize: "11px", margin: 0, overflow: "auto", maxHeight: "150px", color: "#c9d1d9" }}>
                      {f.code_snippet}
                    </pre>
                  </div>

                  <button onClick={() => loadPatches(f.id)}
                    style={{ background: "#21262d", border: "1px solid #30363d", color: "#58a6ff", padding: "6px 12px", borderRadius: "4px", cursor: "pointer", fontSize: "12px", marginBottom: "12px" }}>
                    {activeFinding === f.id ? "▲ Hide Patches" : "▼ View Patches"}
                  </button>

                  {activeFinding === f.id && patches[f.id] && (
                    <div>
                      <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
                        {["minimal", "enriched"].map(c => (
                          <button key={c} onClick={() => setActiveTab(prev => ({ ...prev, [f.id]: c }))}
                            style={{
                              padding: "6px 16px", borderRadius: "4px", cursor: "pointer", fontSize: "12px", fontWeight: "bold",
                              background: activeTab[f.id] === c ? (c === "minimal" ? "#f39c12" : "#2ecc71") : "#21262d",
                              color: activeTab[f.id] === c ? "#000" : "#8b949e",
                              border: `1px solid ${c === "minimal" ? "#f39c12" : "#2ecc71"}`
                            }}>
                            {c === "minimal" ? "Minimal Prompt" : "Enriched Prompt"}
                          </button>
                        ))}
                      </div>
                      <PatchPanel findingId={f.id} condition={activeTab[f.id] || "minimal"} />
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
