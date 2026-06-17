	import { useState, useEffect } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

const LIGHT = {
  bg: "#f9fafb", surface: "#fff", border: "#e5e7eb", text: "#111827",
  textMuted: "#9ca3af", textSecondary: "#374151", accent: "#6366f1",
  sidebarBg: "#fff", headerBg: "#fff", tabActiveBg: "#f9fafb",
  tabActiveTop: "#6366f1", findingBg: "#fff", findingBorder: "#e5e7eb",
  vulnBg: "#fff5f5", vulnBorder: "#fecaca", vulnText: "#ef4444",
  codeBg: "#f9fafb", prBg: "#f0fdf4", prColor: "#15803d", prBorder: "#86efac",
  statBorder: "#e5e7eb", toggleBg: "#e5e7eb", toggleKnob: "#fff",
};

const DARK = {
  bg: "#0d1117", surface: "#161b22", border: "#30363d", text: "#c9d1d9",
  textMuted: "#8b949e", textSecondary: "#8b949e", accent: "#58a6ff",
  sidebarBg: "#161b22", headerBg: "#161b22", tabActiveBg: "#0d1117",
  tabActiveTop: "#58a6ff", findingBg: "#161b22", findingBorder: "#30363d",
  vulnBg: "#1a0a0a", vulnBorder: "#5a1a1a", vulnText: "#f87171",
  codeBg: "#0d1117", prBg: "#0a1f12", prColor: "#4ade80", prBorder: "#166534",
  statBorder: "#30363d", toggleBg: "#58a6ff", toggleKnob: "#fff",
};

const severityColor = (s, dark) => {
  if (s === "ERROR") return dark ? "#f87171" : "#ef4444";
  if (s === "WARNING") return dark ? "#fbbf24" : "#f59e0b";
  return dark ? "#818cf8" : "#6366f1";
};

const statusBadge = (s, dark) => {
  if (s === "SAFE") return { bg: dark ? "#052e16" : "#d1fae5", color: dark ? "#4ade80" : "#065f46" };
  if (s === "NEEDS_REVIEW") return { bg: dark ? "#2d0a0a" : "#fee2e2", color: dark ? "#f87171" : "#991b1b" };
  if (s === "UNVERIFIED") return { bg: dark ? "#2d1a00" : "#fef3c7", color: dark ? "#fbbf24" : "#92400e" };
  return { bg: dark ? "#21262d" : "#f3f4f6", color: dark ? "#8b949e" : "#6b7280" };
};

export default function App() {
  const [scans, setScans] = useState([]);
  const [tabs, setTabs] = useState([]);
  const [activeTabId, setActiveTabId] = useState(null);
  const [patches, setPatches] = useState({});
  const [stats, setStats] = useState(null);
  const [activeFinding, setActiveFinding] = useState({});
  const [activeCondition, setActiveCondition] = useState({});
  const [dark, setDark] = useState(false);

  const T = dark ? DARK : LIGHT;

  useEffect(() => {
    axios.get(`${API}/scans`).then(r => setScans(r.data));
    axios.get(`${API}/stats`).then(r => setStats(r.data));
  }, []);

  const loadScan = (scan) => {
    const exists = tabs.find(t => t.id === scan.id);
    if (exists) { setActiveTabId(scan.id); return; }
    axios.get(`${API}/scans/${scan.id}`).then(r => {
      setTabs(prev => [...prev, {
        id: scan.id,
        label: scan.repo_url.replace("https://github.com/", "").split("/")[1] + " · " + scan.branch,
        data: r.data
      }]);
      setActiveTabId(scan.id);
    });
  };

  const closeTab = (e, id) => {
    e.stopPropagation();
    const remaining = tabs.filter(t => t.id !== id);
    setTabs(remaining);
    if (activeTabId === id) setActiveTabId(remaining.length > 0 ? remaining[remaining.length - 1].id : null);
  };

  const loadPatches = (findingId) => {
    if (activeFinding[activeTabId] === findingId) {
      setActiveFinding(prev => ({ ...prev, [activeTabId]: null }));
      return;
    }
    setActiveFinding(prev => ({ ...prev, [activeTabId]: findingId }));
    setActiveCondition(prev => ({ ...prev, [findingId]: "minimal" }));
    if (!patches[findingId]) {
      axios.get(`${API}/findings/${findingId}/patches`).then(r => {
        setPatches(prev => ({ ...prev, [findingId]: r.data }));
      });
    }
  };

  const PatchPanel = ({ findingId, condition }) => {
    const patch = patches[findingId]?.[condition];
    if (!patch) return <div style={{ color: T.textMuted, padding: "12px", fontSize: "13px" }}>No patch available for this condition.</div>;
    const badge = statusBadge(patch.sandbox_status, dark);
    const borderColor = condition === "minimal" ? (dark ? "#d97706" : "#f59e0b") : (dark ? "#059669" : "#10b981");
    return (
      <div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "14px", flexWrap: "wrap" }}>
          <span style={{ background: badge.bg, color: badge.color, padding: "3px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: "500" }}>
            {patch.sandbox_status}
          </span>
          {patch.pr_url && (
            <a href={patch.pr_url} target="_blank" rel="noreferrer"
              style={{ background: T.prBg, color: T.prColor, border: `0.5px solid ${T.prBorder}`, padding: "3px 12px", borderRadius: "999px", fontSize: "11px", textDecoration: "none", fontWeight: "500" }}>
              ↗ View PR on GitHub
            </a>
          )}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
          <div>
            <div style={{ fontSize: "11px", color: T.textMuted, marginBottom: "6px", fontWeight: "500", textTransform: "uppercase", letterSpacing: "0.5px" }}>Patched Code</div>
            <pre style={{ background: T.codeBg, border: `1.5px solid ${borderColor}`, borderRadius: "8px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "250px", margin: 0, color: T.text, fontFamily: "monospace" }}>
              {patch.patched_code}
            </pre>
          </div>
          <div>
            <div style={{ fontSize: "11px", color: T.textMuted, marginBottom: "6px", fontWeight: "500", textTransform: "uppercase", letterSpacing: "0.5px" }}>Auto-Generated Test</div>
            <pre style={{ background: T.codeBg, border: `1.5px solid ${T.accent}`, borderRadius: "8px", padding: "12px", fontSize: "11px", overflow: "auto", maxHeight: "250px", margin: 0, color: T.text, fontFamily: "monospace" }}>
              {patch.generated_test || "No test generated"}
            </pre>
          </div>
        </div>
        {patch.test_output && (
          <div>
            <div style={{ fontSize: "11px", color: T.textMuted, marginBottom: "6px", fontWeight: "500", textTransform: "uppercase", letterSpacing: "0.5px" }}>Test Output</div>
            <pre style={{ background: T.codeBg, border: `0.5px solid ${T.border}`, borderRadius: "8px", padding: "8px 12px", fontSize: "10px", overflow: "auto", maxHeight: "100px", margin: 0, color: T.textMuted, fontFamily: "monospace" }}>
              {patch.test_output}
            </pre>
          </div>
        )}
      </div>
    );
  };

  const activeTabData = tabs.find(t => t.id === activeTabId)?.data;

  return (
    <div style={{ fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", background: T.bg, height: "100vh", color: T.text, display: "flex", flexDirection: "column", overflow: "hidden", transition: "background 0.2s" }}>

      {/* HEADER */}
      <div style={{ background: T.headerBg, borderBottom: `0.5px solid ${T.border}`, padding: "16px 28px", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "18px", fontWeight: "600", color: T.text }}>Intelligent CI/CD</h1>
            <p style={{ margin: 0, fontSize: "12px", color: T.textMuted }}>Autonomous patch generation dashboard</p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "12px", color: T.textMuted }}>{dark ? "Dark" : "Light"}</span>
            <div onClick={() => setDark(d => !d)}
              style={{ width: "40px", height: "22px", borderRadius: "999px", background: T.toggleBg, cursor: "pointer", position: "relative", transition: "background 0.2s" }}>
              <div style={{ position: "absolute", top: "3px", left: dark ? "20px" : "3px", width: "16px", height: "16px", borderRadius: "50%", background: T.toggleKnob, transition: "left 0.2s" }} />
            </div>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#10b981", boxShadow: "0 0 0 3px #d1fae522" }} />
          </div>
        </div>
        {stats && (
          <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
            {[
              ["Total Scans", stats.total_scans, T.accent],
              ["Findings", stats.total_findings, dark ? "#fbbf24" : "#f59e0b"],
              ["Patches", stats.total_patches, T.text],
              ["Safe", stats.safe_patches, "#10b981"],
              ["Needs Review", stats.needs_review_patches, dark ? "#f87171" : "#ef4444"]
            ].map(([label, val, color]) => (
              <div key={label} style={{ background: T.surface, border: `0.5px solid ${T.statBorder}`, borderRadius: "10px", padding: "10px 18px", minWidth: "90px" }}>
                <div style={{ fontSize: "20px", fontWeight: "600", color }}>{val}</div>
                <div style={{ fontSize: "11px", color: T.textMuted, marginTop: "2px" }}>{label}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* BODY */}
      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", flex: 1, overflow: "hidden" }}>

        {/* SIDEBAR */}
        <div style={{ background: T.sidebarBg, borderRight: `0.5px solid ${T.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "16px 16px 8px", flexShrink: 0 }}>
            <span style={{ fontSize: "11px", fontWeight: "600", color: T.textMuted, textTransform: "uppercase", letterSpacing: "0.5px" }}>Recent Scans</span>
          </div>
          <div style={{ overflowY: "auto", flex: 1, padding: "0 8px 16px" }}>
            {scans.map(s => {
              const isActive = activeTabId === s.id;
              const isOpen = tabs.find(t => t.id === s.id);
              return (
                <div key={s.id} onClick={() => loadScan(s)}
                  style={{ borderRadius: "8px", padding: "10px 12px", marginBottom: "4px", cursor: "pointer",
                    background: isActive ? (dark ? "#1f2d4a" : "#eef2ff") : isOpen ? (dark ? "#1a2030" : "#f9fafb") : "transparent",
                    border: isActive ? `0.5px solid ${T.accent}` : "0.5px solid transparent" }}>
                  <div style={{ fontSize: "12px", fontWeight: "500", color: isActive ? T.accent : T.textSecondary, marginBottom: "2px" }}>
                    {s.repo_url.replace("https://github.com/", "").split("/")[1]}
                  </div>
                  <div style={{ fontSize: "11px", color: T.textMuted }}>
                    {s.branch} · {new Date(s.created_at).toLocaleString()}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* RIGHT */}
        <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {tabs.length > 0 && (
            <div style={{ background: T.headerBg, borderBottom: `0.5px solid ${T.border}`, display: "flex", gap: "2px", padding: "8px 16px 0", flexShrink: 0, overflowX: "auto" }}>
              {tabs.map(t => (
                <div key={t.id} onClick={() => setActiveTabId(t.id)}
                  style={{ display: "flex", alignItems: "center", gap: "8px", padding: "6px 14px", borderRadius: "8px 8px 0 0", cursor: "pointer", fontSize: "12px", fontWeight: "500", whiteSpace: "nowrap",
                    background: activeTabId === t.id ? T.tabActiveBg : "transparent",
                    color: activeTabId === t.id ? T.text : T.textMuted,
                    borderTop: activeTabId === t.id ? `2px solid ${T.tabActiveTop}` : "2px solid transparent",
                    borderLeft: activeTabId === t.id ? `0.5px solid ${T.border}` : "0.5px solid transparent",
                    borderRight: activeTabId === t.id ? `0.5px solid ${T.border}` : "0.5px solid transparent" }}>
                  {t.label}
                  <span onClick={(e) => closeTab(e, t.id)} style={{ color: T.textMuted, fontSize: "14px", lineHeight: 1, padding: "0 2px", cursor: "pointer" }}>×</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ overflowY: "auto", flex: 1, padding: "20px 24px" }}>
            {!activeTabData ? (
              <div style={{ color: T.textMuted, textAlign: "center", marginTop: "60px", fontSize: "14px" }}>
                <div style={{ fontSize: "32px", marginBottom: "8px" }}>←</div>
                Select a scan to view findings
              </div>
            ) : activeTabData.findings.length === 0 ? (
              <p style={{ color: T.textMuted }}>No findings for this scan.</p>
            ) : (
              activeTabData.findings.map(f => (
                <div key={f.id} style={{ background: T.findingBg, border: `0.5px solid ${T.findingBorder}`, borderRadius: "12px", padding: "18px", marginBottom: "12px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                    <span style={{ background: severityColor(f.severity, dark) + "22", color: severityColor(f.severity, dark), padding: "3px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: "600" }}>{f.severity}</span>
                    <span style={{ color: T.textMuted, fontSize: "11px", fontFamily: "monospace" }}>{f.file_path.split("/").pop()}:{f.line_number}</span>
                  </div>
                  <div style={{ fontSize: "14px", fontWeight: "500", color: T.text, marginBottom: "4px" }}>{f.message}</div>
                  <div style={{ fontSize: "11px", color: T.textMuted, marginBottom: "14px", fontFamily: "monospace" }}>{f.rule_id}</div>
                  <div style={{ background: T.vulnBg, border: `0.5px solid ${T.vulnBorder}`, borderRadius: "8px", padding: "12px", marginBottom: "14px" }}>
                    <div style={{ fontSize: "11px", color: T.vulnText, marginBottom: "6px", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>Vulnerable Code</div>
                    <pre style={{ fontSize: "11px", margin: 0, overflow: "auto", maxHeight: "150px", color: T.textSecondary, fontFamily: "monospace" }}>
                      {f.code_snippet}
                    </pre>
                  </div>
                  <button onClick={() => loadPatches(f.id)}
                    style={{ background: "transparent", border: `0.5px solid ${T.border}`, color: T.accent, padding: "6px 14px", borderRadius: "8px", cursor: "pointer", fontSize: "12px", fontWeight: "500", marginBottom: "14px" }}>
                    {activeFinding[activeTabId] === f.id ? "▲ Hide Patches" : "▼ View Patches"}
                  </button>
                  {activeFinding[activeTabId] === f.id && patches[f.id] && (
                    <div>
                      <div style={{ display: "flex", gap: "6px", marginBottom: "14px" }}>
                        {["minimal", "enriched"].map(c => (
                          <button key={c} onClick={() => setActiveCondition(prev => ({ ...prev, [f.id]: c }))}
                            style={{
                              padding: "6px 16px", borderRadius: "999px", cursor: "pointer", fontSize: "12px", fontWeight: "500",
                              background: activeCondition[f.id] === c ? (c === "minimal" ? (dark ? "#2d1a00" : "#fef3c7") : (dark ? "#052e16" : "#d1fae5")) : T.surface,
                              color: activeCondition[f.id] === c ? (c === "minimal" ? (dark ? "#fbbf24" : "#92400e") : (dark ? "#4ade80" : "#065f46")) : T.textMuted,
                              border: `0.5px solid ${activeCondition[f.id] === c ? (c === "minimal" ? (dark ? "#d97706" : "#f59e0b") : (dark ? "#059669" : "#10b981")) : T.border}`
                            }}>
                            {c === "minimal" ? "Minimal Prompt" : "Enriched Prompt"}
                          </button>
                        ))}
                      </div>
                      <PatchPanel findingId={f.id} condition={activeCondition[f.id] || "minimal"} />
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
