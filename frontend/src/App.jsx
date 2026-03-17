import { useState, useEffect, useRef } from "react";
import {
  LineChart, Line, BarChart, Bar, RadarChart, Radar, PolarGrid, PolarAngleAxis,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from "recharts";

const API = 'http://192.168.56.101:8000';
// ── CONSTANTS ─────────────────────────────────────────────────────────────────
const RADAR_DATA = [
  { metric: "Detection",    Dionaea:95, Cowrie:87, Honeyd:78, Amun:82, Glastopf:76, Kippo:68, Thug:74 },
  { metric: "Data Quality", Dionaea:92, Cowrie:84, Honeyd:52, Amun:80, Glastopf:78, Kippo:65, Thug:75 },
  { metric: "Scalability",  Dionaea:80, Cowrie:65, Honeyd:98, Amun:80, Glastopf:60, Kippo:62, Thug:58 },
  { metric: "Reliability",  Dionaea:90, Cowrie:95, Honeyd:85, Amun:83, Glastopf:78, Kippo:70, Thug:65 },
  { metric: "Ease",         Dionaea:78, Cowrie:70, Honeyd:92, Amun:80, Glastopf:84, Kippo:85, Thug:48 },
  { metric: "Extensibility",Dionaea:95, Cowrie:72, Honeyd:90, Amun:90, Glastopf:88, Kippo:60, Thug:75 },
];
const COMPARISON_TABLE = [
  { tool:"Dionaea",  detection:"Multi", accuracy:"Excellent",  data:"Excellent", reliability:"★★★★★", scalability:"★★★★",  setup:"Moderate", useCase:"Malware capture" },
  { tool:"Cowrie",   detection:"SSH",   accuracy:"Good",       data:"Good",      reliability:"★★★★★", scalability:"★★★",   setup:"Moderate", useCase:"SSH forensics" },
  { tool:"Honeyd",   detection:"Multi", accuracy:"Acceptable", data:"Weak",      reliability:"★★★★",  scalability:"★★★★★", setup:"Easy",     useCase:"Broad scanning" },
  { tool:"Glastopf", detection:"HTTP",  accuracy:"Excellent",  data:"Good",      reliability:"★★★★",  scalability:"★★★",   setup:"Easy",     useCase:"Web app attacks" },
  { tool:"Kippo",    detection:"SSH",   accuracy:"Good",       data:"Good",      reliability:"★★★",   scalability:"★★★",   setup:"Easy",     useCase:"Basic SSH" },
  { tool:"Amun",     detection:"Multi", accuracy:"Good",       data:"Good",      reliability:"★★★★",  scalability:"★★★★",  setup:"Moderate", useCase:"Multi-service" },
  { tool:"Thug",     detection:"HTTP",  accuracy:"Good",       data:"Good",      reliability:"★★★",   scalability:"★★★",   setup:"Complex",  useCase:"Browser emulation" },
];
const HONEYPOT_NAMES = ["Dionaea","Cowrie","Honeyd","Glastopf","Kippo","Amun","Thug"];
const TOOL_COLORS   = ["#00D4FF","#7C3AED","#10B981","#F59E0B","#EF4444","#EC4899","#8B5CF6"];
const PIE_COLORS    = ["#7C3AED","#00D4FF","#10B981","#F59E0B","#EF4444","#EC4899","#8B5CF6"];
const SEV_COLORS    = { CRITICAL:"#ef4444", HIGH:"#f97316", MEDIUM:"#eab308", LOW:"#22c55e" };
const SKILL_COLORS  = { EXPERT:"#EF4444", INTERMEDIATE:"#F59E0B", "SCRIPT KIDDIE":"#7C3AED", BOT:"#00D4FF", NOVICE:"#10B981" };

// ── SMALL REUSABLE COMPONENTS ─────────────────────────────────────────────────
const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload?.length) return (
    <div style={{ background:"#0D1B2A", border:"1px solid #1E3A5F", borderRadius:8, padding:"10px 14px" }}>
      <div style={{ color:"#94A3B8", fontSize:11, marginBottom:4 }}>{label}</div>
      {payload.map((p,i) => <div key={i} style={{ color:p.color, fontSize:12 }}>{p.name}: <strong>{p.value}</strong></div>)}
    </div>
  );
  return null;
};

function MetricCard({ label, value, unit, color, sub }) {
  return (
    <div style={{ background:"linear-gradient(135deg,#0D1B2A,#111827)", border:`1px solid ${color}40`,
      borderRadius:12, padding:"18px 20px", position:"relative", overflow:"hidden" }}>
      <div style={{ position:"absolute", top:0, left:0, right:0, height:3, background:color }} />
      <div style={{ fontSize:10, color:"#64748B", letterSpacing:2, textTransform:"uppercase", marginBottom:8 }}>{label}</div>
      <div style={{ display:"flex", alignItems:"baseline", gap:4 }}>
        <span style={{ fontSize:38, fontWeight:900, color, fontFamily:"'Courier New',monospace", lineHeight:1 }}>{value}</span>
        {unit && <span style={{ fontSize:13, color:"#94A3B8" }}>{unit}</span>}
      </div>
      {sub && <div style={{ fontSize:10, color:"#22c55e", marginTop:6 }}>{sub}</div>}
    </div>
  );
}

function AttackRow({ attack, fresh }) {
  return (
    <div style={{ display:"grid", gridTemplateColumns:"70px 1fr 110px 55px 120px 95px",
      gap:8, padding:"8px 14px", borderBottom:"1px solid #1E3A5F22",
      background:fresh?"#00D4FF08":"transparent", transition:"background 0.5s", alignItems:"center" }}>
      <span style={{ fontSize:10, color:"#64748B", fontFamily:"monospace" }}>{attack.time}</span>
      <span style={{ fontSize:11, color:"#CBD5E1" }}>{attack.type}</span>
      <span style={{ fontSize:10, color:"#94A3B8", fontFamily:"monospace" }}>{attack.source}</span>
      <span style={{ fontSize:10, color:"#7C3AED", fontWeight:700 }}>{attack.country}</span>
      <span style={{ fontSize:10, color:"#00D4FF" }}>{attack.honeypot}</span>
      <span style={{ fontSize:9, fontWeight:700, color:SEV_COLORS[attack.severity],
        background:SEV_COLORS[attack.severity]+"22", padding:"2px 8px", borderRadius:4, textAlign:"center" }}>{attack.severity}</span>
    </div>
  );
}

function SectionBox({ title, children, color }) {
  return (
    <div style={{ background:"#0D1B2A", borderRadius:12, border:`1px solid ${color||"#1E3A5F"}`, overflow:"hidden" }}>
      <div style={{ padding:"14px 20px", borderBottom:"1px solid #1E3A5F",
        borderTop:`3px solid ${color||"#00D4FF"}` }}>
        <div style={{ fontSize:11, color:color||"#64748B", letterSpacing:2 }}>{title}</div>
      </div>
      <div style={{ padding:"16px 20px" }}>{children}</div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
export default function HoneypotDashboard() {
  const [tab, setTab]           = useState("overview");
  const [attacks, setAttacks]   = useState([]);
  const [freshId, setFreshId]   = useState(null);
  const [stats, setStats]       = useState(null);
  const [selectedTool, setSelectedTool] = useState(null);

  // New ML state
  const [dna, setDna]               = useState([]);
  const [anomalies, setAnomalies]   = useState([]);
  const [prediction, setPrediction] = useState(null);
  const [emotions, setEmotions]     = useState([]);
  const [threats, setThreats]       = useState([]);
  const [commands, setCommands]     = useState([]);

  const feedRef = useRef(null);

  // ── FETCH ALL DATA ──────────────────────────────────────────────────────────
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [atkR, stR, dnaR, anoR, predR, emoR, thrR, cmdR] = await Promise.all([
          fetch(API+'/api/attacks'),
          fetch(API+'/api/stats'),
          fetch(API+'/api/dna'),
          fetch(API+'/api/anomalies'),
          fetch(API+'/api/prediction'),
          fetch(API+'/api/emotions'),
          fetch(API+'/api/threats'),
          fetch(API+'/api/commands'),
        ]);
        if (atkR.ok)  { const d=await atkR.json();  if(d.length>0){setFreshId(d[0].id);setAttacks(d);} }
        if (stR.ok)   { setStats(await stR.json()); }
        if (dnaR.ok)  { setDna(await dnaR.json()); }
        if (anoR.ok)  { setAnomalies(await anoR.json()); }
        if (predR.ok) { setPrediction(await predR.json()); }
        if (emoR.ok)  { setEmotions(await emoR.json()); }
        if (thrR.ok)  { setThreats(await thrR.json()); }
        if (cmdR.ok)  { setCommands(await cmdR.json()); }
      } catch(e) { console.log("Backend offline:", e); }
    };
    fetchAll();
    const iv = setInterval(fetchAll, 3000);
    return () => clearInterval(iv);
  }, []);

  const total = stats?.total ?? 0;
  const tabs = ["overview","detection","comparison","live feed","🧬 dna","🤖 ml anomaly","🔮 prediction","😤 emotions","🎯 threats","💻 commands"];

  return (
    <div style={{ minHeight:"100vh", background:"#070D16", color:"#E2E8F0", fontFamily:"'Courier New','Consolas',monospace" }}>
      <div style={{ position:"fixed", inset:0, pointerEvents:"none",
        background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px)", zIndex:0 }} />

      {/* ── HEADER ── */}
      <div style={{ background:"linear-gradient(90deg,#0A0E1A,#0D1B2A)", borderBottom:"1px solid #1E3A5F",
        padding:"0 28px", display:"flex", alignItems:"center", justifyContent:"space-between",
        height:64, position:"sticky", top:0, zIndex:100, boxShadow:"0 4px 32px #00D4FF10" }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <div style={{ width:36, height:36, background:"linear-gradient(135deg,#7C3AED,#00D4FF)",
            borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>🛡</div>
          <div>
            <div style={{ fontSize:16, fontWeight:900, color:"#fff", letterSpacing:2 }}>HONEYPOT 2.0</div>
            <div style={{ fontSize:9, color:"#64748B", letterSpacing:3 }}>DECEPTION TECHNOLOGY + ML INTELLIGENCE</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:24 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:8, height:8, borderRadius:"50%", background:"#22c55e",
              boxShadow:"0 0 8px #22c55e", animation:"pulse 1s infinite" }} />
            <span style={{ fontSize:10, color:"#22c55e", letterSpacing:2 }}>LIVE + ML ACTIVE</span>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontSize:18, fontWeight:900, color:"#00D4FF", fontFamily:"monospace" }}>{total.toLocaleString()}</div>
            <div style={{ fontSize:9, color:"#64748B", letterSpacing:1 }}>TOTAL EVENTS</div>
          </div>
        </div>
      </div>

      {/* ── TABS ── */}
      <div style={{ display:"flex", gap:2, padding:"0 28px", background:"#0A0E1A",
        borderBottom:"1px solid #1E3A5F", overflowX:"auto", flexWrap:"nowrap" }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding:"12px 18px", border:"none", whiteSpace:"nowrap",
            background: tab===t ? "#0D1B2A" : "transparent",
            color: tab===t ? "#00D4FF" : "#64748B",
            fontSize:10, letterSpacing:1.5, cursor:"pointer", textTransform:"uppercase",
            borderBottom: tab===t ? "2px solid #00D4FF" : "2px solid transparent",
            transition:"all 0.2s", fontFamily:"inherit",
          }}>{t}</button>
        ))}
      </div>

      <div style={{ padding:"24px 28px", position:"relative", zIndex:1 }}>

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: OVERVIEW
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="overview" && (
          <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16 }}>
              <MetricCard label="Detection Accuracy"  value={stats?.detection_accuracy??"—"} unit="%" color="#10B981" sub={`${total} events analysed`} />
              <MetricCard label="Avg Alert Time"       value={stats?.avg_alert_time??"—"}      unit="sec" color="#00D4FF" sub="real-time polling" />
              <MetricCard label="Active Honeypots"     value={stats?.active_honeypots??"—"}    color="#7C3AED" sub="Cowrie running" />
              <MetricCard label="Threats Blocked"      value={stats?.threats_blocked??"—"}     unit="%" color="#F59E0B" sub={`${stats?.critical??0} critical caught`} />
            </div>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
              <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:16 }}>ATTACK TIMELINE — REAL DATA</div>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={stats?.timeline??[]}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E3A5F" />
                  <XAxis dataKey="t" tick={{ fill:"#64748B", fontSize:9 }} />
                  <YAxis tick={{ fill:"#64748B", fontSize:9 }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Legend wrapperStyle={{ fontSize:10, color:"#94A3B8" }} />
                  <Line type="monotone" dataKey="attacks"  stroke="#EF4444" strokeWidth={2} dot={false} name="Total Attacks" />
                  <Line type="monotone" dataKey="detected" stroke="#10B981" strokeWidth={2} dot={false} name="Detected" />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"1.6fr 1fr", gap:16 }}>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:16 }}>ATTACK TYPE BREAKDOWN</div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={stats?.bar??[]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E3A5F" />
                    <XAxis dataKey="name" tick={{ fill:"#64748B", fontSize:8 }} />
                    <YAxis tick={{ fill:"#64748B", fontSize:9 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="score" name="% of attacks">
                      {(stats?.bar??[]).map((_,i)=><Cell key={i} fill={TOOL_COLORS[i%TOOL_COLORS.length]}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:16 }}>ATTACK DISTRIBUTION</div>
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie data={stats?.pie??[]} cx="50%" cy="45%" outerRadius={75} dataKey="value" labelLine={false}
                      label={({percent})=>`${(percent*100).toFixed(0)}%`}>
                      {(stats?.pie??[]).map((_,i)=><Cell key={i} fill={PIE_COLORS[i%PIE_COLORS.length]}/>)}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend wrapperStyle={{ fontSize:9, color:"#94A3B8" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: DETECTION
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="detection" && (
          <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16 }}>
              {[
                { label:"Precision",           value:stats?stats.precision+"%":"—",  desc:"True Positives / All Positives",   color:"#10B981" },
                { label:"Recall",              value:stats?stats.recall+"%":"—",     desc:"True Positives / Actual Threats",  color:"#00D4FF" },
                { label:"F1 Score",            value:stats?stats.f1+"%":"—",         desc:"Harmonic Mean of P & R",           color:"#7C3AED" },
                { label:"False Positive Rate", value:stats?stats.fpr+"%":"—",        desc:"Low severity / total events",      color:"#F59E0B" },
                { label:"Zero-Day Capture",    value:stats?stats.zeroday+"%":"—",    desc:"Critical events / total",          color:"#EC4899" },
                { label:"Avg Dwell Time",      value:stats?stats.avg_dwell+"m":"—",  desc:"Avg session duration",             color:"#EF4444" },
              ].map(m=>(
                <div key={m.label} style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 22px",
                  border:`1px solid ${m.color}30`, position:"relative" }}>
                  <div style={{ position:"absolute", top:0, left:0, width:"100%", height:3, background:m.color, borderRadius:"12px 12px 0 0" }} />
                  <div style={{ fontSize:9, color:"#64748B", letterSpacing:2, textTransform:"uppercase" }}>{m.label}</div>
                  <div style={{ fontSize:36, fontWeight:900, color:m.color, margin:"8px 0 4px", fontFamily:"monospace" }}>{m.value}</div>
                  <div style={{ fontSize:10, color:"#64748B" }}>{m.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
              <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:20 }}>ATTACK TYPE DETECTION BREAKDOWN</div>
              {(stats?.per_honeypot??[]).map((row,i)=>(
                <div key={row.tool} style={{ marginBottom:14 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
                    <span style={{ fontSize:11, color:"#CBD5E1", fontWeight:700 }}>{row.tool}</span>
                    <span style={{ fontSize:11, color:TOOL_COLORS[i%TOOL_COLORS.length], fontFamily:"monospace" }}>
                      {row.count} events ({row.score}%)
                    </span>
                  </div>
                  <div style={{ height:8, background:"#1E3A5F", borderRadius:4, overflow:"hidden" }}>
                    <div style={{ height:"100%", width:`${row.score}%`,
                      background:`linear-gradient(90deg,${TOOL_COLORS[i%TOOL_COLORS.length]},${TOOL_COLORS[i%TOOL_COLORS.length]}88)`,
                      borderRadius:4, transition:"width 0.8s ease" }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: COMPARISON
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="comparison" && (
          <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:8 }}>MULTI-DIMENSIONAL RADAR ANALYSIS</div>
                <div style={{ fontSize:9, color:"#64748B", marginBottom:16 }}>
                  {selectedTool ? `Viewing: ${selectedTool} — click to deselect` : "Click a tool name to isolate"}
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  <RadarChart data={RADAR_DATA}>
                    <PolarGrid stroke="#1E3A5F" />
                    <PolarAngleAxis dataKey="metric" tick={{ fill:"#94A3B8", fontSize:9 }} />
                    {HONEYPOT_NAMES.map((name,i) => {
                      if (selectedTool && name!==selectedTool) return null;
                      return <Radar key={name} name={name} dataKey={name}
                        stroke={TOOL_COLORS[i]} fill={TOOL_COLORS[i]} fillOpacity={0.12} strokeWidth={1.5}/>;
                    })}
                    <Legend wrapperStyle={{ fontSize:10 }} onClick={e=>setSelectedTool(prev=>prev===e.value?null:e.value)} />
                    <Tooltip content={<CustomTooltip />} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2, marginBottom:16 }}>DETECTION vs DATA QUALITY</div>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={COMPARISON_TABLE.map((r,i)=>({
                    name:r.tool, Detection:[95,87,78,76,68,82,74][i], "Data Quality":[92,84,52,78,65,80,75][i]
                  }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E3A5F" />
                    <XAxis dataKey="name" tick={{ fill:"#64748B", fontSize:9 }} />
                    <YAxis domain={[40,100]} tick={{ fill:"#64748B", fontSize:9 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend wrapperStyle={{ fontSize:10, color:"#94A3B8" }} />
                    <Bar dataKey="Detection" fill="#00D4FF" />
                    <Bar dataKey="Data Quality" fill="#7C3AED" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div style={{ background:"#0D1B2A", borderRadius:12, border:"1px solid #1E3A5F", overflow:"hidden" }}>
              <div style={{ padding:"18px 24px", borderBottom:"1px solid #1E3A5F" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2 }}>FULL EVALUATION MATRIX</div>
              </div>
              <div style={{ overflowX:"auto" }}>
                <table style={{ width:"100%", borderCollapse:"collapse" }}>
                  <thead>
                    <tr style={{ background:"#111827" }}>
                      {["Tool","Detection","Accuracy","Data Quality","Reliability","Scalability","Setup","Best Use Case"].map(h=>(
                        <th key={h} style={{ padding:"10px 16px", fontSize:9, color:"#64748B",
                          letterSpacing:2, textAlign:"left", borderBottom:"1px solid #1E3A5F",
                          textTransform:"uppercase", whiteSpace:"nowrap" }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {COMPARISON_TABLE.map((row,i)=>(
                      <tr key={row.tool} style={{ background:i%2===0?"#0D1B2A":"#0A141F", cursor:"pointer" }}
                        onMouseEnter={e=>e.currentTarget.style.background="#1E3A5F22"}
                        onMouseLeave={e=>e.currentTarget.style.background=i%2===0?"#0D1B2A":"#0A141F"}>
                        <td style={{ padding:"10px 16px", color:TOOL_COLORS[i], fontWeight:900, fontSize:12 }}>{row.tool}</td>
                        <td style={{ padding:"10px 16px", fontSize:10 }}>
                          <span style={{ background:row.detection==="Multi"?"#7C3AED22":"#00D4FF22",
                            color:row.detection==="Multi"?"#7C3AED":"#00D4FF", padding:"2px 8px", borderRadius:4, fontSize:9 }}>{row.detection}</span>
                        </td>
                        <td style={{ padding:"10px 16px", color:row.accuracy==="Excellent"?"#10B981":"#F59E0B", fontSize:10 }}>{row.accuracy}</td>
                        <td style={{ padding:"10px 16px", color:row.data==="Excellent"?"#10B981":row.data==="Weak"?"#EF4444":"#F59E0B", fontSize:10 }}>{row.data}</td>
                        <td style={{ padding:"10px 16px", fontSize:12, color:"#F59E0B" }}>{row.reliability}</td>
                        <td style={{ padding:"10px 16px", fontSize:12, color:"#94A3B8" }}>{row.scalability}</td>
                        <td style={{ padding:"10px 16px" }}>
                          <span style={{ background:row.setup==="Easy"?"#10B98122":row.setup==="Complex"?"#EF444422":"#F59E0B22",
                            color:row.setup==="Easy"?"#10B981":row.setup==="Complex"?"#EF4444":"#F59E0B",
                            padding:"2px 8px", borderRadius:4, fontSize:9 }}>{row.setup}</span>
                        </td>
                        <td style={{ padding:"10px 16px", fontSize:10, color:"#64748B" }}>{row.useCase}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: LIVE FEED
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="live feed" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
              {[
                { label:"CRITICAL", count:stats?.critical??0, color:"#EF4444" },
                { label:"HIGH",     count:stats?.high??0,     color:"#F97316" },
                { label:"MEDIUM",   count:stats?.medium??0,   color:"#EAB308" },
                { label:"LOW",      count:stats?.low??0,      color:"#22C55E" },
              ].map(s=>(
                <div key={s.label} style={{ background:"#0D1B2A", borderRadius:8, padding:"12px 16px",
                  borderLeft:`4px solid ${s.color}`, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                  <span style={{ fontSize:10, color:"#64748B", letterSpacing:2 }}>{s.label}</span>
                  <span style={{ fontSize:24, fontWeight:900, color:s.color, fontFamily:"monospace" }}>{s.count}</span>
                </div>
              ))}
            </div>
            <div style={{ background:"#0D1B2A", borderRadius:12, border:"1px solid #1E3A5F", overflow:"hidden" }}>
              <div style={{ padding:"14px 20px", borderBottom:"1px solid #1E3A5F",
                display:"flex", alignItems:"center", justifyContent:"space-between" }}>
                <div style={{ fontSize:11, color:"#64748B", letterSpacing:2 }}>LIVE ATTACK DETECTION FEED</div>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <div style={{ width:7, height:7, borderRadius:"50%", background:"#22c55e", boxShadow:"0 0 6px #22c55e" }} />
                  <span style={{ fontSize:9, color:"#22c55e", letterSpacing:2 }}>STREAMING</span>
                </div>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"70px 1fr 110px 55px 120px 95px",
                gap:8, padding:"8px 14px", background:"#111827", borderBottom:"1px solid #1E3A5F" }}>
                {["TIME","ATTACK TYPE","SOURCE IP","ORIGIN","HONEYPOT","SEVERITY"].map(h=>(
                  <span key={h} style={{ fontSize:8, color:"#475569", letterSpacing:1.5 }}>{h}</span>
                ))}
              </div>
              <div ref={feedRef} style={{ maxHeight:480, overflowY:"auto" }}>
                {attacks.length===0
                  ? <div style={{ padding:"40px", textAlign:"center", color:"#64748B", fontSize:12 }}>No attacks yet — SSH to port 2222</div>
                  : attacks.map(a=><AttackRow key={a.id} attack={a} fresh={a.id===freshId}/>)
                }
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 🧬 DNA FINGERPRINTING  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="🧬 dna" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #00D4FF40" }}>
              <div style={{ fontSize:13, color:"#00D4FF", letterSpacing:2, marginBottom:6 }}>🧬 ATTACKER DNA FINGERPRINTING</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Novel feature — identifies unique attackers by behavioural pattern. Even if IP changes, the attack style (commands used, login patterns, session behaviour) remains the same. Each attacker gets a unique DNA score.
              </div>
            </div>

            {dna.length === 0
              ? <div style={{ color:"#64748B", textAlign:"center", padding:40 }}>No attacker profiles yet — generate some SSH attacks first</div>
              : dna.map((d,i)=>(
                <div key={i} style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px",
                  border:`1px solid #${d.skill_color}40`, position:"relative" }}>
                  <div style={{ position:"absolute", top:0, left:0, right:0, height:3, background:`#${d.skill_color}` }} />
                  <div style={{ display:"grid", gridTemplateColumns:"1fr auto", alignItems:"start", marginBottom:16 }}>
                    <div>
                      <div style={{ fontSize:14, color:"#CBD5E1", fontFamily:"monospace", marginBottom:4 }}>{d.ip}</div>
                      <span style={{ fontSize:9, background:`#${d.skill_color}22`, color:`#${d.skill_color}`,
                        padding:"3px 10px", borderRadius:4, fontWeight:700, letterSpacing:1 }}>{d.skill_level}</span>
                    </div>
                    <div style={{ textAlign:"right" }}>
                      <div style={{ fontSize:9, color:"#64748B", letterSpacing:1 }}>DNA SCORE</div>
                      <div style={{ fontSize:20, color:`#${d.skill_color}`, fontFamily:"monospace", fontWeight:900 }}>
                        #{String(d.dna_score).slice(-6)}
                      </div>
                    </div>
                  </div>
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12 }}>
                    {[
                      { l:"Sessions",       v:d.sessions },
                      { l:"Commands Run",   v:d.total_commands },
                      { l:"Unique Cmds",    v:d.unique_commands },
                      { l:"Usernames Tried",v:d.usernames_tried },
                      { l:"Login Successes",v:d.login_successes },
                      { l:"Files Downloaded",v:d.files_downloaded },
                    ].map(m=>(
                      <div key={m.l} style={{ background:"#111827", borderRadius:8, padding:"10px 12px" }}>
                        <div style={{ fontSize:8, color:"#64748B", letterSpacing:1, marginBottom:4 }}>{m.l}</div>
                        <div style={{ fontSize:22, fontWeight:900, color:`#${d.skill_color}`, fontFamily:"monospace" }}>{m.v}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ display:"flex", gap:16, marginTop:12, fontSize:10, color:"#64748B" }}>
                    <span>First seen: <span style={{ color:"#94A3B8" }}>{d.first_seen}</span></span>
                    <span>Last seen: <span style={{ color:"#94A3B8" }}>{d.last_seen}</span></span>
                    <span>Success rate: <span style={{ color:`#${d.skill_color}` }}>{d.success_rate}%</span></span>
                  </div>
                </div>
              ))
            }
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 🤖 ML ANOMALY DETECTION  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="🤖 ml anomaly" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #7C3AED40" }}>
              <div style={{ fontSize:13, color:"#7C3AED", letterSpacing:2, marginBottom:6 }}>🤖 ML ANOMALY DETECTION — ISOLATION FOREST</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Machine Learning model (Isolation Forest algorithm) trained on your real attack data. Automatically detects unusual attack patterns that rule-based systems would miss — including novel attack techniques and zero-day behaviour.
              </div>
            </div>

            <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16 }}>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px", border:"1px solid #7C3AED40" }}>
                <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>ANOMALIES DETECTED</div>
                <div style={{ fontSize:42, fontWeight:900, color:"#7C3AED", fontFamily:"monospace", margin:"8px 0" }}>{anomalies.filter(a=>!a.error).length}</div>
                <div style={{ fontSize:10, color:"#64748B" }}>unusual patterns found</div>
              </div>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px", border:"1px solid #EF444440" }}>
                <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>CRITICAL ANOMALIES</div>
                <div style={{ fontSize:42, fontWeight:900, color:"#EF4444", fontFamily:"monospace", margin:"8px 0" }}>
                  {anomalies.filter(a=>a.severity==="CRITICAL").length}
                </div>
                <div style={{ fontSize:10, color:"#64748B" }}>require immediate attention</div>
              </div>
              <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px", border:"1px solid #10B98140" }}>
                <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>ML ALGORITHM</div>
                <div style={{ fontSize:18, fontWeight:900, color:"#10B981", fontFamily:"monospace", margin:"8px 0" }}>Isolation Forest</div>
                <div style={{ fontSize:10, color:"#64748B" }}>contamination=10%</div>
              </div>
            </div>

            {anomalies.length===0 || anomalies[0]?.error
              ? <div style={{ color:"#64748B", textAlign:"center", padding:40 }}>
                  {anomalies[0]?.error ? `ML Error: ${anomalies[0].error}` : "Need more attack data for ML analysis (minimum 10 events)"}
                </div>
              : <div style={{ background:"#0D1B2A", borderRadius:12, border:"1px solid #1E3A5F", overflow:"hidden" }}>
                  <div style={{ padding:"14px 20px", borderBottom:"1px solid #1E3A5F", borderTop:"3px solid #7C3AED" }}>
                    <div style={{ fontSize:11, color:"#7C3AED", letterSpacing:2 }}>ANOMALOUS EVENTS DETECTED BY ML</div>
                  </div>
                  {anomalies.map((a,i)=>(
                    <div key={i} style={{ padding:"14px 20px", borderBottom:"1px solid #1E3A5F11",
                      background:i%2===0?"#0D1B2A":"#0A141F",
                      display:"grid", gridTemplateColumns:"1fr auto auto auto", gap:16, alignItems:"center" }}>
                      <div>
                        <div style={{ fontSize:12, color:"#CBD5E1", marginBottom:3 }}>{a.type}</div>
                        <div style={{ fontSize:10, color:"#64748B" }}>{a.reason}</div>
                        <div style={{ fontSize:10, color:"#94A3B8", marginTop:2, fontFamily:"monospace" }}>{a.time} · {a.source}</div>
                      </div>
                      <div style={{ textAlign:"center" }}>
                        <div style={{ fontSize:8, color:"#64748B", letterSpacing:1 }}>ANOMALY SCORE</div>
                        <div style={{ fontSize:18, fontWeight:900, color:"#7C3AED", fontFamily:"monospace" }}>{a.anomaly_score}</div>
                      </div>
                      <span style={{ fontSize:9, fontWeight:700, color:SEV_COLORS[a.severity],
                        background:SEV_COLORS[a.severity]+"22", padding:"3px 10px", borderRadius:4 }}>{a.severity}</span>
                      <span style={{ fontSize:9, color:"#7C3AED", background:"#7C3AED22",
                        padding:"3px 10px", borderRadius:4, fontWeight:700 }}>ANOMALY</span>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 🔮 ATTACK PREDICTION  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="🔮 prediction" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #10B98140" }}>
              <div style={{ fontSize:13, color:"#10B981", letterSpacing:2, marginBottom:6 }}>🔮 ML ATTACK PREDICTION — RANDOM FOREST</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Random Forest classifier trained on historical attack timing patterns. Predicts which hours are most likely to see high attack volume in the next 24 hours — enabling proactive defence.
              </div>
            </div>

            {prediction && (
              <>
                <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16 }}>
                  <div style={{ background:"#0D1B2A", borderRadius:12, padding:"24px", border:`1px solid ${
                    prediction.risk_level==="HIGH"?"#EF444440":prediction.risk_level==="MEDIUM"?"#F59E0B40":"#10B98140"}` }}>
                    <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>NEXT PEAK ATTACK HOUR</div>
                    <div style={{ fontSize:42, fontWeight:900, color:"#10B981", fontFamily:"monospace", margin:"8px 0" }}>
                      {prediction.next_peak_hour}
                    </div>
                    <div style={{ fontSize:10, color:"#64748B" }}>predicted peak time</div>
                  </div>
                  <div style={{ background:"#0D1B2A", borderRadius:12, padding:"24px", border:"1px solid #F59E0B40" }}>
                    <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>RISK LEVEL</div>
                    <div style={{ fontSize:32, fontWeight:900, margin:"8px 0",
                      color:prediction.risk_level==="HIGH"?"#EF4444":prediction.risk_level==="MEDIUM"?"#F59E0B":"#10B981",
                      fontFamily:"monospace" }}>{prediction.risk_level}</div>
                    <div style={{ fontSize:10, color:"#64748B" }}>overall threat level</div>
                  </div>
                  <div style={{ background:"#0D1B2A", borderRadius:12, padding:"24px", border:"1px solid #00D4FF40" }}>
                    <div style={{ fontSize:9, color:"#64748B", letterSpacing:2 }}>ML CONFIDENCE</div>
                    <div style={{ fontSize:42, fontWeight:900, color:"#00D4FF", fontFamily:"monospace", margin:"8px 0" }}>
                      {prediction.confidence?.toFixed(1)}%
                    </div>
                    <div style={{ fontSize:10, color:"#64748B" }}>prediction confidence</div>
                  </div>
                </div>

                <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                  <div style={{ fontSize:11, color:"#10B981", letterSpacing:2, marginBottom:16 }}>HOURLY RISK FORECAST — NEXT 24 HOURS</div>
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={prediction.hourly_risk??[]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1E3A5F" />
                      <XAxis dataKey="hour" tick={{ fill:"#64748B", fontSize:8 }} />
                      <YAxis tick={{ fill:"#64748B", fontSize:9 }} domain={[0,100]} />
                      <Tooltip content={<CustomTooltip />} />
                      <Bar dataKey="risk_score" name="Risk Score %" radius={[3,3,0,0]}>
                        {(prediction.hourly_risk??[]).map((entry,i)=>(
                          <Cell key={i} fill={entry.risk_score>70?"#EF4444":entry.risk_score>40?"#F59E0B":"#10B981"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 😤 EMOTION DETECTION  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="😤 emotions" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #EC489940" }}>
              <div style={{ fontSize:13, color:"#EC4899", letterSpacing:2, marginBottom:6 }}>😤 ATTACKER EMOTION DETECTION</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Novel feature — analyses attacker session behaviour to infer emotional state. Repeated failed commands = frustrated. Methodical exploration = confident. No commands after login = cautious. First implementation of emotion detection in honeypot research.
              </div>
            </div>

            {emotions.length===0
              ? <div style={{ color:"#64748B", textAlign:"center", padding:40 }}>No attacker sessions analysed yet</div>
              : <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16 }}>
                  {emotions.map((e,i)=>(
                    <div key={i} style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px",
                      border:"1px solid #EC489930" }}>
                      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
                        <div>
                          <div style={{ fontSize:12, color:"#94A3B8", fontFamily:"monospace", marginBottom:4 }}>{e.ip}</div>
                          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                            <span style={{ fontSize:24 }}>{e.emoji}</span>
                            <span style={{ fontSize:16, fontWeight:900, color:"#EC4899" }}>{e.emotion}</span>
                          </div>
                        </div>
                        <div style={{ textAlign:"right" }}>
                          <div style={{ fontSize:9, color:"#64748B" }}>LOGIN SUCCESS</div>
                          <div style={{ fontSize:18, fontWeight:900, fontFamily:"monospace",
                            color:e.login_success?"#10B981":"#EF4444" }}>{e.login_success?"YES":"NO"}</div>
                        </div>
                      </div>
                      <div style={{ fontSize:11, color:"#64748B", background:"#111827", borderRadius:8,
                        padding:"10px 14px", marginBottom:12 }}>💡 {e.reason}</div>
                      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:8 }}>
                        <div style={{ background:"#111827", borderRadius:8, padding:"8px 12px" }}>
                          <div style={{ fontSize:8, color:"#64748B" }}>COMMANDS</div>
                          <div style={{ fontSize:20, fontWeight:900, color:"#EC4899", fontFamily:"monospace" }}>{e.commands_run}</div>
                        </div>
                        <div style={{ background:"#111827", borderRadius:8, padding:"8px 12px" }}>
                          <div style={{ fontSize:8, color:"#64748B" }}>LOGIN FAILS</div>
                          <div style={{ fontSize:20, fontWeight:900, color:"#EF4444", fontFamily:"monospace" }}>{e.login_failures}</div>
                        </div>
                        <div style={{ background:"#111827", borderRadius:8, padding:"8px 12px" }}>
                          <div style={{ fontSize:8, color:"#64748B" }}>STATUS</div>
                          <div style={{ fontSize:12, fontWeight:900, color:e.login_success?"#10B981":"#EF4444",
                            marginTop:4 }}>{e.login_success?"INTRUDER":"BLOCKED"}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 🎯 THREAT INTELLIGENCE  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="🎯 threats" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #F59E0B40" }}>
              <div style={{ fontSize:13, color:"#F59E0B", letterSpacing:2, marginBottom:6 }}>🎯 THREAT INTELLIGENCE SCORING</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Each attacker IP is scored 0–100 based on severity and volume of their attacks. Critical events add 30 points, High add 15, Medium add 5, Low add 1. IPs scoring above 80 are classified as CRITICAL threats.
              </div>
            </div>

            {threats.length===0
              ? <div style={{ color:"#64748B", textAlign:"center", padding:40 }}>No threat data yet</div>
              : threats.map((t,i)=>(
                <div key={i} style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px",
                  border:`1px solid #${t.color}40` }}>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr auto", alignItems:"center", marginBottom:16 }}>
                    <div>
                      <div style={{ fontSize:14, color:"#CBD5E1", fontFamily:"monospace", marginBottom:6 }}>{t.ip}</div>
                      <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
                        {t.tags.map(tag=>(
                          <span key={tag} style={{ fontSize:9, background:"#1E3A5F", color:"#94A3B8",
                            padding:"2px 8px", borderRadius:4 }}>{tag}</span>
                        ))}
                      </div>
                    </div>
                    <div style={{ textAlign:"center" }}>
                      <div style={{ fontSize:9, color:"#64748B", letterSpacing:1 }}>THREAT SCORE</div>
                      <div style={{ fontSize:48, fontWeight:900, color:`#${t.color}`, fontFamily:"monospace", lineHeight:1 }}>{t.threat_score}</div>
                      <span style={{ fontSize:9, fontWeight:700, color:`#${t.color}`,
                        background:`#${t.color}22`, padding:"3px 10px", borderRadius:4 }}>{t.threat_level}</span>
                    </div>
                  </div>
                  {/* Score bar */}
                  <div style={{ height:8, background:"#1E3A5F", borderRadius:4, overflow:"hidden", marginBottom:12 }}>
                    <div style={{ height:"100%", width:`${t.threat_score}%`,
                      background:`linear-gradient(90deg,#${t.color},#${t.color}88)`,
                      borderRadius:4, transition:"width 1s ease" }} />
                  </div>
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                    <div style={{ background:"#111827", borderRadius:8, padding:"10px 14px" }}>
                      <div style={{ fontSize:8, color:"#64748B" }}>TOTAL EVENTS</div>
                      <div style={{ fontSize:22, fontWeight:900, color:`#${t.color}`, fontFamily:"monospace" }}>{t.total_events}</div>
                    </div>
                    <div style={{ background:"#111827", borderRadius:8, padding:"10px 14px" }}>
                      <div style={{ fontSize:8, color:"#64748B" }}>CRITICAL EVENTS</div>
                      <div style={{ fontSize:22, fontWeight:900, color:"#EF4444", fontFamily:"monospace" }}>{t.critical_events}</div>
                    </div>
                    <div style={{ background:"#111827", borderRadius:8, padding:"10px 14px" }}>
                      <div style={{ fontSize:8, color:"#64748B" }}>HIGH EVENTS</div>
                      <div style={{ fontSize:22, fontWeight:900, color:"#F59E0B", fontFamily:"monospace" }}>{t.high_events}</div>
                    </div>
                  </div>
                </div>
              ))
            }
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════════
            TAB: 💻 COMMAND INTELLIGENCE  (NEW)
        ══════════════════════════════════════════════════════════════════════ */}
        {tab==="💻 commands" && (
          <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
            <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #00D4FF40" }}>
              <div style={{ fontSize:13, color:"#00D4FF", letterSpacing:2, marginBottom:6 }}>💻 COMMAND INTELLIGENCE ANALYSIS</div>
              <div style={{ fontSize:11, color:"#64748B" }}>
                Analyses every command typed by attackers inside the honeypot and maps it to attacker intent. Reveals what attackers were actually trying to do — user enumeration, privilege escalation, malware download, persistence setup, and more.
              </div>
            </div>

            {commands.length===0
              ? <div style={{ color:"#64748B", textAlign:"center", padding:40 }}>No commands captured yet — SSH into Cowrie and type some commands</div>
              : <>
                  <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                    <div style={{ fontSize:11, color:"#00D4FF", letterSpacing:2, marginBottom:20 }}>COMMAND USAGE & INTENT BREAKDOWN</div>
                    {commands.map((c,i)=>(
                      <div key={i} style={{ marginBottom:16 }}>
                        <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr 1fr auto", gap:12,
                          alignItems:"center", marginBottom:6 }}>
                          <span style={{ fontSize:12, color:"#CBD5E1", fontFamily:"monospace" }}>{c.command}</span>
                          <span style={{ fontSize:11, color:"#94A3B8" }}>{c.intent}</span>
                          <span style={{ fontSize:11, color:`#${c.color}`, fontFamily:"monospace" }}>{c.count}x</span>
                          <span style={{ fontSize:9, fontWeight:700, color:`#${c.color}`,
                            background:`#${c.color}22`, padding:"2px 8px", borderRadius:4 }}>{c.risk}</span>
                        </div>
                        <div style={{ height:6, background:"#1E3A5F", borderRadius:3, overflow:"hidden" }}>
                          <div style={{ height:"100%",
                            width:`${Math.min((c.count/(commands[0]?.count||1))*100, 100)}%`,
                            background:`linear-gradient(90deg,#${c.color},#${c.color}66)`,
                            borderRadius:3, transition:"width 0.8s ease" }} />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Intent distribution pie */}
                  <div style={{ background:"#0D1B2A", borderRadius:12, padding:"20px 24px", border:"1px solid #1E3A5F" }}>
                    <div style={{ fontSize:11, color:"#00D4FF", letterSpacing:2, marginBottom:16 }}>ATTACKER INTENT DISTRIBUTION</div>
                    <ResponsiveContainer width="100%" height={260}>
                      <PieChart>
                        <Pie data={commands.map(c=>({ name:c.intent, value:c.count }))}
                          cx="50%" cy="50%" outerRadius={100} dataKey="value" labelLine={false}
                          label={({name,percent})=>`${name} ${(percent*100).toFixed(0)}%`}>
                          {commands.map((_,i)=><Cell key={i} fill={TOOL_COLORS[i%TOOL_COLORS.length]}/>)}
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </>
            }
          </div>
        )}

      </div>

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        ::-webkit-scrollbar { width:6px; }
        ::-webkit-scrollbar-track { background:#0A0E1A; }
        ::-webkit-scrollbar-thumb { background:#1E3A5F; border-radius:3px; }
      `}</style>
    </div>
  );
}
