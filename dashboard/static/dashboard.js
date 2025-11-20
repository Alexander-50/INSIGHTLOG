// dashboard/static/dashboard.js
const REFRESH_MS = 3000;
let ipsChart = null;
let statusChart = null;
let urlsChart = null;
let sevChart = null;
let timelineChart = null;

function qs(sel){ return document.querySelector(sel); }
function qsa(sel){ return document.querySelectorAll(sel); }

// Helper to safely set text content without crashing
function safeSetText(sel, text) {
    const el = qs(sel);
    if (el) el.textContent = text;
    else console.warn(`Element not found: ${sel}`);
}

let currentTab = "overview";

function setTab(tab){
  currentTab = tab;
  qsa(".tabcontent").forEach(n => n.classList.add("hidden"));
  const target = qs(`#tab-${tab}`);
  if(target) target.classList.remove("hidden");
  
  qsa(".navbtn").forEach(b => b.classList.remove("bg-slate-100"));
  [...qsa(`.navbtn[data-tab="${tab}"]`)].forEach(b => b.classList.add("bg-slate-100"));
}

qsa(".navbtn").forEach(btn => {
  btn.addEventListener("click", () => setTab(btn.dataset.tab));
});

qs("#dark-toggle").addEventListener("click", () => {
  document.documentElement.classList.toggle("dark");
  document.body.classList.toggle("bg-slate-900");
  document.body.classList.toggle("text-white");
});

function severityColor(sev){
  sev = (sev||"INFO").toUpperCase();
  if(sev === "CRITICAL") return 'rgb(220,38,38)'; // Red
  if(sev === "ALERT" || sev === "ERROR") return 'rgb(249,115,22)'; // Orange
  if(sev === "WARNING") return 'rgb(234,179,8)'; // Yellow
  if(sev === "INFO") return 'rgb(34,197,94)'; // Green
  return 'rgb(100,116,139)'; // Grey
}

async function fetchData(){
  try {
    const res = await fetch("/data/report");
    if(!res.ok) throw new Error(`HTTP Error: ${res.status}`);
    
    const data = await res.json();
    
    // If Python says file not found
    if(data.ok === false){
      console.warn("Backend Error:", data.error);
      safeSetText("#last-updated", "Waiting for report.json...");
      return;
    }

    // Basic stats (Using safe setter)
    safeSetText("#last-updated", data.generated_at || "-");
    safeSetText("#total-records", data.summary.total_records || 0);
    safeSetText("#active-alerts", (data.alerts || []).length);
    safeSetText("#corr-count", (data.correlations || []).length);

    // Top IPs
    const topIps = data.summary.top_ips || [];
    if(!ipsChart){
      const ctx = qs("#ipsChart").getContext("2d");
      ipsChart = new Chart(ctx, {
        type:'bar',
        data:{ labels: topIps.map(i=>i[0]), datasets:[{label:'Requests', data: topIps.map(i=>i[1])}] },
        options:{ responsive:true }
      });
    } else {
      ipsChart.data.labels = topIps.map(i=>i[0]);
      ipsChart.data.datasets[0].data = topIps.map(i=>i[1]);
      ipsChart.update();
    }

    // Status Codes
    const sc = data.summary.status_counts || [];
    if(!statusChart){
      const ctx = qs("#statusChart").getContext("2d");
      statusChart = new Chart(ctx, {
        type:'bar',
        data:{ labels: sc.map(s=>s[0]), datasets:[{label:'Count', data: sc.map(s=>s[1])}] },
        options:{ responsive:true }
      });
    } else {
      statusChart.data.labels = sc.map(s=>s[0]);
      statusChart.data.datasets[0].data = sc.map(s=>s[1]);
      statusChart.update();
    }

    // Top URLs
    const urls = data.summary.top_urls || [];
    if(!urlsChart){
      const ctx = qs("#urlsChart").getContext("2d");
      urlsChart = new Chart(ctx, {
        type:'bar',
        data:{ labels:urls.map(u=>u[0]), datasets:[{label:'Hits', data:urls.map(u=>u[1])}] },
        options:{ indexAxis:'y', responsive:true }
      });
    } else {
      urlsChart.data.labels = urls.map(u=>u[0]);
      urlsChart.data.datasets[0].data = urls.map(u=>u[1]);
      urlsChart.update();
    }

    // Severity Pie
    const alerts = data.alerts || [];
    const sevCounts = alerts.reduce((acc,a)=>{
      const s = (a.severity||"UNKNOWN").toUpperCase();
      acc[s] = (acc[s]||0)+1; 
      return acc;
    },{});
    if(!sevChart){
      const ctx = qs("#sevChart").getContext("2d");
      sevChart = new Chart(ctx, {
        type:'pie',
        data:{ labels:Object.keys(sevCounts), datasets:[{data:Object.values(sevCounts)}] },
        options:{ responsive:true }
      });
    } else {
      sevChart.data.labels = Object.keys(sevCounts);
      sevChart.data.datasets[0].data = Object.values(sevCounts);
      sevChart.update();
    }

    // Alerts list
    const alertsNode = qs("#alerts-list");
    if(alertsNode) {
        alertsNode.innerHTML = "";
        alerts.slice().reverse().forEach(a => {
        const el = document.createElement("div");
        el.className = "p-2 border rounded bg-white/60";
        el.innerHTML = `<div class="flex justify-between"><strong style="color:${severityColor(a.severity)}">${a.severity}</strong><span class="text-sm text-slate-500">${a.type||''}</span></div>
                        <div class="text-sm">${a.message||''}</div>`;
        alertsNode.appendChild(el);
        });
    }

    // Correlations
    const corrNode = qs("#corr-list");
    if(corrNode) {
        corrNode.innerHTML = "";
        (data.correlations||[]).slice().reverse().forEach(c=>{
        const el=document.createElement("div");
        el.className="p-2 border rounded bg-white/60";
        el.innerHTML=`<strong>${c.type}</strong> — ${c.message}`;
        corrNode.appendChild(el);
        });
    }

    // Timeline
    const timeline = data.timeline || [];
    const categories = ["record","alert","burst","plugin","correlation"];
    const points = [];

    timeline.forEach(ev=>{
      if(!ev.timestamp) return;
      const ts = new Date(ev.timestamp).getTime();
      if(isNaN(ts)) return; 

      let ci = categories.indexOf((ev.type||"").toLowerCase());
      if(ci < 0) ci = 0; // default to record

      points.push({
        x: ts,
        y: ci,
        r: 6,
        backgroundColor: severityColor(ev.severity),
        meta: ev
      });
    });

    if(!timelineChart){
      const ctxT = qs("#timelineChart").getContext("2d");
      timelineChart = new Chart(ctxT, {
        type: 'bubble',
        data: { datasets:[{ label:"Events", data:points }] },
        options: {
          parsing: false,
          scales: {
            x:{ type:'time', time:{ unit:'minute' }, title:{ display:true, text:'Time' } },
            y:{
              type:'linear',
              ticks:{ callback:(v)=>categories[v]||"", stepSize:1, min:0, max:4 },
              title:{ display:true, text:'Event Type' }
            }
          },
          plugins:{
            tooltip:{
              callbacks:{
                label:(ctx)=>{
                  const m=ctx.raw.meta||{};
                  return `${m.timestamp} | ${m.severity} | ${m.message}`;
                }
              }
            }
          },
          maintainAspectRatio:false,
          responsive:true
        }
      });
    } else {
      timelineChart.data.datasets[0].data = points;
      timelineChart.update();
    }

    // Timeline List
    const tnode = qs("#timeline-list");
    if(tnode) {
        tnode.innerHTML = "";
        timeline.slice(-50).reverse().forEach(ev=>{
        if(!ev.timestamp) return;
        const item = document.createElement("div");
        item.className = "p-2 border rounded bg-white/60";
        item.innerHTML = `
            <div class="flex justify-between">
            <strong style="color:${severityColor(ev.severity)}">${ev.severity}</strong>
            <span class="text-sm text-slate-500">${ev.timestamp}</span>
            </div>
            <div class="text-sm"><em>${ev.type}</em> ${ev.message}</div>`;
        tnode.appendChild(item);
        });
    }

  } catch (e) {
    console.error("fetchData error", e);
  }
}

// Initial load
setTab("overview");
fetchData();
// Refresh every 3 seconds
setInterval(fetchData, REFRESH_MS);