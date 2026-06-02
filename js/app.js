"use strict";

// State
let expandedThreatId = null;

// DOM helpers
function el(id)   { return document.getElementById(id); }
function qs(sel)  { return document.querySelector(sel); }
function qsa(sel) { return document.querySelectorAll(sel); }

// Risk score 
function riskScore(threat) {
  return threat.likelihood * threat.impact;
}

const SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

// Badge helpers 
function sevBadge(sev) {
  const cls = { Critical: "badge-danger", High: "badge-warning", Medium: "badge-info", Low: "badge-success" };
  return `<span class="badge ${cls[sev] || "badge-gray"}">${sev}</span>`;
}

function layerBadge(layer) {
  const cls = {
    Ingestion:  "badge-info",
    Storage:    "badge-danger",
    Processing: "badge-gray",
    Analysis:   "badge-success",
    Serving:    "badge-warning"
  };
  return `<span class="badge ${cls[layer] || "badge-gray"}">${layer}</span>`;
}

function ciaBadge(cia) {
  const cls = { Confidentiality: "badge-info", Integrity: "badge-danger", Availability: "badge-warning" };
  return `<span class="badge ${cls[cia] || "badge-gray"}">${cia.slice(0, 4)}</span>`;
}

function effortBadge(effort) {
  const cls = { Low: "badge-success", Medium: "badge-warning", High: "badge-danger" };
  return `<span class="badge ${cls[effort] || "badge-gray"}">${effort}</span>`;
}

function priorityBadge(p) {
  const cls = { P1: "badge-danger", P2: "badge-warning", P3: "badge-info" };
  return `<span class="badge ${cls[p] || "badge-gray"}">${p}</span>`;
}

function riskBar(score) {
  const pct = Math.round((score / 25) * 100);
  const cls = score >= 20 ? "bar-danger" : score >= 12 ? "bar-warning" : "bar-info";
  return `
    <div class="risk-bar-wrap">
      <div class="risk-bar-bg">
        <div class="risk-bar-fill ${cls}" style="width:${pct}%"></div>
      </div>
      <span class="risk-score-label">${score}/25</span>
    </div>`;
}

function vTags(vsArray) {
  return vsArray.map(v => `<span class="v-tag">${v.slice(0, 3)}</span>`).join("");
}




//  Section navigation
function showSection(sectionId) {
  qsa(".section").forEach(s => s.classList.remove("active"));
  qsa(".nav-link").forEach(l => l.classList.remove("active"));

  const target = el(sectionId);
  if (target) target.classList.add("active");

  const navLink = qs(`[data-section="${sectionId}"]`);
  if (navLink) navLink.classList.add("active");

  // Update topbar title to match current section
  const titles = {
    overview:        "Overview",
    threats:         "Threat Matrix",
    sixvs:           "6Vs Analysis",
    cia:             "CIA Triad",
    recommendations: "Security Recommendations"
  };
  const titleEl = qs(".topbar-title");
  if (titleEl && titles[sectionId]) titleEl.textContent = titles[sectionId];

  if (sectionId === "overview") initOverviewCharts();
  if (sectionId === "sixvs")    initSixVsCharts();
  if (sectionId === "cia")      initCIACharts();
}


//  Overview page
function renderOverviewStats() {
  const total   = THREATS.length;
  const critical = THREATS.filter(t => t.severity === "Critical").length;
  const high    = THREATS.filter(t => t.severity === "High").length;
  const avgRisk = Math.round(THREATS.reduce((s, t) => s + riskScore(t), 0) / total);
  const vsAvg   = Math.round(SIX_VS.reduce((s, v) => s + v.score, 0) / SIX_VS.length);

  el("stat-total").textContent    = total;
  el("stat-critical").textContent = critical;
  el("stat-high").textContent     = high;
  el("stat-risk").textContent     = avgRisk + "/25";
  el("stat-vs").textContent       = vsAvg + "/100";

  const tbody = el("layer-summary-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  LAYERS.forEach(layer => {
    const subset   = THREATS.filter(t => t.layer === layer);
    const avg      = Math.round(subset.reduce((s, t) => s + riskScore(t), 0) / subset.length * 10) / 10;
    const critical = subset.filter(t => t.severity === "Critical").length;
    const high     = subset.filter(t => t.severity === "High").length;
    const pct      = Math.round((avg / 25) * 100);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${layerBadge(layer)}</td>
      <td>${subset.length}</td>
      <td>
        <div class="risk-bar-wrap">
          <div class="risk-bar-bg" style="width:100px">
            <div class="risk-bar-fill ${avg >= 16 ? "bar-danger" : avg >= 10 ? "bar-warning" : "bar-info"}" style="width:${pct}%"></div>
          </div>
          <span class="risk-score-label">${avg}/25</span>
        </div>
      </td>
      <td>${critical > 0 ? `<span class="badge badge-danger">${critical}</span>` : "0"}</td>
      <td>${high > 0 ? `<span class="badge badge-warning">${high}</span>` : "0"}</td>`;
    tbody.appendChild(tr);
  });
}


// Threat matrix page
function renderThreatTable() {
  const layerFilter = el("filter-layer").value;
  const sevFilter   = el("filter-sev").value;
  const ciaFilter   = el("filter-cia").value;

  const filtered = THREATS
    .filter(t => {
      if (layerFilter !== "All" && t.layer !== layerFilter)    return false;
      if (sevFilter   !== "All" && t.severity !== sevFilter)   return false;
      if (ciaFilter   !== "All" && !t.cia.includes(ciaFilter)) return false;
      return true;
    })
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);

  const countLabel = el("filter-count");
  if (countLabel) countLabel.textContent = `${filtered.length} threat${filtered.length !== 1 ? "s" : ""}`;

  const tbody = el("threat-table-body");
  if (!tbody) return;
  tbody.innerHTML = "";
  expandedThreatId = null;

  filtered.forEach(threat => {
    const score = riskScore(threat);

    const tr = document.createElement("tr");
    tr.className  = "threat-row";
    tr.dataset.id = threat.id;
    tr.innerHTML  = `
      <td class="col-id">${threat.id}</td>
      <td>${layerBadge(threat.layer)}</td>
      <td class="col-threat">${threat.threat}</td>
      <td><div class="tag-group">${threat.cia.map(ciaBadge).join("")}</div></td>
      <td><div class="tag-group">${vTags(threat.vs)}</div></td>
      <td>${sevBadge(threat.severity)}</td>
      <td>${riskBar(score)}</td>`;

    tr.addEventListener("click", () => toggleExpand(threat, tr, tbody));
    tbody.appendChild(tr);
  });
}

function toggleExpand(threat, parentRow, tbody) {
  if (expandedThreatId === threat.id) {
    const existing = el(`expand-${threat.id}`);
    if (existing) existing.remove();
    expandedThreatId = null;
    parentRow.classList.remove("expanded");
    return;
  }

  if (expandedThreatId) {
    const old = el(`expand-${expandedThreatId}`);
    if (old) old.remove();
    const oldParent = tbody.querySelector(".threat-row.expanded");
    if (oldParent) oldParent.classList.remove("expanded");
  }

  const expandRow = document.createElement("tr");
  expandRow.id        = `expand-${threat.id}`;
  expandRow.className = "expand-row";
  expandRow.innerHTML = `
    <td colspan="7">
      <div class="expand-inner">
        <div class="expand-grid">
          <div>
            <p class="expand-label">Description</p>
            <p class="expand-text">${threat.description}</p>
          </div>
          <div>
            <p class="expand-label">Recommended controls</p>
            <p class="expand-text">${threat.controls}</p>
            <p class="expand-label" style="margin-top:12px">MITRE ATT&CK</p>
            <p class="expand-text">
              <a href="https://attack.mitre.org/techniques/${threat.mitre.replace(".", "/")}" target="_blank" rel="noopener">${threat.mitre}</a>
            </p>
          </div>
        </div>
      </div>
    </td>`;

  parentRow.after(expandRow);
  parentRow.classList.add("expanded");
  expandedThreatId = threat.id;
}


// 6Vs analysis page — radar + score bars + detail cards
function renderSixVsCards() {
  // Score bars (right card, inside charts-grid) ─
  const barsEl = el("sixvs-bars-inline");
  if (barsEl) {
    barsEl.innerHTML = SIX_VS.map(item => {
      const cls = item.score >= 90 ? "bar-danger"
                : item.score >= 80 ? "bar-warning"
                : item.score >= 70 ? "bar-info"
                : "bar-success";
      return `
        <div class="vs-bar-row">
          <div class="vs-bar-label-row">
            <span class="vs-bar-name">${item.v}</span>
            <span class="vs-bar-score">${item.score}<span class="vs-max">/100</span></span>
          </div>
          <div class="progress-bg">
            <div class="progress-fill ${cls}" style="width:${item.score}%"></div>
          </div>
        </div>`;
    }).join("");
  }

  // Detail cards (grid below charts)
  const container = el("sixvs-cards");
  if (!container) return;
  container.innerHTML = "";

  SIX_VS.forEach(item => {
    const cls   = item.score >= 90 ? "bar-danger"
                : item.score >= 80 ? "bar-warning"
                : item.score >= 70 ? "bar-info"
                : "bar-success";
    const count = THREATS.filter(t => t.vs.includes(item.v)).length;

    const card = document.createElement("div");
    card.className = "vs-card";
    card.innerHTML = `
      <div class="vs-card-header">
        <span class="vs-name">${item.v}</span>
        <span class="vs-score">${item.score}<span class="vs-max">/100</span></span>
      </div>
      <div class="progress-bg">
        <div class="progress-fill ${cls}" style="width:${item.score}%"></div>
      </div>
      <p class="vs-summary">${item.summary}</p>
      <p class="vs-detail">${item.detail}</p>
      <p class="vs-count">${count} threat${count !== 1 ? "s" : ""} mapped to this dimension</p>`;
    container.appendChild(card);
  });
}


// CIA triad page
function renderCIACards() {
  const container = el("cia-cards");
  if (!container) return;
  container.innerHTML = "";

  const definitions = {
    Confidentiality: "Ensures that data is accessible only to those who are authorised to access it. Violations include unauthorised disclosure, data breaches, and privacy violations.",
    Integrity:       "Ensures that data remains accurate, consistent, and unaltered except by authorised parties. Violations include tampering, poisoning, and record corruption.",
    Availability:    "Ensures that systems and data are accessible and operational when needed. Violations include denial of service attacks, ransomware, and infrastructure destruction."
  };

  ["Confidentiality", "Integrity", "Availability"].forEach(pillar => {
    const subset   = THREATS.filter(t => t.cia.includes(pillar));
    const critical = subset.filter(t => t.severity === "Critical").length;
    const high     = subset.filter(t => t.severity === "High").length;
    const top      = subset.filter(t => t.severity === "Critical" || t.severity === "High").slice(0, 3);
    const cls      = { Confidentiality: "cia-blue", Integrity: "cia-red", Availability: "cia-amber" };

    const card = document.createElement("div");
    card.className = `cia-card ${cls[pillar]}`;
    card.innerHTML = `
      <div class="cia-card-header">
        <h3 class="cia-name">${pillar}</h3>
        <span class="cia-total">${subset.length}</span>
      </div>
      <p class="cia-def">${definitions[pillar]}</p>
      <div class="cia-counts">
        <div class="cia-count-item">
          <span class="cia-count-num danger-text">${critical}</span>
          <span class="cia-count-lbl">Critical</span>
        </div>
        <div class="cia-count-item">
          <span class="cia-count-num warning-text">${high}</span>
          <span class="cia-count-lbl">High</span>
        </div>
        <div class="cia-count-item">
          <span class="cia-count-num">${subset.length - critical - high}</span>
          <span class="cia-count-lbl">Other</span>
        </div>
      </div>
      <p class="expand-label" style="margin-top:14px;margin-bottom:8px">Top threats</p>
      <div class="cia-threat-list">
        ${top.map(t => `
          <div class="cia-threat-item">
            ${sevBadge(t.severity)}
            <span class="cia-threat-name">${t.threat}</span>
          </div>`).join("")}
      </div>`;
    container.appendChild(card);
  });
}


// Recommendations page
function renderRecommendations() {
  const container = el("rec-list");
  if (!container) return;
  container.innerHTML = "";

  const groups = {
    P1: "Critical — implement within 7 days",
    P2: "High — implement within 30 days",
    P3: "Medium — implement within 90 days"
  };

  ["P1", "P2", "P3"].forEach(p => {
    const subset = RECOMMENDATIONS.filter(r => r.priority === p);
    if (!subset.length) return;

    const groupEl = document.createElement("div");
    groupEl.className = "rec-group";
    groupEl.innerHTML = `<div class="rec-group-header">${priorityBadge(p)}<span class="rec-group-label">${groups[p]}</span></div>`;

    subset.forEach(rec => {
      const item = document.createElement("div");
      item.className = "rec-item";
      item.innerHTML = `
        <div class="rec-header">
          <span class="rec-title">${rec.title}</span>
          <div class="rec-meta-right">
            ${effortBadge(rec.effort)} effort
          </div>
        </div>
        <p class="rec-layer">Layer: ${rec.layer}</p>
        <p class="rec-body">${rec.body}</p>`;
      groupEl.appendChild(item);
    });

    container.appendChild(groupEl);
  });
}


// Filters
function bindFilters() {
  const layerSel = el("filter-layer");
  const sevSel   = el("filter-sev");
  const ciaSel   = el("filter-cia");

  if (layerSel) layerSel.addEventListener("change", renderThreatTable);
  if (sevSel)   sevSel.addEventListener("change",   renderThreatTable);
  if (ciaSel)   ciaSel.addEventListener("change",   renderThreatTable);
}

function bindNav() {
  qsa(".nav-link").forEach(link => {
    link.addEventListener("click", e => {
      e.preventDefault();
      showSection(link.dataset.section);
    });
  });
}


// Boot
document.addEventListener("DOMContentLoaded", () => {
  setChartDefaults();

  bindNav();
  bindFilters();

  renderOverviewStats();
  renderThreatTable();
  renderSixVsCards();
  renderCIACards();
  renderRecommendations();

  showSection("overview");

  // Toggle sidebar on hamburger click
  const hamburgerBtn = document.getElementById("hamburger-btn");
  const sidebarEl = document.querySelector(".sidebar");
  const overlayEl = document.getElementById("sidebar-overlay");

  if (hamburgerBtn && sidebarEl && overlayEl) {
    hamburgerBtn.addEventListener("click", () => {
      const isOpen = sidebarEl.classList.toggle("open");
      overlayEl.classList.toggle("active", isOpen);
      hamburgerBtn.classList.toggle("active", isOpen);
      hamburgerBtn.setAttribute("aria-label", isOpen ? "Close sidebar menu" : "Open sidebar menu");
    });

    // Close sidebar on overlay click
    overlayEl.addEventListener("click", () => {
      sidebarEl.classList.remove("open");
      overlayEl.classList.remove("active");
      hamburgerBtn.classList.remove("active");
      hamburgerBtn.setAttribute("aria-label", "Open sidebar menu");
    });

    // Close sidebar when clicking any nav link
    document.querySelectorAll(".nav-link").forEach(link => {
      link.addEventListener("click", () => {
        sidebarEl.classList.remove("open");
        overlayEl.classList.remove("active");
        hamburgerBtn.classList.remove("active");
        hamburgerBtn.setAttribute("aria-label", "Open sidebar menu");
      });
    });
  }
});
