"use strict";

// Chart colour constants
const CHART_COLORS = {
  danger:  "#c0392b",
  warning: "#d68910",
  info:    "#1a6fa8",
  success: "#1e8449",
  gray:    "#7f8c8d",
  dangerBg:  "rgba(192, 57, 43, 0.15)",
  warningBg: "rgba(214, 137, 16, 0.15)",
  infoBg:    "rgba(26, 111, 168, 0.15)",
  successBg: "rgba(30, 132, 73, 0.15)"
};

// Layer colour map — one colour per layer, consistent across all charts
const LAYER_COLORS = {
  Ingestion:  "#1a6fa8",
  Storage:    "#c0392b",
  Processing: "#7f8c8d",
  Analysis:   "#1e8449",
  Serving:    "#d68910"
};

// CIA triad colour map
const CIA_COLORS = {
  Confidentiality: "#1a6fa8",
  Integrity:       "#c0392b",
  Availability:    "#d68910"
};

// Severity colour map
const SEV_COLORS = {
  Critical: "#c0392b",
  High:     "#d68910",
  Medium:   "#1a6fa8",
  Low:      "#1e8449"
};

// Shared chart defaults applied once globally
function setChartDefaults() {
  Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
  Chart.defaults.font.size   = 12;
  Chart.defaults.color       = "#555";
  Chart.defaults.plugins.legend.labels.boxWidth  = 12;
  Chart.defaults.plugins.legend.labels.padding   = 16;
  Chart.defaults.plugins.tooltip.backgroundColor = "#fff";
  Chart.defaults.plugins.tooltip.titleColor      = "#222";
  Chart.defaults.plugins.tooltip.bodyColor       = "#555";
  Chart.defaults.plugins.tooltip.borderColor     = "#ddd";
  Chart.defaults.plugins.tooltip.borderWidth     = 1;
  Chart.defaults.plugins.tooltip.padding         = 10;
}

// Registry so we can destroy a chart before re-rendering it
const chartRegistry = {};

function destroyChart(id) {
  if (chartRegistry[id]) {
    chartRegistry[id].destroy();
    delete chartRegistry[id];
  }
}

// compute average risk score per layer 
function getLayerAvgRisk() {
  return LAYERS.map(layer => {
    const subset = THREATS.filter(t => t.layer === layer);
    const avg    = subset.reduce((sum, t) => sum + t.likelihood * t.impact, 0) / subset.length;
    return Math.round(avg * 10) / 10;
  });
}

// count threats per severity
function getSeverityCounts() {
  return ["Critical", "High", "Medium", "Low"].map(s => ({
    label: s,
    count: THREATS.filter(t => t.severity === s).length
  }));
}

// count threats per CIA pillar
function getCIACounts() {
  return ["Confidentiality", "Integrity", "Availability"].map(c => ({
    label: c,
    count: THREATS.filter(t => t.cia.includes(c)).length
  }));
}

// CIA breakdown per layer (for stacked bar chart)
function getCIAPerLayer() {
  return LAYERS.map(layer => {
    const subset = THREATS.filter(t => t.layer === layer);
    return {
      layer,
      Confidentiality: subset.filter(t => t.cia.includes("Confidentiality")).length,
      Integrity:       subset.filter(t => t.cia.includes("Integrity")).length,
      Availability:    subset.filter(t => t.cia.includes("Availability")).length
    };
  });
}


// Chart: Average Risk Score by Layer (bar chart on overview page)
function renderLayerRiskChart(canvasId) {
  destroyChart(canvasId);
  const ctx  = document.getElementById(canvasId).getContext("2d");
  const data = getLayerAvgRisk();

  chartRegistry[canvasId] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: LAYERS,
      datasets: [{
        label: "Avg risk score",
        data,
        backgroundColor: LAYERS.map(l => LAYER_COLORS[l] + "cc"),
        borderColor:     LAYERS.map(l => LAYER_COLORS[l]),
        borderWidth: 1,
        borderRadius: 4,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.parsed.y} / 25`
          }
        }
      },
      scales: {
        y: {
          min: 0,
          max: 25,
          ticks: { stepSize: 5 },
          grid: { color: "#f0f0f0" },
          title: { display: true, text: "Risk score (max 25)", color: "#888", font: { size: 11 } }
        },
        x: {
          grid: { display: false }
        }
      }
    }
  });
}


// Severity Distribution (doughnut on overview page)
function renderSeverityDonut(canvasId) {
  destroyChart(canvasId);
  const ctx    = document.getElementById(canvasId).getContext("2d");
  const counts = getSeverityCounts();

  chartRegistry[canvasId] = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: counts.map(c => c.label),
      datasets: [{
        data:            counts.map(c => c.count),
        backgroundColor: counts.map(c => SEV_COLORS[c.label] + "dd"),
        borderColor:     counts.map(c => SEV_COLORS[c.label]),
        borderWidth: 1,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "60%",
      plugins: {
        legend: {
          position: "right",
          labels: { font: { size: 11 } }
        }
      }
    }
  });
}


// Chart: CIA Triad Exposure horizontal bar (overview page)
function renderCIABar(canvasId) {
  destroyChart(canvasId);
  const ctx    = document.getElementById(canvasId).getContext("2d");
  const counts = getCIACounts();

  chartRegistry[canvasId] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: counts.map(c => c.label),
      datasets: [{
        label: "Threats",
        data:            counts.map(c => c.count),
        backgroundColor: counts.map(c => CIA_COLORS[c.label] + "cc"),
        borderColor:     counts.map(c => CIA_COLORS[c.label]),
        borderWidth: 1,
        borderRadius: 4,
        borderSkipped: false
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: "#f0f0f0" },
          title: { display: true, text: "Number of threats", color: "#888", font: { size: 11 } }
        },
        y: { grid: { display: false } }
      }
    }
  });
}


// Chart: 6Vs Radar (sixvs page)
function renderRadarChart(canvasId) {
  destroyChart(canvasId);
  const ctx = document.getElementById(canvasId).getContext("2d");

  chartRegistry[canvasId] = new Chart(ctx, {
    type: "radar",
    data: {
      labels: SIX_VS.map(v => v.v),
      datasets: [{
        label: "Risk score",
        data:            SIX_VS.map(v => v.score),
        borderColor:     CHART_COLORS.danger,
        backgroundColor: CHART_COLORS.dangerBg,
        pointBackgroundColor: CHART_COLORS.danger,
        pointBorderColor:     "#fff",
        pointRadius: 5,
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { display: false, stepSize: 25 },
          grid:        { color: "#e8e8e8" },
          angleLines:  { color: "#e8e8e8" },
          pointLabels: { font: { size: 12 } }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}


// Chart: CIA Exposure per Layer (stacked bar on CIA triad page)
function renderCIALayerChart(canvasId) {
  destroyChart(canvasId);
  const ctx  = document.getElementById(canvasId).getContext("2d");
  const data = getCIAPerLayer();

  chartRegistry[canvasId] = new Chart(ctx, {
    type: "bar",
    data: {
      labels: LAYERS,
      datasets: [
        {
          label: "Confidentiality",
          data:            data.map(d => d.Confidentiality),
          backgroundColor: CIA_COLORS.Confidentiality + "cc",
          borderColor:     CIA_COLORS.Confidentiality,
          borderWidth: 1,
          borderRadius: 2
        },
        {
          label: "Integrity",
          data:            data.map(d => d.Integrity),
          backgroundColor: CIA_COLORS.Integrity + "cc",
          borderColor:     CIA_COLORS.Integrity,
          borderWidth: 1,
          borderRadius: 2
        },
        {
          label: "Availability",
          data:            data.map(d => d.Availability),
          backgroundColor: CIA_COLORS.Availability + "cc",
          borderColor:     CIA_COLORS.Availability,
          borderWidth: 1,
          borderRadius: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom" }
      },
      scales: {
        x: { grid: { display: false } },
        y: {
          grid: { color: "#f0f0f0" },
          ticks: { stepSize: 1 },
          title: { display: true, text: "Threat count", color: "#888", font: { size: 11 } }
        }
      }
    }
  });
}


// Public entry point: called by app.js when a section becomes visible
function initOverviewCharts() {
  renderLayerRiskChart("layerRiskChart");
  renderSeverityDonut("severityDonut");
  renderCIABar("ciaBarChart");
}

function initSixVsCharts() {
  renderRadarChart("radarChart");
}

function initCIACharts() {
  renderCIALayerChart("ciaLayerChart");
}
