"use strict";

const API = "/api";
const MAX_FILE_MB = 10;
const charts = {};
let currentAnalysisId = null;

const $ = (id) => document.getElementById(id);

// Build a DOM element with safe text (never inserts HTML from the server).
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function showError(message) {
  const box = $("error-box");
  box.textContent = message;
  box.hidden = false;
}

function clearError() {
  $("error-box").hidden = true;
  $("error-box").textContent = "";
}

// Calls the API and turns error responses into readable messages.
async function apiFetch(url, options) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    throw new Error("Could not reach the server. Is it running?");
  }
  if (response.status === 204) return null;

  let body = null;
  try { body = await response.json(); } catch (err) { /* no JSON body */ }

  if (!response.ok) {
    let message = "Request failed (status " + response.status + ").";
    if (body && typeof body.detail === "string") {
      message = body.detail;
    } else if (body && Array.isArray(body.detail)) {
      message = "Invalid input: " + body.detail.map((d) => d.msg).join("; ");
    }
    throw new Error(message);
  }
  return body;
}

function renderSummary(a) {
  $("result-title").textContent = "Results for " + a.filename + " (analysis #" + a.id + ")";
  $("stat-total").textContent = a.total_records.toLocaleString();
  $("stat-flagged").textContent = a.anomaly_count.toLocaleString();
  $("stat-percent").textContent = a.anomaly_percentage.toFixed(2) + "%";
  $("stat-skipped").textContent = a.skipped_records.toLocaleString();
}

function renderAlerts(a) {
  const body = $("alerts-body");
  body.replaceChildren();
  a.alerts.forEach((alert) => {
    const d = alert.details;
    const tr = document.createElement("tr");
    [alert.row_number, d.timestamp, d.protocol, d.duration, d.packets, d.bytes, alert.score.toFixed(4)]
      .forEach((value) => tr.appendChild(el("td", value)));
    body.appendChild(tr);
  });

  const note = $("truncation-note");
  if (a.alerts_truncated) {
    note.textContent = "Showing the top " + a.alerts.length + " of " + a.anomaly_count + " flagged records.";
    note.hidden = false;
  } else {
    note.hidden = true;
  }
}

function makeChart(key, canvasId, config) {
  if (charts[key]) charts[key].destroy();
  charts[key] = new Chart($(canvasId), config);
}

function renderCharts(a) {
  if (typeof Chart === "undefined") {
    $("chart-warning").hidden = false;
    return;
  }
  $("chart-warning").hidden = true;

  makeChart("distribution", "chart-distribution", {
    type: "doughnut",
    data: {
      labels: ["Normal", "Anomalous"],
      datasets: [{ data: [a.total_records - a.anomaly_count, a.anomaly_count], backgroundColor: ["#2563eb", "#d93025"] }],
    },
  });

  const byProtocol = {};
  a.alerts.forEach((alert) => {
    const p = alert.details.protocol;
    byProtocol[p] = (byProtocol[p] || 0) + 1;
  });
  makeChart("protocol", "chart-protocol", {
    type: "bar",
    data: {
      labels: Object.keys(byProtocol),
      datasets: [{ label: "Flagged records", data: Object.values(byProtocol), backgroundColor: "#f5a623" }],
    },
    options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
  });

  makeChart("scatter", "chart-scatter", {
    type: "scatter",
    data: {
      datasets: [{
        label: "Flagged record",
        data: a.alerts.map((alert) => ({ x: alert.details.packets, y: alert.details.bytes })),
        backgroundColor: "#d93025",
      }],
    },
    options: {
      scales: {
        x: { title: { display: true, text: "Packets" } },
        y: { title: { display: true, text: "Bytes" } },
      },
    },
  });
}

function showAnalysis(a) {
  currentAnalysisId = a.id;
  renderSummary(a);
  renderAlerts(a);
  renderCharts(a);
  $("results").hidden = false;
}

async function viewAnalysis(id) {
  clearError();
  try {
    const a = await apiFetch(API + "/analyses/" + id);
    showAnalysis(a);
    $("results").scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    showError(err.message);
  }
}

async function deleteAnalysis(id) {
  if (!confirm("Delete analysis #" + id + " and its alerts?")) return;
  clearError();
  try {
    await apiFetch(API + "/analyses/" + id, { method: "DELETE" });
    if (currentAnalysisId === id) {
      $("results").hidden = true;
      currentAnalysisId = null;
    }
    await loadHistory();
  } catch (err) {
    showError(err.message);
  }
}

async function loadHistory() {
  try {
    const data = await apiFetch(API + "/analyses");
    const body = $("history-body");
    body.replaceChildren();
    $("history-empty").hidden = data.items.length > 0;

    data.items.forEach((a) => {
      const tr = document.createElement("tr");
      [a.id, a.filename, new Date(a.created_at).toLocaleString(), a.total_records, a.anomaly_count,
        a.anomaly_percentage.toFixed(2) + "%"].forEach((v) => tr.appendChild(el("td", v)));

      const actions = document.createElement("td");
      const viewBtn = el("button", "View", "small");
      viewBtn.type = "button";
      viewBtn.addEventListener("click", () => viewAnalysis(a.id));
      const delBtn = el("button", "Delete", "danger");
      delBtn.type = "button";
      delBtn.style.marginLeft = "6px";
      delBtn.addEventListener("click", () => deleteAnalysis(a.id));
      actions.append(viewBtn, delBtn);
      tr.appendChild(actions);
      body.appendChild(tr);
    });
  } catch (err) {
    showError(err.message);
  }
}

async function handleUpload(event) {
  event.preventDefault();
  clearError();

  const file = $("file-input").files[0];
  if (!file) { showError("Please choose a CSV file first."); return; }
  if (!file.name.toLowerCase().endsWith(".csv")) { showError("Only .csv files are supported."); return; }
  if (file.size > MAX_FILE_MB * 1024 * 1024) { showError("File is too large. The maximum is " + MAX_FILE_MB + " MB."); return; }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("contamination", $("contamination-input").value);

  $("analyze-btn").disabled = true;
  $("loading").hidden = false;
  try {
    const a = await apiFetch(API + "/analyze", { method: "POST", body: formData });
    showAnalysis(a);
    await loadHistory();
  } catch (err) {
    showError(err.message);
  } finally {
    $("analyze-btn").disabled = false;
    $("loading").hidden = true;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("upload-form").addEventListener("submit", handleUpload);
  loadHistory();
});
