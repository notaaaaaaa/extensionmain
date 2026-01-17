function loadDetections(callback) {
  chrome.storage.local.get({ detections: [] }, (data) => {
    const list = Array.isArray(data.detections) ? data.detections : [];
    // Most recent first
    list.sort((a, b) => (b.time || 0) - (a.time || 0));
    console.log("[POPUP] Loaded detections from storage:", list.length);
    callback(list);
  });
}

function formatTime(ts) {
  if (!ts) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts);
  }
}

function buildOriginOptions(detections) {
  const originFilter = document.getElementById("originFilter");
  // Keep the first option (All origins)
  while (originFilter.options.length > 1) {
    originFilter.remove(1);
  }

  const origins = new Set();
  detections.forEach((d) => {
    if (d.origin) origins.add(d.origin);
  });

  Array.from(origins)
    .sort()
    .forEach((origin) => {
      const opt = document.createElement("option");
      opt.value = origin;
      opt.textContent = origin;
      originFilter.appendChild(opt);
    });
}

function applyFilters(detections) {
  const originFilter = document.getElementById("originFilter").value;
  const categoryFilter = document.getElementById("categoryFilter").value;
  const rawLimit = document.getElementById("limitSelect").value;
  const limit = parseInt(rawLimit, 10);

  let filtered = detections;

  if (originFilter !== "all") {
    filtered = filtered.filter((d) => d.origin === originFilter);
  }

  if (categoryFilter !== "all") {
    filtered = filtered.filter((d) => d.category === categoryFilter);
  }

  // If limit is 0 or not a valid number, show all filtered events
  if (Number.isNaN(limit) || limit <= 0) {
    console.log(
      "[POPUP] Showing all events after filters:",
      filtered.length
    );
    return filtered;
  }

  console.log(
    `[POPUP] Showing last ${limit} events out of ${filtered.length} after filters`
  );
  return filtered.slice(0, limit);
}

function renderSummary(detections) {
  const tbody = document.querySelector("#summaryTable tbody");
  tbody.innerHTML = "";

  if (!detections.length) {
    return;
  }

  const perOrigin = {};
  detections.forEach((d) => {
    const origin = d.origin || "unknown";
    const cat = d.category || "UNKNOWN";
    if (!perOrigin[origin]) {
      perOrigin[origin] = {
        INJECTION: 0,
        XSS: 0,
        MISCONFIGURATION: 0,
        SENSITIVE_DATA_EXPOSURE: 0,
        CLIENT_SIDE_ATTACKS: 0,
        UNKNOWN: 0,
      };
    }
    if (perOrigin[origin][cat] === undefined) {
      perOrigin[origin][cat] = 0;
    }
    perOrigin[origin][cat]++;
  });

  Object.entries(perOrigin).forEach(([origin, counts]) => {
    const tr = document.createElement("tr");
    const total =
      counts.INJECTION +
      counts.XSS +
      counts.MISCONFIGURATION +
      counts.SENSITIVE_DATA_EXPOSURE +
      counts.CLIENT_SIDE_ATTACKS +
      (counts.UNKNOWN || 0);

    tr.innerHTML = `
      <td>${origin}</td>
      <td>${counts.INJECTION || 0}</td>
      <td>${counts.XSS || 0}</td>
      <td>${counts.MISCONFIGURATION || 0}</td>
      <td>${counts.SENSITIVE_DATA_EXPOSURE || 0}</td>
      <td>${counts.CLIENT_SIDE_ATTACKS || 0}</td>
      <td>${total}</td>
    `;

    tbody.appendChild(tr);
  });
}

function severityBadge(sev) {
  const span = document.createElement("span");
  span.classList.add("badge");
  const s = (sev || "warning").toLowerCase();
  if (s === "critical") {
    span.classList.add("badge-critical");
  } else if (s === "info") {
    span.classList.add("badge-info");
  } else {
    span.classList.add("badge-warning");
  }
  span.textContent = sev || "warning";
  return span;
}

function renderEvents(detections) {
  const tbody = document.querySelector("#eventsTable tbody");
  const emptyState = document.getElementById("emptyState");
  tbody.innerHTML = "";

  if (!detections.length) {
    emptyState.style.display = "block";
    return;
  }

  emptyState.style.display = "none";

  detections.forEach((d) => {
    const tr = document.createElement("tr");

    const timeCell = document.createElement("td");
    timeCell.textContent = formatTime(d.time);

    const originCell = document.createElement("td");
    originCell.textContent = d.origin || "unknown";

    const categoryCell = document.createElement("td");
    categoryCell.textContent = d.category || "UNKNOWN";

    const ruleCell = document.createElement("td");
    ruleCell.textContent = d.ruleId || "-";

    const typeCell = document.createElement("td");
    typeCell.textContent = d.type || "-";

    const severityCell = document.createElement("td");
    severityCell.appendChild(severityBadge(d.severity));

    const detailsCell = document.createElement("td");
    const details = d.details || "";
    detailsCell.textContent = details.length > 120
      ? details.slice(0, 117) + "..."
      : details;
    detailsCell.classList.add("muted");

    tr.appendChild(timeCell);
    tr.appendChild(originCell);
    tr.appendChild(categoryCell);
    tr.appendChild(ruleCell);
    tr.appendChild(typeCell);
    tr.appendChild(severityCell);
    tr.appendChild(detailsCell);

    tbody.appendChild(tr);
  });
}

function refresh() {
  loadDetections((all) => {
    console.log("[POPUP] Refreshing view with", all.length, "events");
    buildOriginOptions(all);
    renderSummary(all);
    const filtered = applyFilters(all);
    renderEvents(filtered);
  });
}

function exportJson() {
  chrome.storage.local.get({ detections: [] }, (data) => {
    const detections = Array.isArray(data.detections) ? data.detections : [];
    const blob = new Blob([JSON.stringify(detections, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "web_intrusion_detector_report.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("refreshBtn").addEventListener("click", refresh);
  document.getElementById("exportBtn").addEventListener("click", exportJson);
  document
    .getElementById("originFilter")
    .addEventListener("change", refresh);
  document
    .getElementById("categoryFilter")
    .addEventListener("change", refresh);
  document.getElementById("limitSelect").addEventListener("change", refresh);

  refresh();
});

// Auto-refresh the popup whenever detections change in storage
if (
  typeof chrome !== "undefined" &&
  chrome.storage &&
  chrome.storage.onChanged
) {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.detections) {
      console.log("[POPUP] Detected storage change for detections; refreshing");
      refresh();
    }
  });
}
