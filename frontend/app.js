const API_URL = "http://localhost:3000/alerts";

let attackTypeChartInstance = null;
let timelineChartInstance = null;
let topIpChartInstance = null;
let severityChartInstance = null;

async function fetchAlerts() {
  const response = await fetch(API_URL);
  if (!response.ok) {
    throw new Error("Failed to fetch alerts");
  }
  return await response.json();
}

function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function updateKpis(alerts) {
  const totalAlerts = alerts.length;
  const highSeverityAlerts = alerts.filter((a) => a.severity === "high").length;
  const uniqueIps = new Set(alerts.map((a) => a.src_ip).filter(Boolean)).size;

  const latestAlert = alerts
    .map((a) => a.logged_at)
    .filter(Boolean)
    .sort()
    .at(-1);

  document.getElementById("totalAlerts").textContent = totalAlerts;
  document.getElementById("highSeverityAlerts").textContent =
    highSeverityAlerts;
  document.getElementById("uniqueIps").textContent = uniqueIps;
  document.getElementById("latestAlertTime").textContent = latestAlert
    ? formatDateTime(latestAlert)
    : "-";
}

function buildAttackTypeCounts(alerts) {
  const counts = {};
  for (const alert of alerts) {
    const type = alert.type || "UNKNOWN";
    counts[type] = (counts[type] || 0) + 1;
  }
  return counts;
}

function buildTimelineCounts(alerts) {
  const counts = {};

  for (const alert of alerts) {
    const ts = alert.logged_at || alert.timestamp;
    if (!ts) continue;

    const date = new Date(ts);
    if (Number.isNaN(date.getTime())) continue;

    const bucket = new Date(date);
    bucket.setSeconds(0, 0);

    const label = bucket.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

    counts[label] = (counts[label] || 0) + 1;
  }

  return counts;
}

function renderAttackTypeChart(alerts) {
  const counts = buildAttackTypeCounts(alerts);
  const labels = Object.keys(counts);
  const values = Object.values(counts);

  if (attackTypeChartInstance) {
    attackTypeChartInstance.destroy();
  }

  attackTypeChartInstance = new Chart(
    document.getElementById("attackTypeChart"),
    {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Alerts",
            data: values,
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            labels: {
              color: "#e5e7eb",
            },
          },
        },
        scales: {
          x: {
            ticks: { color: "#cbd5e1" },
            grid: { color: "#1f2937" },
          },
          y: {
            beginAtZero: true,
            ticks: { color: "#cbd5e1" },
            grid: { color: "#1f2937" },
          },
        },
      },
    },
  );
}

function renderTimelineChart(alerts) {
  const counts = buildTimelineCounts(alerts);
  const labels = Object.keys(counts);
  const values = Object.values(counts);

  if (timelineChartInstance) {
    timelineChartInstance.destroy();
  }

  timelineChartInstance = new Chart(document.getElementById("timelineChart"), {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Alerts over time",
          data: values,
          tension: 0.25,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: {
            color: "#e5e7eb",
          },
        },
      },
      scales: {
        x: {
          ticks: { color: "#cbd5e1" },
          grid: { color: "#1f2937" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#cbd5e1" },
          grid: { color: "#1f2937" },
        },
      },
    },
  });
}

function severityBadgeClass(severity) {
  if (severity === "high") return "badge badge-high";
  if (severity === "medium") return "badge badge-medium";
  return "badge badge-low";
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alertsTableBody");
  tbody.innerHTML = "";

  const sortedAlerts = [...alerts].sort((a, b) => {
    const aTime = new Date(a.logged_at || 0).getTime();
    const bTime = new Date(b.logged_at || 0).getTime();
    return bTime - aTime;
  });

  for (const alert of sortedAlerts.slice(0, 20)) {
    const row = document.createElement("tr");

    row.innerHTML = `
      <td>${formatDateTime(alert.logged_at)}</td>
      <td><span class="type-pill">${alert.type || "-"}</span></td>
      <td><span class="${severityBadgeClass(alert.severity)}">${alert.severity || "low"}</span></td>
      <td>${alert.src_ip || "-"}</td>
      <td>${alert.message || "-"}</td>
    `;

    tbody.appendChild(row);
  }
}

async function loadDashboard() {
  try {
    const alerts = await fetchAlerts();
    updateKpis(alerts);
    renderAttackTypeChart(alerts);
    renderTimelineChart(alerts);
    renderTopIpChart(alerts);
    renderSeverityChart(alerts);
    renderAlertsTable(alerts);
  } catch (error) {
    console.error(error);
    alert("Failed to load dashboard data");
  }
}

function buildTopIps(alerts) {
  const counts = {};

  alerts.forEach((a) => {
    if (!a.src_ip) return;
    counts[a.src_ip] = (counts[a.src_ip] || 0) + 1;
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    labels: sorted.map((i) => i[0]),
    values: sorted.map((i) => i[1]),
  };
}

function renderTopIpChart(alerts) {
  const { labels, values } = buildTopIps(alerts);

  if (topIpChartInstance) {
    topIpChartInstance.destroy();
  }

  topIpChartInstance = new Chart(document.getElementById("topIpChart"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "Top Attackers",
          data: values,
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: {
            color: "#e5e7eb",
          },
        },
      },
      scales: {
        x: {
          ticks: { color: "#cbd5e1" },
          grid: { color: "#1f2937" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#cbd5e1" },
          grid: { color: "#1f2937" },
        },
      },
    },
  });
}

function buildSeverity(alerts) {
  const counts = { high: 0, medium: 0, low: 0 };

  alerts.forEach((a) => {
    if (counts[a.severity] !== undefined) {
      counts[a.severity]++;
    }
  });

  return counts;
}

function renderSeverityChart(alerts) {
  const counts = buildSeverity(alerts);

  if (severityChartInstance) {
    severityChartInstance.destroy();
  }

  severityChartInstance = new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
      labels: ["High", "Medium", "Low"],
      datasets: [
        {
          data: [counts.high, counts.medium, counts.low],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: {
            color: "#e5e7eb",
          },
        },
      },
    },
  });
}

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);

loadDashboard();
setInterval(loadDashboard, 5000);
