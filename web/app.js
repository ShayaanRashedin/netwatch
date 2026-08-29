"use strict";

const elements = {
  liveDot: document.querySelector("#live-dot"),
  connectionStatus: document.querySelector("#connection-status"),
  lastUpdated: document.querySelector("#last-updated"),
  errorBanner: document.querySelector("#error-banner"),
  eventCount: document.querySelector("#event-count"),
  alertCount: document.querySelector("#alert-count"),
  criticalCount: document.querySelector("#critical-count"),
  highCount: document.querySelector("#high-count"),
  processCount: document.querySelector("#process-count"),
  latestEvent: document.querySelector("#latest-event"),
  latestAlert: document.querySelector("#latest-alert"),
  severityLow: document.querySelector("#severity-low"),
  severityMedium: document.querySelector("#severity-medium"),
  severityHigh: document.querySelector("#severity-high"),
  severityCritical: document.querySelector("#severity-critical"),
  ruleBars: document.querySelector("#rule-bars"),
  alertFeed: document.querySelector("#alert-feed"),
  eventRows: document.querySelector("#event-rows"),
  riskFilter: document.querySelector("#risk-filter"),
  alertFilterLabel: document.querySelector("#alert-filter-label"),
  refreshButton: document.querySelector("#refresh-button"),
  pauseButton: document.querySelector("#pause-button")
};

const state = {
  paused: false,
  refreshing: false,
  refreshInterval: 3000,
  timer: null
};

const numberFormatter = new Intl.NumberFormat();

function formatCount(value) {
  return numberFormatter.format(Number(value || 0));
}

function formatTime(value) {
  if (!value) return "No data yet";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function endpointText(endpoint, family) {
  if (!endpoint) return "unknown";
  const address = family === "IPv6" ? `[${endpoint.address}]` : endpoint.address;
  return `${address}:${endpoint.port}`;
}

function setConnection(online, message) {
  elements.liveDot.classList.toggle("online", online);
  elements.liveDot.classList.toggle("offline", !online);
  elements.connectionStatus.textContent = message;
}

function showError(message) {
  elements.errorBanner.textContent = message;
  elements.errorBanner.hidden = false;
}

function clearError() {
  elements.errorBanner.hidden = true;
  elements.errorBanner.textContent = "";
}

async function fetchJson(path) {
  const response = await fetch(path, {
    headers: { "Accept": "application/json" },
    cache: "no-store"
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with status ${response.status}`);
  }
  return payload;
}

function renderSummary(summary) {
  const severity = summary.alerts_by_severity || {};

  elements.eventCount.textContent = formatCount(summary.event_count);
  elements.alertCount.textContent = formatCount(summary.alert_count);
  elements.processCount.textContent = formatCount(summary.process_owner_count);
  elements.criticalCount.textContent = formatCount(severity.CRITICAL);
  elements.highCount.textContent = formatCount(severity.HIGH);
  elements.latestEvent.textContent = summary.latest_event_at
    ? `Latest ${formatTime(summary.latest_event_at)}`
    : "No event data yet";
  elements.latestAlert.textContent = summary.latest_alert_at
    ? `Latest ${formatTime(summary.latest_alert_at)}`
    : "No alert data yet";

  elements.severityLow.textContent = formatCount(severity.LOW);
  elements.severityMedium.textContent = formatCount(severity.MEDIUM);
  elements.severityHigh.textContent = formatCount(severity.HIGH);
  elements.severityCritical.textContent = formatCount(severity.CRITICAL);

  const rules = Array.isArray(summary.alerts_by_rule)
    ? summary.alerts_by_rule
    : [];
  elements.ruleBars.replaceChildren();

  if (!rules.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No alert rules have fired yet.";
    elements.ruleBars.append(empty);
    return;
  }

  const maximum = Math.max(...rules.map((rule) => Number(rule.count || 0)), 1);

  for (const rule of rules) {
    const row = document.createElement("div");
    row.className = "rule-row";

    const copy = document.createElement("div");
    copy.className = "rule-copy";
    const name = document.createElement("span");
    name.textContent = rule.rule_id;
    const count = document.createElement("span");
    count.textContent = formatCount(rule.count);
    copy.append(name, count);

    const track = document.createElement("div");
    track.className = "rule-track";
    const fill = document.createElement("div");
    fill.className = "rule-fill";
    fill.style.width = `${Math.max(3, (Number(rule.count) / maximum) * 100)}%`;
    track.append(fill);
    row.append(copy, track);
    elements.ruleBars.append(row);
  }
}

function renderAlerts(payload) {
  const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
  elements.alertFeed.replaceChildren();

  if (!alerts.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No alerts match the selected risk threshold.";
    elements.alertFeed.append(empty);
    return;
  }

  for (const alert of alerts) {
    const article = document.createElement("article");
    article.className = "alert-item";

    const topline = document.createElement("div");
    topline.className = "alert-topline";

    const severity = document.createElement("span");
    severity.className = `severity-badge ${alert.severity}`;
    severity.textContent = alert.severity;

    const score = document.createElement("span");
    score.className = "risk-score";
    score.textContent = `RISK ${alert.risk_score}`;

    const time = document.createElement("time");
    time.className = "alert-time";
    time.dateTime = alert.detected_at;
    time.textContent = formatTime(alert.detected_at);
    topline.append(severity, score, time);

    const title = document.createElement("h3");
    title.textContent = alert.title;

    const reason = document.createElement("p");
    reason.textContent = alert.reason;

    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = `Evidence · ${alert.rule_id}`;
    const evidenceList = document.createElement("ul");
    evidenceList.className = "evidence-list";

    for (const item of alert.evidence || []) {
      const entry = document.createElement("li");
      entry.textContent = item;
      evidenceList.append(entry);
    }

    const source = alert.source_event || {};
    const sourceEntry = document.createElement("li");
    sourceEntry.textContent = `source=${source.type || "UNKNOWN"} ${source.protocol || ""} ${endpointText(source.local, source.family)} → ${endpointText(source.remote, source.family)}`;
    evidenceList.append(sourceEntry);

    details.append(summary, evidenceList);
    article.append(topline, title, reason, details);
    elements.alertFeed.append(article);
  }
}

function renderEvents(payload) {
  const events = Array.isArray(payload.events) ? payload.events : [];
  elements.eventRows.replaceChildren();

  if (!events.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "empty-state";
    cell.textContent = "No persisted socket events yet.";
    row.append(cell);
    elements.eventRows.append(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const owner = Array.isArray(event.owners) && event.owners.length
      ? event.owners[0]
      : null;
    const values = [
      formatTime(event.observed_at),
      event.type,
      `${event.protocol} · ${event.family}`,
      endpointText(event.local, event.family),
      endpointText(event.remote, event.family),
      event.state,
      owner ? `${owner.name || "unknown"} · ${owner.pid}` : "owner unknown"
    ];

    values.forEach((value, index) => {
      const cell = document.createElement("td");
      if (index === 1) {
        const badge = document.createElement("span");
        badge.className = `event-badge ${event.type}`;
        badge.textContent = value;
        cell.append(badge);
      } else {
        cell.textContent = value;
        if (index === 6 && owner) cell.className = "owner-name";
      }
      row.append(cell);
    });

    elements.eventRows.append(row);
  }
}

async function refresh() {
  if (state.refreshing || state.paused) return;
  state.refreshing = true;
  elements.refreshButton.disabled = true;

  const minimumScore = Number(elements.riskFilter.value);
  elements.alertFilterLabel.textContent = `SCORE ≥ ${minimumScore}`;

  try {
    const [health, summary, alerts, events] = await Promise.all([
      fetchJson("/api/health"),
      fetchJson("/api/summary"),
      fetchJson(`/api/alerts?limit=20&min_score=${minimumScore}`),
      fetchJson("/api/events?limit=50")
    ]);

    renderSummary(summary);
    renderAlerts(alerts);
    renderEvents(events);
    clearError();
    setConnection(health.status === "ok", "Live telemetry");
    elements.lastUpdated.textContent = `Updated ${formatTime(summary.generated_at)}`;
  } catch (error) {
    setConnection(false, "API unavailable");
    showError(error instanceof Error ? error.message : "Unable to refresh telemetry");
  } finally {
    state.refreshing = false;
    elements.refreshButton.disabled = false;
  }
}

function scheduleRefresh() {
  window.clearInterval(state.timer);
  state.timer = window.setInterval(refresh, state.refreshInterval);
}

elements.refreshButton.addEventListener("click", () => {
  const wasPaused = state.paused;
  state.paused = false;
  refresh().finally(() => {
    state.paused = wasPaused;
  });
});

elements.pauseButton.addEventListener("click", () => {
  state.paused = !state.paused;
  elements.pauseButton.setAttribute("aria-pressed", String(state.paused));
  elements.pauseButton.textContent = state.paused ? "Resume live" : "Pause live";
  setConnection(!state.paused, state.paused ? "Live refresh paused" : "Live telemetry");
  if (!state.paused) refresh();
});

elements.riskFilter.addEventListener("change", refresh);

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !state.paused) refresh();
});

refresh();
scheduleRefresh();

