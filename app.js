const paths = {
  alert: "data/alerts/alert-005-oauth-consent-cloud-exfiltration.json",
  email: "data/logs/email-security-logs.json",
  clicks: "data/logs/url-click-events.json",
  signins: "data/logs/entra-signin-logs.json",
  audit: "data/logs/entra-audit-logs.json",
  oauth: "data/logs/oauth-consent-logs.json",
  graph: "data/logs/graph-api-activity.json",
  sharepoint: "data/logs/sharepoint-file-activity.json",
  dlp: "data/logs/dlp-alerts.json",
  proxy: "data/logs/proxy-events.json",
  users: "data/entities/users.json",
  apps: "data/entities/apps.json",
  files: "data/entities/files.json",
  ipIntel: "data/entities/ip-intel.json",
  expected: "data/answers/expected-findings.json"
};

let lab = {
  alert: null,
  logs: [],
  users: [],
  apps: [],
  files: [],
  ipIntel: [],
  expected: null
};

function byId(id) {
  return document.getElementById(id);
}

async function loadJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Could not load ${path}`);
  }
  return response.json();
}

async function loadLab() {
  const [
    alert,
    email,
    clicks,
    signins,
    audit,
    oauth,
    graph,
    sharepoint,
    dlp,
    proxy,
    users,
    apps,
    files,
    ipIntel,
    expected
  ] = await Promise.all([
    loadJson(paths.alert),
    loadJson(paths.email),
    loadJson(paths.clicks),
    loadJson(paths.signins),
    loadJson(paths.audit),
    loadJson(paths.oauth),
    loadJson(paths.graph),
    loadJson(paths.sharepoint),
    loadJson(paths.dlp),
    loadJson(paths.proxy),
    loadJson(paths.users),
    loadJson(paths.apps),
    loadJson(paths.files),
    loadJson(paths.ipIntel),
    loadJson(paths.expected)
  ]);

  lab = {
    alert,
    logs: [
      ...email.events,
      ...clicks.events,
      ...signins.events,
      ...audit.events,
      ...oauth.events,
      ...graph.events,
      ...sharepoint.events,
      ...dlp.events,
      ...proxy.events
    ].sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
    users: users.users,
    apps: apps.apps,
    files: files.files,
    ipIntel: ipIntel.indicators,
    expected
  };
}

function renderAlertQueue() {
  const alert = lab.alert;
  byId("alertQueue").innerHTML = `
    <button class="queue-item active" type="button">
      <strong>${alert.alert_id}</strong>
      <span>${alert.title}</span>
      <span>${alert.created_at}</span>
      <span>Initial severity: ${alert.initial_severity.toUpperCase()}</span>
    </button>
  `;
}

function renderCaseHeader() {
  const alert = lab.alert;
  byId("caseHeader").innerHTML = `
    <h2>${alert.title}</h2>
    <p>${alert.summary}</p>
    <div class="case-meta">
      <span class="tag critical">Initial ${alert.initial_severity}</span>
      <span class="tag">${alert.environment}</span>
      <span class="tag">${alert.alert_source}</span>
      <span class="tag">${alert.status}</span>
    </div>
  `;

  byId("affectedUser").textContent = lab.expected.affected_user;
  byId("suspiciousApp").textContent = lab.expected.suspicious_app;
  byId("dataScope").textContent = `${lab.expected.files_accessed.length} sensitive files`;
  byId("mitreSummary").textContent = lab.expected.mitre_techniques.join(", ");
}

function formatTimestamp(value) {
  return value.replace("T", " ").replace("Z", " UTC");
}

function eventActor(event) {
  return event.user || event.actor_user || event.app_name || event.client_app || "-";
}

function eventIp(event) {
  return event.src_ip || event.ip_address || event.destination_ip || "-";
}

function summarizeEvent(event) {
  if (event.event_type === "inbound_email") {
    return `${event.recipient} received "${event.subject}" from ${event.sender}; message auth was ${event.authentication_result}`;
  }
  if (event.event_type === "url_clicked") {
    return `${event.user} clicked ${event.url} from ${event.device_name}`;
  }
  if (event.event_type === "interactive_signin") {
    return `${event.user} signed in to ${event.resource} from ${event.src_ip}; MFA ${event.mfa_result}`;
  }
  if (event.event_type === "consent_grant") {
    return `${event.user} granted ${event.scopes.join(", ")} to ${event.app_name}`;
  }
  if (event.event_type === "app_role_assignment") {
    return `${event.actor_user} assigned ${event.permission} to ${event.app_name}`;
  }
  if (event.event_type === "service_principal_credential_added") {
    return `${event.app_name} received a new ${event.credential_type} credential from ${event.src_ip}`;
  }
  if (event.event_type === "graph_api_call") {
    return `${event.app_name} called ${event.api_operation} against ${event.target_resource}`;
  }
  if (event.event_type === "file_accessed" || event.event_type === "file_downloaded") {
    return `${event.app_name || event.user} ${event.action} ${event.file_name} from ${event.site_name}`;
  }
  if (event.event_type === "sharing_link_created") {
    return `${event.app_name} created ${event.link_scope} sharing link for ${event.file_name}`;
  }
  if (event.event_type === "dlp_alert") {
    return `${event.policy_name}: ${event.matched_sensitive_info.join(", ")} in ${event.file_name}`;
  }
  if (event.event_type === "proxy_upload") {
    return `${event.user || event.app_name} uploaded ${event.bytes_out} bytes to ${event.domain}`;
  }
  return event.description || event.event_type;
}

function renderTimeline() {
  const keyEvents = lab.logs.filter((event) => event.timeline === true);
  byId("timeline").innerHTML = keyEvents.map((event) => `
    <article class="timeline-item">
      <time>${formatTimestamp(event.timestamp)}</time>
      <div>
        <strong>${event.event_type.replaceAll("_", " ")}</strong>
        <p>${summarizeEvent(event)}</p>
      </div>
    </article>
  `).join("");
}

function renderOAuthEvidence() {
  const consent = lab.logs.find((event) => event.event_type === "consent_grant");
  const assignment = lab.logs.find((event) => event.event_type === "app_role_assignment");
  const credential = lab.logs.find((event) => event.event_type === "service_principal_credential_added");
  const app = lab.apps.find((item) => item.app_name === lab.expected.suspicious_app);

  byId("oauthEvidence").innerHTML = `
    <article class="entity-card">
      <h3>Consent Grant</h3>
      <dl>
        <dt>User</dt><dd>${consent.user}</dd>
        <dt>App</dt><dd>${consent.app_name}</dd>
        <dt>Publisher</dt><dd>${consent.publisher}</dd>
        <dt>Scopes</dt><dd>${consent.scopes.join(", ")}</dd>
      </dl>
    </article>
    <article class="entity-card">
      <h3>App Risk</h3>
      <dl>
        <dt>Verified</dt><dd>${app.verified_publisher ? "Yes" : "No"}</dd>
        <dt>Created</dt><dd>${app.created_at}</dd>
        <dt>Redirect URI</dt><dd>${app.redirect_uri}</dd>
        <dt>Risk Note</dt><dd>${app.risk_note}</dd>
      </dl>
    </article>
    <article class="entity-card">
      <h3>App Role Assignment</h3>
      <dl>
        <dt>Permission</dt><dd>${assignment.permission}</dd>
        <dt>Resource</dt><dd>${assignment.resource}</dd>
        <dt>Actor</dt><dd>${assignment.actor_user}</dd>
        <dt>Result</dt><dd>${assignment.result}</dd>
      </dl>
    </article>
    <article class="entity-card">
      <h3>Persistence Signal</h3>
      <dl>
        <dt>Change</dt><dd>${credential.event_type.replaceAll("_", " ")}</dd>
        <dt>Credential</dt><dd>${credential.credential_type}</dd>
        <dt>Source IP</dt><dd>${credential.src_ip}</dd>
        <dt>Result</dt><dd>${credential.result}</dd>
      </dl>
    </article>
  `;
}

function renderCloudEvidence() {
  byId("cloudEvidence").innerHTML = lab.files.map((file) => `
    <article class="entity-card">
      <h3>${file.file_name}</h3>
      <dl>
        <dt>Location</dt><dd>${file.location}</dd>
        <dt>Owner</dt><dd>${file.owner}</dd>
        <dt>Sensitivity</dt><dd>${file.sensitivity}</dd>
        <dt>Data Types</dt><dd>${file.data_types.join(", ")}</dd>
        <dt>Lab Signal</dt><dd>${file.lab_signal}</dd>
      </dl>
    </article>
  `).join("");
}

function renderLogs(filter = "all") {
  const filtered = lab.logs.filter((event) => filter === "all" || event.category === filter);
  byId("logTable").innerHTML = filtered.map((event) => `
    <tr>
      <td>${formatTimestamp(event.timestamp).replace(" UTC", "")}</td>
      <td>${event.source}</td>
      <td>${eventActor(event)}</td>
      <td>${eventIp(event)}</td>
      <td>${event.event_type.replaceAll("_", " ")}</td>
      <td><code>${summarizeEvent(event)}</code></td>
    </tr>
  `).join("");
}

function renderEntities() {
  const users = lab.users.map((user) => `
    <article class="entity-card">
      <h3>${user.username}</h3>
      <dl>
        <dt>Display</dt><dd>${user.display_name}</dd>
        <dt>Role</dt><dd>${user.role}</dd>
        <dt>Department</dt><dd>${user.department}</dd>
        <dt>Risk Note</dt><dd>${user.risk_note}</dd>
      </dl>
    </article>
  `).join("");

  const apps = lab.apps.map((app) => `
    <article class="entity-card">
      <h3>${app.app_name}</h3>
      <dl>
        <dt>App ID</dt><dd>${app.app_id}</dd>
        <dt>Publisher</dt><dd>${app.publisher}</dd>
        <dt>Verified</dt><dd>${app.verified_publisher ? "Yes" : "No"}</dd>
        <dt>Risk Note</dt><dd>${app.risk_note}</dd>
      </dl>
    </article>
  `).join("");

  const ips = lab.ipIntel.map((ip) => `
    <article class="entity-card">
      <h3>${ip.indicator}</h3>
      <dl>
        <dt>Type</dt><dd>${ip.type}</dd>
        <dt>Reputation</dt><dd>${ip.reputation}</dd>
        <dt>Country</dt><dd>${ip.country}</dd>
        <dt>Note</dt><dd>${ip.note}</dd>
      </dl>
    </article>
  `).join("");

  byId("entities").innerHTML = users + apps + ips;
}

function renderDetections() {
  const expected = lab.expected;
  byId("detectionDetails").innerHTML = `
    <article class="detection-card">
      <h3>Detection Summary</h3>
      <dl>
        <dt>Logic</dt><dd>${lab.alert.detection_logic}</dd>
        <dt>Threshold</dt><dd>${lab.alert.threshold}</dd>
        <dt>Time Window</dt><dd>${lab.alert.time_window}</dd>
        <dt>False Positives</dt><dd>${lab.alert.false_positive_notes.join("; ")}</dd>
      </dl>
    </article>
    <article class="detection-card">
      <h3>Expected Mapping</h3>
      <dl>
        <dt>Verdict</dt><dd>${expected.verdict.replaceAll("_", " ")}</dd>
        <dt>Severity</dt><dd>${expected.severity}</dd>
        <dt>Primary Technique</dt><dd>${expected.primary_mitre}</dd>
        <dt>Related Techniques</dt><dd>${expected.mitre_techniques.filter((id) => id !== expected.primary_mitre).join(", ")}</dd>
      </dl>
    </article>
  `;
}

function setupTabs() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
      button.classList.add("active");
      byId(`${button.dataset.tab}Panel`).classList.add("active");
    });
  });
}

function setupFilters() {
  document.querySelectorAll(".filter").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".filter").forEach((filter) => filter.classList.remove("active"));
      button.classList.add("active");
      renderLogs(button.dataset.filter);
    });
  });
}

function normalize(value) {
  return value.trim().toLowerCase();
}

function addFeedback(message, pass) {
  const item = document.createElement("div");
  item.className = `feedback-item ${pass ? "pass" : "fail"}`;
  item.textContent = message;
  byId("feedback").appendChild(item);
}

function setupForm() {
  byId("triageForm").addEventListener("submit", (event) => {
    event.preventDefault();
    byId("feedback").innerHTML = "";

    const expected = lab.expected;
    const checks = [
      {
        pass: byId("verdict").value === expected.verdict,
        passText: "Verdict is correct.",
        failText: "Verdict needs another look. OAuth consent followed by token-based file access and DLP alerts should be treated as a confirmed incident."
      },
      {
        pass: byId("severity").value === expected.severity,
        passText: "Severity matches the expected triage.",
        failText: "Severity is not quite right. Sensitive file access, external sharing, and app persistence make this critical in the lab."
      },
      {
        pass: normalize(byId("answerUser").value) === expected.affected_user.toLowerCase(),
        passText: "Affected user is correct.",
        failText: `Affected user should be ${expected.affected_user}.`
      },
      {
        pass: normalize(byId("answerApp").value) === expected.suspicious_app.toLowerCase(),
        passText: "Suspicious OAuth app is correct.",
        failText: `Suspicious OAuth app should be ${expected.suspicious_app}.`
      },
      {
        pass: expected.high_risk_scopes.map((scope) => scope.toLowerCase()).includes(normalize(byId("answerScope").value)),
        passText: "High-risk scope is correct.",
        failText: `Use one of the high-risk scopes: ${expected.high_risk_scopes.join(", ")}.`
      },
      {
        pass: normalize(byId("answerDestination").value) === expected.exfil_destination.toLowerCase(),
        passText: "Exfil destination is correct.",
        failText: `Exfil destination should be ${expected.exfil_destination}.`
      },
      {
        pass: byId("mitreTechnique").value === expected.primary_mitre,
        passText: "Primary MITRE technique is correct.",
        failText: `Primary MITRE technique should be ${expected.primary_mitre}.`
      },
      {
        pass: byId("notes").value.trim().length >= 140,
        passText: "Evidence notes are detailed enough for a first escalation report.",
        failText: "Add more evidence notes. Mention consent grant, high-risk scopes, Graph API activity, sensitive file access, DLP alert, external sharing, and service principal credential change."
      }
    ];

    checks.forEach((check) => addFeedback(check.pass ? check.passText : check.failText, check.pass));
  });
}

function renderAll() {
  renderAlertQueue();
  renderCaseHeader();
  renderTimeline();
  renderOAuthEvidence();
  renderCloudEvidence();
  renderLogs();
  renderEntities();
  renderDetections();
}

async function init() {
  try {
    await loadLab();
    renderAll();
    setupTabs();
    setupFilters();
    setupForm();
  } catch (error) {
    document.body.innerHTML = `
      <main class="load-error">
        <h1>Lab data could not be loaded</h1>
        <p>${error.message}</p>
        <p>Run a local server from this folder with <code>python -m http.server 8000</code>, then open <code>http://localhost:8000</code>.</p>
      </main>
    `;
  }
}

init();
