const CONFIG_KEYS = [
  "public_storage_access",
  "encryption_enabled",
  "logging_enabled",
  "unrestricted_ssh",
  "excessive_iam_admin",
];

const SAFE_DEFAULTS = {
  public_storage_access: false,
  encryption_enabled: true,
  logging_enabled: true,
  unrestricted_ssh: false,
  excessive_iam_admin: false,
};

const CHECK_LABELS = {
  public_storage_access: "public storage access",
  encryption_enabled: "storage encryption",
  logging_enabled: "audit logging",
  unrestricted_ssh: "unrestricted SSH access",
  excessive_iam_admin: "excessive IAM admin privileges",
};

const CHECK_NAMES = {
  public_storage_access: "Public Storage Access",
  encryption_enabled: "Storage Encryption",
  logging_enabled: "Audit Logging",
  unrestricted_ssh: "Unrestricted SSH Access",
  excessive_iam_admin: "Excessive IAM Admin Privileges",
};

const WHY_IT_MATTERS = {
  public_storage_access: "Public storage can expose private files to anyone.",
  encryption_enabled: "Encryption helps protect stored information if accessed.",
  logging_enabled: "Audit logs help explain who changed a resource and when.",
  unrestricted_ssh: "Open SSH access gives untrusted sources a path to connect.",
  excessive_iam_admin: "Overly broad permissions increase the impact of mistakes.",
};

const RISKY_VALUES = {
  public_storage_access: true,
  encryption_enabled: false,
  logging_enabled: false,
  unrestricted_ssh: true,
  excessive_iam_admin: true,
};

const form = document.querySelector("#config-editor");
const validationBadge = document.querySelector("#validation-badge");
const errorAlert = document.querySelector("#error-alert");
const scanButton = document.querySelector("#scan-button");
const scanSequence = document.querySelector("#scan-sequence");
const resultsDashboard = document.querySelector("#results-dashboard");
const resultsSkeleton = document.querySelector("#results-skeleton");
const resultsContent = document.querySelector("#results-content");
const terminalLog = document.querySelector("#terminal-log");
const toast = document.querySelector("#toast");
let latestResults = [];
let knownConfig = {};
let toastTimer;
let statusSortAscending = true;

function validateEditor(showAlert = false) {
  let parsedConfig;
  try {
    parsedConfig = JSON.parse(form.value);
  } catch {
    setValidation("Invalid JSON syntax", "is-invalid");
    clearMissingNotice();
    if (showAlert) showError("This JSON is not valid yet. Check the commas, quotes, and braces.");
    return null;
  }

  const source =
    parsedConfig !== null && typeof parsedConfig === "object" && !Array.isArray(parsedConfig)
      ? parsedConfig
      : {};
  const missing = CONFIG_KEYS.filter((key) => typeof source[key] !== "boolean");
  knownConfig = Object.fromEntries(
    CONFIG_KEYS.filter((key) => typeof source[key] === "boolean").map((key) => [key, source[key]]),
  );

  if (missing.length) {
    setValidation(`${missing.length} check${missing.length === 1 ? "" : "s"} not checked`, "is-incomplete");
    showMissingNotice(missing);
  } else {
    setValidation("Configuration valid", "is-valid");
    clearMissingNotice();
  }
  clearError();
  syncSwitches(knownConfig);
  return knownConfig;
}

function setValidation(text, stateClass) {
  validationBadge.textContent = text;
  form.setAttribute("aria-invalid", stateClass === "is-invalid" ? "true" : "false");
  validationBadge.classList.remove("is-valid", "is-incomplete", "is-invalid");
  validationBadge.classList.add(stateClass);
}

function showMissingNotice(missingKeys) {
  const names = missingKeys.map((key) => CHECK_LABELS[key]).join(", ");
  const notice = document.querySelector("#missing-notice");
  notice.textContent = `${names} ${missingKeys.length === 1 ? "will be" : "will each be"} marked NOT CHECKED.`;
  notice.hidden = false;
}

function clearMissingNotice() {
  const notice = document.querySelector("#missing-notice");
  notice.textContent = "";
  notice.hidden = true;
}

function syncSwitches(config) {
  for (const key of CONFIG_KEYS) {
    const card = document.querySelector(`[data-setting="${key}"]`);
    const toggle = card.querySelector("[data-toggle]");
    const chip = card.querySelector("[data-state]");
    const hasValue = typeof config[key] === "boolean";
    toggle.indeterminate = !hasValue;
    toggle.checked = hasValue && config[key];
    const unsafe = hasValue && config[key] === RISKY_VALUES[key];
    chip.textContent = hasValue ? (unsafe ? "UNSAFE" : "SAFE") : "NOT CHECKED";
    chip.classList.toggle("is-unsafe", unsafe);
    chip.classList.toggle("is-unknown", !hasValue);
  }
}

function syncLineNumbers() {
  const lineCount = form.value.split("\n").length;
  document.querySelector("#line-numbers").textContent = Array.from(
    { length: lineCount },
    (_, index) => index + 1,
  ).join("\n");
}

function setEditor(config) {
  form.value = JSON.stringify(config, null, 2);
  syncLineNumbers();
  validateEditor();
}

function showError(message) {
  errorAlert.textContent = message;
  errorAlert.classList.add("is-visible");
  errorAlert.classList.remove("is-shaking");
  requestAnimationFrame(() => errorAlert.classList.add("is-shaking"));
}

function clearError() {
  errorAlert.textContent = "";
  errorAlert.classList.remove("is-visible", "is-shaking");
}

function setPreset(preset) {
  const unsafe = {
    public_storage_access: true,
    encryption_enabled: false,
    logging_enabled: false,
    unrestricted_ssh: true,
    excessive_iam_admin: true,
  };

  if (preset === "secure" || preset === "unsafe") {
    setEditor(preset === "secure" ? SAFE_DEFAULTS : unsafe);
    showToast(`${preset === "secure" ? "All secure" : "All unsafe"} preset loaded.`);
  } else if (preset === "missing") {
    const missing = { ...SAFE_DEFAULTS };
    delete missing.logging_enabled;
    setEditor(missing);
  } else if (preset === "invalid") {
    form.value = '{"public_storage_access": true,';
    syncLineNumbers();
    validateEditor();
    showError("This preset contains invalid JSON. Fix the syntax before running the scan.");
  }
}

function isRisky(key, value) {
  return value === RISKY_VALUES[key];
}

function getStatusForKey(key, config) {
  if (typeof config[key] !== "boolean") return "NOT CHECKED";
  return isRisky(key, config[key]) ? "RISK DETECTED" : "SECURE";
}

function updateAttackSurface(results) {
  for (const result of results) {
    const key = CONFIG_KEYS.find((candidate) => result.check_name === CHECK_NAMES[candidate]);
    const node = document.querySelector(`[data-node="${key}"]`);
    if (!node) continue;
    node.classList.remove("is-risk", "is-secure", "is-unchecked");
    node.classList.add(
      result.status === "RISK DETECTED"
        ? "is-risk"
        : result.status === "SECURE"
          ? "is-secure"
          : "is-unchecked",
    );
  }
}

function animateCounter(element, endValue, duration = 850) {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    element.textContent = endValue;
    return;
  }

  const startTime = performance.now();
  function update(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - (1 - progress) ** 3;
    element.textContent = Math.round(endValue * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function setScoreGauge(score) {
  const scoreRing = document.querySelector("#score-ring");
  const radius = 75;
  const circumference = 2 * Math.PI * radius;
  scoreRing.setAttribute("stroke-dasharray", `${(score / 100) * circumference} ${circumference}`);
  const state = score < 50 ? "low" : score < 75 ? "medium" : "high";
  scoreRing.setAttribute("data-score-state", state);
  animateCounter(document.querySelector("#score-value"), score, 1100);
}

function buildCheckCard(result, index) {
  const card = document.createElement("article");
  const isSecure = result.status === "SECURE";
  const isRisk = result.status === "RISK DETECTED";
  card.className = `glass-card check-card${isSecure ? " is-secure" : ""}`;
  card.dataset.index = index;

  const top = document.createElement("div");
  top.className = "check-card-top";
  const icon = document.createElement("span");
  icon.className = `check-icon ${isRisk ? "icon-risk" : isSecure ? "icon-secure" : "icon-unchecked"}`;
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = isRisk ? "!" : isSecure ? "✓" : "—";
  const title = document.createElement("h4");
  title.className = "check-title";
  title.textContent = result.check_name;
  top.append(icon, title);

  const chips = document.createElement("div");
  chips.className = "check-chips";
  const status = document.createElement("span");
  status.className = `status-chip ${isRisk ? "status-risk" : isSecure ? "status-secure" : "status-unchecked"}`;
  status.textContent = result.status;
  const risk = document.createElement("span");
  risk.className = `risk-chip ${
    result.status === "NOT CHECKED"
      ? "risk-unchecked"
      : result.risk_level === "HIGH"
        ? "risk-high"
        : "risk-medium"
  }`;
  risk.textContent =
    result.status === "NOT CHECKED"
      ? "NOT CHECKED"
      : isRisk
        ? `${result.risk_level} RISK`
        : `${result.risk_level} CHECK`;
  chips.append(status, risk);

  const why = document.createElement("p");
  why.className = "why-line";
  why.textContent = isSecure
    ? "This setting follows the safer configuration in this demo."
    : isRisk
      ? WHY_IT_MATTERS[CONFIG_KEYS[index]]
      : "No boolean value was provided for this check.";
  const recommendation = document.createElement("p");
  recommendation.className = "recommendation";
  recommendation.textContent = isSecure ? "No action needed." : result.recommendation;

  card.append(top, chips, why, recommendation);
  return card;
}

function statusRank(status) {
  return status === "RISK DETECTED" ? 0 : status === "NOT CHECKED" ? 1 : 2;
}

function renderTable(results) {
  const sortedResults = [...results].sort((first, second) => {
    const difference = statusRank(first.status) - statusRank(second.status);
    return statusSortAscending ? difference : -difference;
  });
  const body = document.querySelector("#results-body");
  body.replaceChildren();

  for (const result of sortedResults) {
    const row = document.createElement("tr");
    const name = document.createElement("th");
    name.scope = "row";
    name.textContent = result.check_name;
    const status = document.createElement("td");
    status.textContent = result.status;
    status.className = `table-status ${result.status === "RISK DETECTED" ? "status-risk" : result.status === "SECURE" ? "status-secure" : "status-unchecked"}`;
    const risk = document.createElement("td");
    risk.textContent = result.risk_level;
    const recommendation = document.createElement("td");
    recommendation.textContent = result.status === "SECURE" ? "No action needed." : result.recommendation;
    row.append(name, status, risk, recommendation);
    body.append(row);
  }
}

function renderFixList(results) {
  const list = document.querySelector("#fix-list");
  list.replaceChildren();
  const risks = results
    .filter((result) => result.status === "RISK DETECTED")
    .sort((first, second) => {
      if (first.risk_level === second.risk_level) return 0;
      return first.risk_level === "HIGH" ? -1 : 1;
    });

  if (!risks.length) {
    const item = document.createElement("li");
    item.className = "fix-empty";
    item.textContent = "No detected risks. All checked settings look secure in this demo.";
    list.append(item);
    return;
  }

  for (const result of risks) {
    const item = document.createElement("li");
    item.className = "fix-item";
    const level = document.createElement("span");
    level.className = `fix-level ${result.risk_level === "HIGH" ? "risk-high" : "risk-medium"}`;
    level.textContent = result.risk_level;
    const name = document.createElement("strong");
    name.textContent = result.check_name;
    const recommendation = document.createElement("span");
    recommendation.textContent = result.recommendation;
    item.append(level, name, recommendation);
    list.append(item);
  }
}

function renderResults(data) {
  const riskCount = data.risks;
  const secureCount = data.secure;
  const uncheckedCount = data.not_checked;
  document.querySelector("#check-cards").replaceChildren(
    ...data.results.map(buildCheckCard),
  );
  document.querySelector("#checks-complete").textContent =
    `${data.results.length - uncheckedCount} / ${data.results.length} checked`;

  animateCounter(document.querySelector("#risk-count"), riskCount, 750);
  animateCounter(document.querySelector("#secure-count"), secureCount, 750);
  animateCounter(document.querySelector("#unchecked-count"), uncheckedCount, 750);
  setScoreGauge(data.score);
  updateAttackSurface(data.results);
  renderFixList(data.results);
  renderTable(data.results);

  const high = data.results.filter(
    (result) => result.status === "RISK DETECTED" && result.risk_level === "HIGH",
  ).length;
  const medium = data.results.filter(
    (result) => result.status === "RISK DETECTED" && result.risk_level === "MEDIUM",
  ).length;
  document.querySelector("#high-count").textContent = high;
  document.querySelector("#medium-count").textContent = medium;
  document.querySelector("#severity-bar").replaceChildren();
  for (const result of data.results) {
    const segment = document.createElement("span");
    segment.className = `severity-segment ${
      result.status === "RISK DETECTED"
        ? result.risk_level === "HIGH"
          ? "severity-high"
          : "severity-medium"
        : result.status === "SECURE"
          ? "severity-secure"
          : "severity-unchecked"
    }`;
    segment.setAttribute("aria-hidden", "true");
    document.querySelector("#severity-bar").append(segment);
  }
  document.querySelector("#severity-bar").setAttribute(
    "aria-label",
    `${high} high risks, ${medium} medium risks, ${secureCount} secure checks, ${uncheckedCount} not checked`,
  );

  resultsSkeleton.classList.remove("is-active");
  resultsSkeleton.hidden = true;
  resultsContent.hidden = false;
  resultsDashboard.classList.remove("is-loading");
  resultsDashboard.classList.add("is-ready");
  resultsDashboard.scrollIntoView({ behavior: "smooth", block: "start" });
}

function completeConfig(config) {
  return Object.fromEntries(
    CONFIG_KEYS.map((key) => [
      key,
      typeof config[key] === "boolean" ? config[key] : SAFE_DEFAULTS[key],
    ]),
  );
}

function markMissingChecks(data, config) {
  const missingKeys = new Set(
    CONFIG_KEYS.filter((key) => typeof config[key] !== "boolean"),
  );
  data.results = data.results.map((result) => {
    const key = CONFIG_KEYS.find((candidate) => result.check_name === CHECK_NAMES[candidate]);
    if (!missingKeys.has(key)) return result;
    return {
      ...result,
      status: "NOT CHECKED",
      recommendation: "Provide a boolean value to evaluate this setting.",
    };
  });
  data.risks = data.results.filter((result) => result.status === "RISK DETECTED").length;
  data.secure = data.results.filter((result) => result.status === "SECURE").length;
  data.not_checked = data.results.filter((result) => result.status === "NOT CHECKED").length;
  return data;
}

function sleep(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

async function typeLine(text, resultText, resultClass) {
  const line = document.createElement("p");
  line.className = "terminal-line";
  terminalLog.append(line);
  for (const character of text) {
    line.textContent += character;
    await sleep(5);
  }
  const result = document.createElement("span");
  result.className = `terminal-result ${resultClass}`;
  result.textContent = resultText;
  line.append(result);
  terminalLog.scrollTop = terminalLog.scrollHeight;
}

async function runSequence(config) {
  terminalLog.replaceChildren();
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const stepDelay = reducedMotion ? 0 : 360;
  for (let index = 0; index < CONFIG_KEYS.length; index += 1) {
    const key = CONFIG_KEYS[index];
    const status = getStatusForKey(key, config);
    const resultLabel = status === "RISK DETECTED" ? "RISK" : status === "SECURE" ? "SECURE" : "NOT CHECKED";
    const resultClass =
      status === "RISK DETECTED" ? "is-risk" : status === "SECURE" ? "is-secure" : "is-not-checked";
    await typeLine(`[${index + 1}/5] Checking ${CHECK_LABELS[key]}... `, resultLabel, resultClass);
    if (stepDelay) await sleep(stepDelay);
  }
}

async function runScan() {
  clearError();
  const config = validateEditor(true);
  if (!config) {
    errorAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }

  scanButton.disabled = true;
  scanButton.classList.add("is-loading");
  scanSequence.hidden = false;
  scanSequence.classList.add("is-active");
  resultsDashboard.hidden = false;
  resultsDashboard.classList.remove("is-ready");
  resultsDashboard.classList.add("is-loading");
  resultsContent.hidden = true;
  resultsSkeleton.hidden = false;
  resultsSkeleton.classList.add("is-active");

  try {
    const [response] = await Promise.all([
      fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(completeConfig(config)),
      }),
      runSequence(config),
    ]);
    const data = await response.json();
    if (!response.ok) {
      const errorText = data.error || "The scan could not be completed.";
      throw new Error(
        errorText.includes("Missing configuration keys")
          ? "A setting is missing. Add all five settings, then run the scan again."
          : errorText,
      );
    }

    markMissingChecks(data, config);
    latestResults = data.results;
    scanSequence.classList.remove("is-active");
    scanSequence.hidden = true;
    renderResults(data);
    showToast("Simulated scan complete.");
  } catch (error) {
    scanSequence.classList.remove("is-active");
    scanSequence.hidden = true;
    resultsDashboard.hidden = true;
    resultsSkeleton.classList.remove("is-active");
    showError(error.message || "The server could not complete the simulated scan. Please try again.");
    errorAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } finally {
    scanButton.disabled = false;
    scanButton.classList.remove("is-loading");
  }
}

async function loadSample() {
  try {
    const response = await fetch("/api/sample");
    const config = await response.json();
    if (!response.ok) throw new Error("The sample configuration could not be loaded.");
    setEditor(config);
  } catch {
    setEditor({
      ...SAFE_DEFAULTS,
    });
    showError("The sample could not be loaded. A safe demo configuration is ready instead.");
  }
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 3200);
}

async function downloadReport() {
  if (!latestResults.length) {
    showError("Run a simulated scan before downloading a report.");
    return;
  }

  try {
    const response = await fetch("/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ results: latestResults }),
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.error || "The CSV report could not be created.");
    }

    const blob = await response.blob();
    const downloadUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = "cloud_sentinel_report.csv";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
    showToast("CSV downloaded and saved in reports/.");
  } catch {
    showError("The CSV could not be downloaded. Check the server and try again.");
  }
}

function setupNetworkCanvas() {
  const canvas = document.querySelector("#network-canvas");
  const context = canvas.getContext("2d");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let width = 0;
  let height = 0;
  let frame = 0;
  let nodes = [];

  function resize() {
    const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * pixelRatio;
    canvas.height = height * pixelRatio;
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    const count = Math.min(64, Math.max(24, Math.round((width * height) / 26000)));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.24,
      vy: (Math.random() - 0.5) * 0.24,
      radius: Math.random() * 1.4 + 0.6,
    }));
    draw();
  }

  function draw() {
    context.clearRect(0, 0, width, height);
    for (let first = 0; first < nodes.length; first += 1) {
      const node = nodes[first];
      if (!reducedMotion.matches && !document.hidden) {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < -5 || node.x > width + 5) node.vx *= -1;
        if (node.y < -5 || node.y > height + 5) node.vy *= -1;
      }

      context.beginPath();
      context.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      context.fillStyle = "rgba(110, 211, 245, 0.42)";
      context.fill();

      for (let second = first + 1; second < nodes.length; second += 1) {
        const other = nodes[second];
        const distance = Math.hypot(node.x - other.x, node.y - other.y);
        if (distance < 135) {
          context.beginPath();
          context.moveTo(node.x, node.y);
          context.lineTo(other.x, other.y);
          context.strokeStyle = `rgba(99, 155, 218, ${0.12 * (1 - distance / 135)})`;
          context.lineWidth = 0.7;
          context.stroke();
        }
      }
    }

    if (!reducedMotion.matches && !document.hidden) frame = requestAnimationFrame(draw);
  }

  window.addEventListener("resize", () => {
    cancelAnimationFrame(frame);
    resize();
  });
  document.addEventListener("visibilitychange", () => {
    cancelAnimationFrame(frame);
    if (!document.hidden && !reducedMotion.matches) draw();
  });
  reducedMotion.addEventListener("change", () => {
    cancelAnimationFrame(frame);
    draw();
  });
  resize();
}

function setupScrollReveal() {
  const sections = document.querySelectorAll(".section-reveal");
  if (!("IntersectionObserver" in window)) {
    sections.forEach((section) => section.classList.add("is-revealed"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-revealed");
          observer.unobserve(entry.target);
        }
      }
    },
    { threshold: 0.08 },
  );
  sections.forEach((section) => observer.observe(section));
}

function setupTypewriter() {
  const target = document.querySelector("#typewriter-text");
  const phrase = "Scan. Detect. Secure.";
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    target.textContent = phrase;
    return;
  }

  target.textContent = "";
  let index = 0;
  function typeNext() {
    target.textContent = phrase.slice(0, index);
    index += 1;
    if (index <= phrase.length) {
      window.setTimeout(typeNext, index < phrase.length ? 76 : 250);
    }
  }
  typeNext();
}

document.querySelectorAll("[data-preset]").forEach((button) => {
  button.addEventListener("click", () => setPreset(button.dataset.preset));
});

document.querySelectorAll("[data-toggle]").forEach((toggle) => {
  toggle.addEventListener("change", () => {
    const key = toggle.dataset.toggle;
    const config = { ...knownConfig, [key]: toggle.checked };
    setEditor(config);
  });
});

form.addEventListener("input", () => {
  syncLineNumbers();
  validateEditor();
});
form.addEventListener("scroll", () => {
  document.querySelector("#line-numbers").scrollTop = form.scrollTop;
});
scanButton.addEventListener("click", runScan);
document.querySelector("#report-button").addEventListener("click", downloadReport);
document.querySelector("#sort-status").addEventListener("click", (event) => {
  statusSortAscending = !statusSortAscending;
  event.currentTarget.textContent = statusSortAscending ? "Sort by status ↑" : "Sort by status ↓";
  renderTable(latestResults);
});

setupNetworkCanvas();
setupScrollReveal();
setupTypewriter();
loadSample();
