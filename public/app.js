"use strict";

(() => {
  const MAX_EMAILS = 50;
  // The server's inference deadline is 120 seconds. Leave time for D1 and the backend.
  const REQUEST_TIMEOUT_MS = 135_000;
  const SAMPLES = {
    controls: [
      "alex.morgan@example.com",
      "team+signup@example.org",
      "relay-example@example.net",
      "a8f03b92c71d@example.net",
      "test@example.com",
      "not-an-email",
    ],
    invalid: ["not-an-email", "missing-at.example.com", "name@", "@example.com"],
  };
  const VERDICTS = {
    likely_legitimate: { label: "Likely legitimate", tone: "green" },
    suspicious: { label: "Suspicious", tone: "orange" },
    insufficient_evidence: { label: "Insufficient evidence", tone: "amber" },
  };
  const API_STATUSES = new Set(["classified", "skipped", "error", "pending"]);
  const byId = (id) => document.getElementById(id);
  const ui = {
    form: byId("email-form"),
    emails: byId("emails"),
    count: byId("input-count"),
    inputError: byId("input-error"),
    run: byId("run-button"),
    runLabel: byId("run-label"),
    stop: byId("stop-button"),
    clear: byId("clear-button"),
    customer: byId("sample-customer"),
    controls: byId("sample-controls"),
    invalid: byId("sample-invalid"),
    sampleStatus: byId("sample-status"),
    message: byId("run-message"),
    progress: byId("batch-progress"),
    progressLabel: byId("progress-label"),
    list: byId("request-list"),
    listEmpty: byId("list-empty"),
    table: byId("results-table"),
    resultCount: byId("result-count"),
    inspectorEmpty: byId("inspector-empty"),
    inspection: byId("inspection"),
  };
  const state = { items: [], selected: null, running: false, stopRequested: false, inputTouched: false, samples: null, customerEmails: new Set() };

  function setText(id, value) {
    byId(id).textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function inputs() {
    return ui.emails.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function inputSource(email) {
    if (state.customerEmails.has(email)) return "Synthetic example";
    if (SAMPLES.controls.includes(email)) return "Control";
    if (SAMPLES.invalid.includes(email)) return "Invalid example";
    return "Custom input";
  }

  function restoreCustomerSamples() {
    if (state.running || !state.samples) return;
    ui.emails.value = state.samples.emails.join("\n");
    ui.sampleStatus.textContent = `${state.samples.emails.length} synthetic examples loaded. No expected verdicts.`;
    updateInputCount();
  }

  async function loadCustomerSamples() {
    try {
      const response = await fetch("/samples.json", {
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const samples = await response.json();
      const source = samples?.source;
      if (!Array.isArray(samples?.emails) || !samples.emails.length || samples.emails.length > MAX_EMAILS
        || !samples.emails.every((email) => typeof email === "string" && email.trim() && !/[\r\n]/.test(email))
        || typeof source?.label !== "string" || typeof source.date !== "string" || typeof source.note !== "string"
        || source.count !== samples.emails.length) {
        throw new Error("Invalid sample file");
      }
      state.samples = samples;
      state.customerEmails = new Set(samples.emails);
      if (!state.inputTouched && !state.running) restoreCustomerSamples();
      else ui.sampleStatus.textContent = `${samples.emails.length} synthetic examples available. No expected verdicts.`;
      if (state.items.length) renderInspector();
      setControls();
    } catch {
      ui.sampleStatus.textContent = "Synthetic examples unavailable. Custom inputs and controls still work.";
      setText("sample-load-error", "Sample loading failed. Reload to try again; no signup request was sent by this load.");
      byId("sample-load-error").hidden = false;
    }
  }

  function updateInputCount() {
    const count = inputs().length;
    ui.count.textContent = `${count} / ${MAX_EMAILS}`;
    ui.runLabel.textContent = state.running ? "Batch running" : `Run ${count || ""}${count ? " " : ""}${count === 1 ? "request" : "requests"}`;
    if (!state.items.length && !state.running) {
      ui.progress.max = Math.max(count, 1);
      ui.progressLabel.textContent = `0 / ${count}`;
    }
    if (!ui.inputError.hidden) {
      ui.inputError.hidden = true;
      ui.emails.removeAttribute("aria-invalid");
    }
  }

  function setControls() {
    ui.emails.disabled = state.running;
    ui.customer.disabled = state.running || !state.samples;
    ui.controls.disabled = state.running;
    ui.invalid.disabled = state.running;
    ui.run.disabled = state.running;
    ui.clear.disabled = state.running || !state.items.length;
    ui.stop.hidden = !state.running;
    ui.stop.disabled = state.stopRequested;
    ui.stop.textContent = state.stopRequested ? "Stopping after this response…" : "Stop after current request";
    updateInputCount();
  }

  function formatDuration(value) {
    if (!Number.isFinite(value) || value < 0) return "—";
    return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(2)} s`;
  }

  function formatPercent(value) {
    return Number.isFinite(value) && value >= 0 && value <= 1 ? `${(value * 100).toFixed(1)}%` : "—";
  }

  function outcome(item) {
    if (item.phase === "queued") return { label: "Queued", tone: "neutral" };
    if (item.phase === "not_sent") return { label: "Not sent", tone: "neutral" };
    if (item.phase === "running") return { label: "In flight", tone: "orange" };
    if (item.phase === "failed") return { label: "Request error", tone: "red" };
    const result = item.data;
    if (result.status === "classified") return VERDICTS[result.verdict] || { label: result.verdict || "Classified", tone: "neutral" };
    if (result.status === "skipped") return { label: "Skipped", tone: "amber" };
    if (result.status === "error") return { label: "Model error", tone: "red" };
    return { label: "Pending", tone: "amber" };
  }

  function originFor(item) {
    return item.data?.origin || item.raw?.origin;
  }

  function delivery(item) {
    const origin = originFor(item);
    if (origin?.predictionsPreserved === true) {
      const status = origin.receivedClef?.status;
      const suffix = status && status !== "classified" ? ` · ${status}` : "";
      return { label: `Received${suffix}`, badge: `Received by backend${suffix}`, tone: status === "classified" ? "green" : "amber" };
    }
    if (origin?.predictionsPreserved === false) return { label: "Mismatch", badge: "Backend prediction mismatch", tone: "red" };
    if (item.phase === "queued" || item.phase === "not_sent") return { label: "Not sent", badge: "No request sent", tone: "neutral" };
    if (item.phase === "running") return { label: "Awaiting proof", badge: "Awaiting backend evidence", tone: "neutral" };
    return { label: "Unconfirmed", badge: "Delivery not confirmed", tone: "amber" };
  }

  function renderList() {
    const hasItems = state.items.length > 0;
    ui.listEmpty.hidden = hasItems;
    ui.table.hidden = !hasItems;
    ui.resultCount.textContent = String(state.items.length);
    const fragment = document.createDocumentFragment();
    for (const [index, item] of state.items.entries()) {
      const row = document.createElement("tr");
      row.dataset.selected = String(state.selected === index);
      const emailCell = document.createElement("td");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "request-button";
      button.dataset.index = String(index);
      button.setAttribute("aria-pressed", String(state.selected === index));
      button.setAttribute("aria-controls", "inspection");
      button.setAttribute("aria-label", `Inspect request ${index + 1}: ${item.email}`);
      button.textContent = item.email;
      emailCell.append(button);
      row.append(emailCell);
      const presentation = outcome(item);
      const receipt = delivery(item);
      const backendStatus = originFor(item)?.status;
      const cells = [
        { text: presentation.label, tone: presentation.tone },
        { text: item.data?.status === "classified" ? formatPercent(item.data.probabilities?.suspicious) : "—" },
        { text: formatDuration(item.data?.inferenceMs) },
        { text: Number.isInteger(backendStatus) ? String(backendStatus) : "—" },
        { text: receipt.label, tone: receipt.tone },
      ];
      for (const cell of cells) {
        const element = document.createElement("td");
        element.textContent = cell.text;
        if (cell.tone) element.dataset.tone = cell.tone;
        row.append(element);
      }
      fragment.append(row);
    }
    // Keep the focused email button and the table's scroll position during batch updates.
    const focusedIndex = ui.list.contains(document.activeElement) ? document.activeElement.dataset.index : null;
    ui.list.replaceChildren(fragment);
    if (focusedIndex !== null) ui.list.querySelector(`[data-index="${focusedIndex}"]`)?.focus({ preventScroll: true });
  }

  function evidence(value) {
    return value === true ? "Verified" : value === false ? "Mismatch" : "Not reported";
  }

  function renderInspector() {
    const item = state.selected === null ? null : state.items[state.selected];
    ui.inspectorEmpty.hidden = Boolean(item);
    ui.inspection.hidden = !item;
    if (!item) return;
    const data = item.data;
    const origin = originFor(item);
    const received = origin?.receivedClef;
    const receipt = delivery(item);
    setText("detail-email", item.email);
    setText("detail-verdict", outcome(item).label);
    setText("detail-backend-status", Number.isInteger(origin?.status) ? `Backend HTTP ${origin.status}` : "Backend HTTP not reported");
    setText("detail-delivery", receipt.badge);
    byId("detail-delivery").dataset.tone = receipt.tone;
    const warning = item.error ? [item.error, item.warning].filter(Boolean).join(" ") : item.warning;
    byId("detail-warning").hidden = !warning;
    setText("detail-warning", warning);
    setText("received-legitimate", formatPercent(received?.probabilities?.likely_legitimate));
    setText("received-suspicious", formatPercent(received?.probabilities?.suspicious));
    setText("received-insufficient", formatPercent(received?.probabilities?.insufficient_evidence));
    setText("backend-response", origin?.response !== null && origin?.response !== undefined
      ? JSON.stringify(origin.response, null, 2)
      : item.phase === "running" ? "Waiting for the actual backend response."
        : item.phase === "queued" || item.phase === "not_sent" ? "No request sent to the backend."
          : "No actual backend response was reported. Delivery cannot be inferred from a Clef result.");

    setText("detail-source", inputSource(item.email));
    setText("record-status", data ? `${data.status} / ${data.errorCode || "no error code"}` : null);
    setText("detail-confidence", data?.status === "classified" ? formatPercent(data.confidence) : "—");
    setText("record-model", data ? `${data.model || "Not reported"} / ${data.policyVersion || "Not reported"}` : null);
    setText("request-timing", `${formatDuration(data?.totalMs)} / ${formatDuration(item.browserMs)}`);
    setText("request-id", data?.requestId);
    setText("ray-id", data?.rayId);
    setText("request-route", data?.request ? [data.request.method, data.request.path].filter(Boolean).join(" ") : null);
    setText("request-content-type", data?.request?.contentType);
    setText("request-body", typeof data?.request?.body === "string" ? `${data.request.body}\n${Number.isInteger(data.request.bodyBytes) ? `${data.request.bodyBytes} bytes` : "Byte count not reported"}` : null);
    setText("request-hash", data?.request?.bodySha256);
    setText("request-preserved", [origin?.bodyPreserved, origin?.methodPreserved, origin?.pathPreserved, origin?.contentTypePreserved].map(evidence).join(" / "));
    setText("prediction-comparison", evidence(origin?.predictionsPreserved));
    const integration = data?.integration;
    setText("transform-marker", integration?.transformApplied === true
      ? `${integration.transformHeader || "Header"}: ${integration.transformValue ?? "Not reported"}`
      : integration?.transformApplied === false ? "Not observed" : "Not reported");
    const redirected = typeof item.responseRedirected === "boolean" ? String(item.responseRedirected) : "Not reported";
    const location = origin?.location === null ? "None reported" : origin?.location ?? "Not reported";
    setText("request-redirect", `${redirected} / ${location}`);
    setText("received-clef", received ? JSON.stringify(received, null, 2) : "No received Clef fields reported.");
    setText("raw-response", item.raw !== null ? JSON.stringify(item.raw, null, 2) : "No API JSON response received.");
  }

  function render() {
    renderList();
    renderInspector();
    const settled = state.items.filter((item) => item.phase === "received" || item.phase === "failed").length;
    ui.progress.max = Math.max(state.items.length, 1);
    ui.progress.value = settled;
    ui.progressLabel.textContent = `${settled} / ${state.items.length}`;
  }

  async function sendRequest(item) {
    const controller = new AbortController();
    let timedOut = false;
    const startedAt = performance.now();
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch("/AccountV2/ConfirmEmail", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "X-Clef-Demo": "1" },
        cache: "no-store",
        redirect: "error",
        body: JSON.stringify({ email: item.email }),
        signal: controller.signal,
      });
      item.responseRedirected = response.redirected;
      let json;
      try {
        json = await response.json();
      } catch (error) {
        if (timedOut) throw error;
        item.error = `The server returned HTTP ${response.status}, but not a readable JSON response.`;
        item.warning = "Backend processing is unconfirmed. No retry was attempted. If your Access session expired, reload to sign in again.";
        return false;
      }
      item.raw = json;
      if (!response.ok) {
        const detail = typeof json?.error === "string" ? json.error : "The API did not provide an error message.";
        item.error = `API error (HTTP ${response.status}): ${detail}`;
        item.warning = "The batch stopped without retrying. This error alone does not establish whether the backend received the request.";
        return false;
      }
      if (!json || typeof json !== "object" || !API_STATUSES.has(json.status)) {
        item.error = "The API returned JSON without a recognized classification status.";
        item.warning = "The batch stopped without retrying. See the inspection envelope in technical details.";
        return false;
      }
      item.data = json;
      return true;
    } catch {
      if (timedOut) {
        item.error = "The browser stopped waiting after 135 seconds.";
        item.warning = "The request may still finish on the server, including backend processing. A browser timeout does not cancel a processed signup. No retry was attempted; the remaining batch was not sent.";
      } else {
        item.error = "The request ended without an API response reaching this page.";
        item.warning = "The request may still finish on the server. Check your connection or reload to renew an expired Access session. No retry was attempted; the remaining batch was not sent.";
      }
      return false;
    } finally {
      clearTimeout(timer);
      item.browserMs = performance.now() - startedAt;
    }
  }

  function batchSummary() {
    const received = state.items.filter((item) => item.phase === "received");
    const classified = received.filter((item) => item.data.status === "classified").length;
    const skipped = received.filter((item) => item.data.status === "skipped").length;
    const errors = received.filter((item) => item.data.status === "error").length;
    const pending = received.filter((item) => item.data.status === "pending").length;
    const failed = state.items.filter((item) => item.phase === "failed").length;
    const unsent = state.items.filter((item) => item.phase === "not_sent").length;
    const pieces = [`${classified} classified`, `${skipped} skipped`];
    if (errors) pieces.push(`${errors} model ${errors === 1 ? "error" : "errors"}`);
    if (pending) pieces.push(`${pending} pending`);
    if (failed) pieces.push(`${failed} request ${failed === 1 ? "error" : "errors"}`);
    if (unsent) pieces.push(`${unsent} not sent`);
    return pieces.join(" · ");
  }

  async function runBatch(emails) {
    state.inputTouched = true;
    state.running = true;
    state.stopRequested = false;
    state.items = emails.map((email) => ({ email, phase: "queued", data: null, raw: null, browserMs: null, responseRedirected: null, error: null, warning: null }));
    state.selected = 0;
    byId("technical-disclosure").open = false;
    setControls();
    render();
    let stoppedOnError = false;
    try {
      for (const [index, item] of state.items.entries()) {
        if (state.stopRequested) break;
        item.phase = "running";
        ui.message.textContent = `Request ${index + 1} of ${emails.length} in flight.`;
        render();
        const succeeded = await sendRequest(item);
        item.phase = succeeded ? "received" : "failed";
        ui.message.textContent = succeeded ? `Response ${index + 1} of ${emails.length} received.` : `Request ${index + 1} failed. No retry.`;
        render();
        if (!succeeded) {
          stoppedOnError = true;
          break;
        }
      }
    } finally {
      for (const item of state.items) {
        if (item.phase === "queued") item.phase = "not_sent";
      }
      state.running = false;
      const prefix = stoppedOnError ? "Stopped on a request error." : state.stopRequested ? "Stopped after the current request finished." : "Batch complete.";
      ui.message.textContent = `${prefix} ${batchSummary()}.`;
      render();
      setControls();
      if (document.activeElement === ui.stop || document.activeElement === document.body) ui.run.focus({ preventScroll: true });
    }
  }

  ui.form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (state.running) return;
    const emails = inputs();
    if (!emails.length || emails.length > MAX_EMAILS) {
      ui.inputError.textContent = emails.length ? `There are ${emails.length} inputs. Reduce the batch to ${MAX_EMAILS} or fewer; nothing has been sent.` : "Add at least one non-empty line. Nothing has been sent.";
      ui.inputError.hidden = false;
      ui.emails.setAttribute("aria-invalid", "true");
      ui.emails.focus();
      return;
    }
    void runBatch(emails);
  });

  ui.stop.addEventListener("click", () => {
    if (!state.running || state.stopRequested) return;
    state.stopRequested = true;
    setControls();
    ui.message.textContent = "Stopping after the current response. The current request may still reach the backend; no further requests will start.";
  });

  ui.list.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-index]");
    if (!button || !ui.list.contains(button)) return;
    state.selected = Number(button.dataset.index);
    byId("technical-disclosure").open = false;
    renderList();
    renderInspector();
  });

  ui.emails.addEventListener("input", () => {
    state.inputTouched = true;
    updateInputCount();
  });
  ui.customer.addEventListener("click", () => {
    if (state.running) return;
    state.inputTouched = true;
    restoreCustomerSamples();
    ui.emails.focus();
  });
  for (const [button, sample] of [[ui.controls, "controls"], [ui.invalid, "invalid"]]) {
    button.addEventListener("click", () => {
      if (state.running) return;
      state.inputTouched = true;
      ui.emails.value = SAMPLES[sample].join("\n");
      ui.sampleStatus.textContent = sample === "controls" ? "Controls loaded · includes Apple private relay. No expected verdicts." : "Invalid examples loaded · inspect extraction skips.";
      updateInputCount();
      ui.emails.focus();
    });
  }
  ui.clear.addEventListener("click", () => {
    if (state.running) return;
    state.items = [];
    state.selected = null;
    ui.message.textContent = "Results cleared from this page. Stored D1 records are not deleted.";
    render();
    setControls();
    ui.emails.focus();
  });
  setControls();
  setText("demo-host", window.location.hostname);
  void loadCustomerSamples();
})();
