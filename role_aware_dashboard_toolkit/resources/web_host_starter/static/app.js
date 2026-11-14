/* Editable host UI. Authority, record scope and persistence belong to the server. */
"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const ui = window.RADTWeb;
  const config = window.RADTWebConfig;
  $("brand").textContent = config.brand;
  $("footer-brand").textContent = config.brand;
  $("headline").textContent = config.headline;
  document.title = `${config.brand} · Workroom`;
  let token = "", epoch = 0, refreshVersion = 0, session = null, items = [], history = [];
  let controller = new AbortController(), editor = null, returnFocus = null, needsSaveReview = false;
  const stale = () => new DOMException("Session changed", "AbortError");

  function clearSession(message = "") {
    epoch += 1;
    refreshVersion += 1;
    controller.abort();
    controller = new AbortController();
    token = ""; session = null; items = []; history = []; editor = null; returnFocus = null; needsSaveReview = false;
    $("editor").close(); $("editor-form").reset(); $("signin-form").reset();
    clearEditorText();
    $("workspace").hidden = true; $("account").hidden = true; $("signin").hidden = false;
    $("board").replaceChildren(); $("metrics").replaceChildren(); $("history").replaceChildren();
    $("account-label").textContent = ""; $("record-count").textContent = ""; $("freeze-label").textContent = ""; $("notice").textContent = message;
    $("signin-error").textContent = ""; $("search").value = "";
    $("signin-form").querySelector("button").disabled = false;
    $("refresh").disabled = false;
  }

  async function api(path, options = {}) {
    const version = epoch;
    const response = await fetch(path, {
      ...options, signal: controller.signal, cache: "no-store", credentials: "omit",
      headers: {Authorization: `Bearer ${token}`, ...(options.body ? {"Content-Type": "application/json"} : {})},
    });
    if (version !== epoch) throw stale();
    const data = await response.json();
    if (version !== epoch) throw stale();
    if (!response.ok) {
      if (response.status === 401) clearSession("Your access has expired. Sign in again to continue.");
      const error = new Error(typeof data.detail === "string" ? data.detail : "Check the fields and try again.");
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function setView() {
    const activity = session?.can_manage && location.hash === "#history";
    $("work-view").hidden = Boolean(activity); $("history-view").hidden = !activity;
    $("work-link").setAttribute("aria-current", activity ? "false" : "page");
    $("history-link").setAttribute("aria-current", activity ? "page" : "false");
  }

  function render() {
    if (!session) return;
    $("signin").hidden = true; $("account").hidden = false; $("workspace").hidden = false;
    $("account-label").textContent = `${session.subject} · ${session.role}`;
    $("history-link").hidden = !session.can_manage;
    $("new-item").hidden = !session.can_manage;
    $("new-item").disabled = session.freeze.frozen || needsSaveReview;
    $("toggle-freeze").hidden = !session.can_manage;
    $("toggle-freeze").disabled = false;
    $("toggle-freeze").textContent = session.freeze.frozen ? "Resume changes" : "Pause changes";
    $("freeze-label").textContent = needsSaveReview ? "Refresh and review saved work before making another change." : session.freeze.frozen ? "Changes are paused. Your records remain available." : "Changes are open.";
    $("metrics").innerHTML = [
      ui.metric({label: "Planned & ready", value: items.filter(item => item.status === "scheduled").length, note: "The next steps ahead", tone: "accent"}),
      ui.metric({label: "Delivered", value: items.filter(item => item.status === "completed").length, note: "Good work, followed through"}),
      ui.metric({label: "All visible work", value: items.length, note: "A view for your account"}),
    ].join("");
    renderBoard(); renderHistory(); setView();
    if (editor && $("editor").getAttribute("aria-busy") !== "true") setEditorBusy(false);
  }

  function formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? value : date.toLocaleString([], {dateStyle: "medium", timeStyle: "short"});
  }

  function renderBoard() {
    const query = $("search").value.trim().toLocaleLowerCase();
    const visible = items.filter(item => `${item.label} ${item.owner}`.toLocaleLowerCase().includes(query));
    $("record-count").textContent = `${visible.length} of ${items.length} work items`;
    $("board").innerHTML = ui.board({
      label: "Work board",
      lanes: [
        {id: "scheduled", label: "Up next", description: "Planned and ready to move.", emptyDescription: "New work starts here."},
        {id: "completed", label: "Delivered", description: "A good day's work, complete."},
        {id: "cancelled", label: "Set aside", description: "Plans change. Keep the context."},
      ],
      items: visible.map(item => ({
        id: item.id, lane: item.status, eyebrow: `Revision ${item.revision}`, title: item.label,
        description: formatDate(item.starts_at), meta: `Assigned to ${item.owner}`,
        actions: session.can_edit ? [
          ...(item.status === "scheduled" ? [{action: "reschedule", label: "Reschedule", disabled: session.freeze.frozen || needsSaveReview}] : []),
          {action: "status", label: "Update status", disabled: session.freeze.frozen || needsSaveReview},
        ] : [],
      })),
    });
  }

  function renderHistory() {
    if (!session.can_manage) { $("history").replaceChildren(); return; }
    $("history").innerHTML = history.length ? [...history].reverse().map(event => {
      const after = event.after || event.after_json || {};
      const title = typeof after === "object" ? (after.label || "Work item") : "Work item";
      return `<article class="history-entry"><h3>${ui.escape(title)}</h3><p>${ui.escape(event.action)} · Revision ${ui.escape(after.revision ?? "—")}</p><p class="history-reason">${ui.escape(event.reason || "No additional note.")}</p></article>`;
    }).join("") : ui.empty({title: "A fresh start", description: "Saved changes will appear here."});
  }

  async function refresh() {
    const version = epoch, sequence = ++refreshVersion;
    try {
      const current = await api("/api/session");
      const records = await api("/api/items");
      const activity = current.can_manage ? await api("/api/history") : {history: []};
      const verified = await api("/api/session");
      if (version !== epoch || sequence !== refreshVersion) throw stale();
      if (current.subject !== verified.subject || current.role !== verified.role) {
        clearSession("Access changed while loading. Sign in again for a current workspace view.");
        throw stale();
      }
      const identityChanged = session && (session.subject !== verified.subject || session.role !== verified.role);
      if (identityChanged || (editor?.item && !records.items.some(item => item.id === editor.item.id))) {
        closeEditor(); $("search").value = "";
        $("board").replaceChildren(); $("history").replaceChildren(); $("metrics").replaceChildren();
        $("notice").textContent = "Your access changed. The workspace now reflects your current role.";
      }
      session = verified; items = records.items; history = activity.history; needsSaveReview = false;
      render();
    } catch (error) {
      if (version === epoch && sequence === refreshVersion && error.status === 403) clearSession("Access changed. Sign in with a current workspace token.");
      throw error;
    }
  }

  async function reconcileDenial() {
    // A frozen write may retain its draft; a revoked account must lose private UI.
    const version = epoch;
    try { await refresh(); }
    catch (error) {
      if (error.name === "AbortError" || version !== epoch) return;
      clearSession("Access changed. Sign in with a current workspace token.");
    }
  }

  $("signin-form").addEventListener("submit", async event => {
    event.preventDefault();
    const supplied = $("access-token").value.trim();
    clearSession(); token = supplied;
    const version = epoch;
    const button = $("signin-form").querySelector("button"); button.disabled = true;
    try { await refresh(); if (version === epoch) $("work-link").focus(); }
    catch (error) {
      if (error.name !== "AbortError" && version === epoch) {
        clearSession(); $("signin-error").textContent = "That token could not open the workspace. Check your access and try again.";
        $("access-token").focus();
      }
    } finally { if (version === epoch) button.disabled = false; }
  });
  $("signout").addEventListener("click", () => { clearSession("You are signed out."); $("access-token").focus(); });
  $("refresh").addEventListener("click", async () => {
    const version = epoch; $("refresh").disabled = true;
    try { await refresh(); if (version === epoch) $("notice").textContent = "Workspace refreshed."; }
    catch (error) {
      if (error.status === 403 && version === epoch) await reconcileDenial();
      else if (error.name !== "AbortError" && version === epoch) $("notice").textContent = "Could not refresh. Check your connection and try again.";
    } finally { if (version === epoch) $("refresh").disabled = false; }
  });
  $("search").addEventListener("input", renderBoard);
  window.addEventListener("hashchange", setView);
  // A page restored from browser history must not expose an earlier private view.
  window.addEventListener("pagehide", () => clearSession());

  function localDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) return "";
    date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
    return date.toISOString().slice(0, 16);
  }

  function populateEditor() {
    const {mode, item} = editor;
    $("editor-form").reset(); $("editor-error").textContent = ""; $("reload-record").hidden = true;
    $("review-save").hidden = true; editor.uncertain = false; editor.conflict = false;
    $("create-fields").hidden = mode !== "create";
    $("schedule-fields").hidden = mode === "status";
    $("status-fields").hidden = mode !== "status";
    $("reason-fields").hidden = mode === "create";
    $("item-label").required = mode === "create"; $("item-owner").required = mode === "create";
    $("item-start").required = mode !== "status";
    $("item-label").value = item?.label || ""; $("item-owner").value = item?.owner || session.subject;
    $("item-start").value = localDate(item?.starts_at || new Date(Date.now() + 86400000).toISOString());
    $("item-status").value = item?.status || "scheduled";
    $("editor-title").textContent = mode === "create" ? "New work item" : item.label;
    $("editor-note").textContent = mode === "create" ? "Give the next step a name, an owner, and a place in the day." : `Editing revision ${item.revision}. ${mode === "status" ? "Update the status and keep the context." : "Choose the next date and time."}`;
    $("save-item").textContent = mode === "create" ? "Create work item" : "Save changes";
    setEditorBusy(false);
  }

  function setEditorBusy(busy) {
    $("editor").setAttribute("aria-busy", String(busy));
    $("editor").querySelectorAll("button,input,textarea,select").forEach(element => { element.disabled = busy; });
    $("save-item").disabled = busy || !session?.can_edit || session.freeze.frozen || needsSaveReview || Boolean(editor?.uncertain || editor?.conflict);
  }

  function openEditor(mode, item = null) {
    returnFocus = document.activeElement;
    editor = {mode, item: item ? {...item} : null};
    populateEditor(); $("editor").showModal();
    $(mode === "create" ? "item-label" : mode === "status" ? "item-status" : "item-start").focus();
  }

  function closeEditor() {
    $("editor").close(); editor = null; $("editor-form").reset();
    clearEditorText();
    if (returnFocus?.isConnected) returnFocus.focus(); else $("work-link").focus();
    returnFocus = null;
  }
  function clearEditorText() {
    $("editor-title").textContent = "New work item";
    $("editor-note").textContent = ""; $("editor-error").textContent = "";
    $("reload-record").hidden = true; $("review-save").hidden = true;
  }
  $("new-item").addEventListener("click", () => openEditor("create"));
  $("board").addEventListener("click", event => {
    const button = event.target.closest("button[data-action]");
    if (!button || button.disabled) return;
    const item = items.find(row => row.id === button.dataset.id);
    if (item) openEditor(button.dataset.action, item);
  });
  $("close-editor").addEventListener("click", closeEditor);
  $("cancel-editor").addEventListener("click", closeEditor);
  $("editor").addEventListener("cancel", event => {
    event.preventDefault();
    if ($("editor").getAttribute("aria-busy") !== "true") closeEditor();
  });
  $("reload-record").addEventListener("click", async () => {
    const active = editor, version = epoch; setEditorBusy(true);
    try {
      await refresh();
      if (version !== epoch || editor !== active) return;
      const item = items.find(row => row.id === active.item.id);
      if (!item) { closeEditor(); $("notice").textContent = "That record is no longer available to this account."; return; }
      editor.item = {...item}; populateEditor();
    } catch (error) {
      if (error.status === 403 && version === epoch) await reconcileDenial();
      else if (error.name !== "AbortError" && version === epoch) $("editor-error").textContent = "Could not load the latest record. Your draft is still here.";
    } finally { if (version === epoch && editor === active) setEditorBusy(false); }
  });

  $("review-save").addEventListener("click", async () => {
    const version = epoch;
    closeEditor();
    $("notice").textContent = "The save result was uncertain. Review the saved work before making another change.";
    try { await refresh(); }
    catch (error) {
      if (error.name !== "AbortError" && version === epoch) $("notice").textContent = "The save result is still uncertain. Refresh and review saved work when the connection returns.";
    }
  });

  $("editor-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!editor || $("save-item").disabled || $("editor").getAttribute("aria-busy") === "true") return;
    const active = editor, version = epoch, values = {};
    if (active.mode !== "status") {
      const date = new Date($("item-start").value);
      if (Number.isNaN(date.valueOf())) { $("editor-error").textContent = "Choose a valid date and time."; return; }
      values.starts_at = date.toISOString();
    }
    if (active.mode === "create") {
      values.label = $("item-label").value; values.owner = $("item-owner").value;
    } else {
      values.expected_revision = active.item.revision; values.reason = $("item-reason").value;
      if (active.mode === "status") values.status = $("item-status").value;
    }
    const path = active.mode === "create" ? "/api/items" : `/api/items/${encodeURIComponent(active.item.id)}/${active.mode}`;
    setEditorBusy(true); $("editor-error").textContent = "";
    try {
      await api(path, {method: "POST", body: JSON.stringify(values)});
      if (version !== epoch || editor !== active) return;
      closeEditor(); $("notice").textContent = active.mode === "create" ? "Work item created." : "Changes saved.";
      try { await refresh(); }
      catch (error) { if (error.name !== "AbortError" && version === epoch) $("notice").textContent = "Saved. Refresh the workspace to see the latest view."; }
    } catch (error) {
      if (version !== epoch || editor !== active || error.name === "AbortError") return;
      $("editor-error").textContent = error.status === 409 ? "This record changed while you were editing. Your draft is preserved. Load the latest record before trying again." : error.message;
      $("reload-record").hidden = error.status !== 409;
      editor.conflict = error.status === 409;
      if (!error.status || error.status >= 500) {
        editor.uncertain = true; needsSaveReview = true;
        $("editor-error").textContent = "The save result is uncertain. Review saved work before trying again; the server may already have saved this change.";
        $("review-save").hidden = false;
        render();
      }
      if (error.status === 403) await reconcileDenial();
    } finally { if (version === epoch && editor === active) setEditorBusy(false); }
  });

  $("toggle-freeze").addEventListener("click", async () => {
    if (!session) return;
    const version = epoch; $("toggle-freeze").disabled = true;
    try {
      await api("/api/freeze", {method: "POST", body: JSON.stringify({frozen: !session.freeze.frozen, expected_revision: session.freeze.revision})});
      await refresh(); if (version === epoch) $("notice").textContent = session.freeze.frozen ? "Changes paused for the workspace." : "Changes resumed for the workspace.";
    } catch (error) {
      if (error.status === 403 && version === epoch) await reconcileDenial();
      else if (error.name !== "AbortError" && version === epoch) $("notice").textContent = error.status === 409 ? "The pause setting changed. Refresh before trying again." : error.message;
    } finally { if (version === epoch) $("toggle-freeze").disabled = false; }
  });
})();
