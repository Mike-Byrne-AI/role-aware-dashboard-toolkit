/* Read-only presentation. Every receipt field is escaped; no test execution lives here. */
window.WestbridgeSecurityLab = (() => {
  "use strict";
  const labels = {passed:"Passed locally", failed:"Failed", not_run:"Not run", stale:"Source changed", unavailable:"Evidence unavailable"};
  const badge = (status, e) => `<span class="lab-status lab-status-${Object.hasOwn(labels,status)?status:"not_run"}">${e(labels[status] || "Not run")}</span>`;
  function render(data, {e, heading, isAdmin}) {
    const evidence=data.evidence,receipt=evidence.receipt;
    const checks=receipt?.checks || [];
    const resultFor=id=>{
      const scene=data.scenarios.find(item=>item.id===id);
      if(!receipt||receipt.mode!=="scenarios")return "not_run";
      if(evidence.status==="stale"||receipt.source_unchanged!==true)return "stale";
      const statuses=scene.checks.map(key=>checks.find(check=>check.id===key)?.status || "not_run");
      return statuses.includes("failed")?"failed":statuses.every(status=>status==="passed")?"passed":"not_run";
    };
    return heading("Security testbed",data.title,"Inspect the threat, the enforced rule, and the evidence behind the result.",'<button class="button" data-action="refresh">Refresh evidence</button>')+
      `<section class="lab-overview panel" aria-labelledby="lab-evidence-heading"><div><div class="eyebrow">Reviewed evidence</div><h2 id="lab-evidence-heading">A result you can inspect</h2><p>${e(evidence.message)}</p></div>${badge(evidence.status,e)}<div class="lab-source"><span>Source snapshot</span><code>${e(data.source.sha256)}</code><small>Captured on this process's first lab request. Restart after source changes. Imported results describe their own recorded environment.</small></div></section>`+
      `<div class="lab-scenarios">${data.scenarios.map(scene=>`<article class="panel lab-scene"><div class="lab-scene-top"><span class="lab-number">${e(scene.number)}</span>${badge(resultFor(scene.id),e)}</div><div class="eyebrow">${e(scene.scope)}</div><h2>${e(scene.title)}</h2><p class="lab-threat">${e(scene.threat)}</p><ol>${scene.steps.map(step=>`<li>${e(step)}</li>`).join("")}</ol><div class="lab-invariant"><strong>What must hold</strong><p>${e(scene.invariant)}</p></div><details><summary>Why this boundary exists</summary><p>${e(scene.decision)}</p></details></article>`).join("")}</div>`+
      `<section class="panel lab-receipt" aria-labelledby="lab-receipt-heading"><div class="panel-heading"><div><h2 id="lab-receipt-heading">Inspect the recorded run</h2><p>Results come from operator-run disposable exercises. Opening this page does not run an attack or change business records.</p></div></div><div class="panel-body">${receipt?`<dl class="lab-facts"><div><dt>Scope</dt><dd>${e(receipt.scope)}</dd></div><div><dt>Mode</dt><dd>${e(receipt.mode)}</dd></div><div><dt>Finished</dt><dd>${e(receipt.finished_at || "Not finished")}</dd></div><div><dt>Receipt</dt><dd><code>${e(receipt.receipt_id)}</code></dd></div></dl><ul class="lab-checks">${checks.map(check=>`<li><span>${e(check.title)}</span>${badge(check.status,e)}</li>`).join("")}</ul><details><summary>View sanitized receipt</summary><pre tabindex="0">${e(JSON.stringify(receipt,null,2))}</pre></details>`:'<p class="lab-empty">No validated receipt is loaded. The scenarios above describe acceptance criteria, not completed checks.</p>'}</div></section>`+
      `<section class="lab-decisions" aria-labelledby="lab-decisions-heading"><div><div class="eyebrow">Engineering decisions</div><h2 id="lab-decisions-heading">The reasoning is part of the demo.</h2></div><div class="lab-decision-grid">${data.decisions.map(item=>`<article><h3>${e(item.title)}</h3><p>${e(item.body)}</p></article>`).join("")}</div></section>`+
      `<aside class="notice lab-hosted"><strong>Hosted acceptance is separate.</strong> ${e(data.hosted_acceptance.message)}</aside>`+
      (isAdmin?`<section class="panel lab-timeline" aria-labelledby="lab-timeline-heading"><div class="panel-heading"><div><div class="eyebrow">Administrator view</div><h2 id="lab-timeline-heading">Durable security timeline</h2><p>Protected runtime events. These records are separate from the public demonstration receipt.</p></div><button class="button small" data-action="lab-events">Load timeline</button></div><div class="panel-body"><p id="lab-events-status" role="status">Load recent events when needed. This page does not poll.</p><div id="lab-events-error" class="error" role="alert" hidden></div><div id="lab-events-content"></div></div></section>`:"");
  }
  function timeline(data,e) {
    const attention=data.delivery.failed>0||data.delivery.pending>=data.retention.normal_event_capacity;
    return (attention?'<p class="notice" role="status"><strong>Delivery needs attention.</strong> Pending evidence is preserved. Use verified administrator delivery or the offline recovery procedure; do not replay the business actions.</p>':"")+
      `<div class="lab-delivery"><span><strong>${e(data.delivery.pending)}</strong> pending</span><span><strong>${e(data.delivery.delivered)}</strong> delivered to local consumer</span><span><strong>${e(data.delivery.failed)}</strong> awaiting delivery retry</span></div><p class="field-hint">At-least-once delivery with an idempotent local consumer. Ordinary-event watermark: ${e(data.retention.normal_event_capacity)}. Administrator containment reserve: ${e(data.retention.containment_reserve)}. Total capacity: ${e(data.retention.max_events)} events. Delivered events become eligible for pruning after ${e(data.retention.max_age_days)} days, on new event insertion; pending events are preserved.</p>`+
      (data.events.length?`<ol class="lab-event-list">${data.events.map(event=>`<li><div><strong>${e(event.code)}</strong><span class="badge">${e(event.outcome)}</span></div><p>${e(event.reason)} · ${e(event.method)} · ${e(event.delivery)}</p><small>${e(new Date(event.occurred_at*1000).toISOString())} · Event ${e(event.id)}</small></li>`).join("")}</ol>`:'<p>No retained security events.</p>')+
      `<p class="field-hint">Denials suppressed in this process: ${e(data.observation.denials_suppressed_since_start)}. Recording failures in this process: ${e(data.observation.recording_failures_since_start)}. These diagnostic counts reset on restart.</p>`;
  }
  return Object.freeze({render,timeline});
})();
