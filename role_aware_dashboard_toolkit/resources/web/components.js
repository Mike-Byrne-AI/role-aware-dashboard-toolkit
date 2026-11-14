/* Presentation only. Hosts own data loading, event handling and authorization. */
"use strict";
window.RADTWeb = (() => {
  const escape = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
  const key = value => {
    if (typeof value !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(value)) throw new Error("Invalid component action");
    return value;
  };
  function metric({label, value, note, action, tone = "default"}) {
    const tag = action ? "button" : "article";
    return `<${tag} class="radt-metric${tone === "accent" ? " radt-metric-accent" : ""}"${action ? ` type="button" data-action="${key(action)}"` : ""}><span class="radt-label">${escape(label)}</span><strong>${escape(value)}</strong><span class="radt-note">${escape(note)}${action ? '<span aria-hidden="true"> ↗</span>' : ""}</span></${tag}>`;
  }
  function action({title, description, action: name, count, disabled = false}) {
    return `<button type="button" class="radt-action" data-action="${key(name)}"${disabled ? " disabled" : ""}><span class="radt-action-count">${escape(count ?? "→")}</span><span><strong>${escape(title)}</strong><small>${escape(description)}</small></span><span aria-hidden="true">↗</span></button>`;
  }
  function steps(labels, current = null) {
    if (!Array.isArray(labels) || !labels.length || (current !== null && (!Number.isInteger(current) || current < 0 || current >= labels.length))) throw new Error("Invalid workflow steps");
    return `<ol class="radt-steps" aria-label="Work progress">${labels.map((label,index) => `<li${index === current ? ' aria-current="step"' : ""} class="${index < current ? "done" : ""}"><span aria-hidden="true">${index < current ? "✓" : index + 1}</span>${escape(label)}</li>`).join("")}</ol>`;
  }
  function empty({title, description}) {
    return `<div class="radt-empty"><strong>${escape(title)}</strong><p>${escape(description)}</p></div>`;
  }
  function filterItems(items, {query = "", lane = "", owner = ""} = {}) {
    const words = String(query).trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    return items.filter(item => {
      const people = item.people || [];
      const text = [item.title, item.eyebrow, item.description, item.meta, ...people.map(person => person.name)].join(" ").toLocaleLowerCase();
      return (!lane || item.lane === lane) && (!owner || people.some(person => person.id === owner)) && words.every(word => text.includes(word));
    });
  }
  function board({label = "Work board", lanes, items}) {
    const ids = new Set(), laneIds = new Set();
    if (!Array.isArray(lanes) || !lanes.length || !Array.isArray(items)) throw new Error("Invalid board data");
    for (const lane of lanes) {
      if (typeof lane.id !== "string" || !lane.id || laneIds.has(lane.id)) throw new Error("Invalid board lane");
      laneIds.add(lane.id);
    }
    for (const item of items) {
      if (typeof item.id !== "string" || !item.id || ids.has(item.id) || !laneIds.has(item.lane)) throw new Error("Invalid board item");
      ids.add(item.id);
    }
    return `<div class="radt-board" role="region" aria-label="${escape(label)}">${lanes.map(lane => {
      const rows = items.filter(item => item.lane === lane.id);
      return `<section class="radt-board-lane" aria-label="${escape(lane.label)}" data-lane="${escape(lane.id)}"><div class="radt-board-heading"><div><h2>${escape(lane.label)}</h2><p>${escape(lane.description)}</p></div><span class="radt-board-count" aria-label="${rows.length} items">${rows.length}</span></div><div class="radt-board-stack">${rows.length ? rows.map(item => `<article class="radt-board-card" data-record-id="${escape(item.id)}"><p class="radt-board-eyebrow">${escape(item.eyebrow)}</p><h3>${escape(item.title)}</h3><p class="radt-board-description">${escape(item.description)}</p><p class="radt-board-meta">${escape(item.meta)}</p><ul class="radt-board-people" aria-label="Assigned people">${(item.people || []).map(person => `<li>${escape(person.name)}</li>`).join("")}</ul><div class="radt-board-actions">${(item.actions || []).map(button => `<button type="button" data-action="${key(button.action)}" data-id="${escape(item.id)}" aria-label="${escape(button.label)}: ${escape(item.title)}"${button.disabled ? " disabled" : ""}>${escape(button.label)}</button>`).join("")}</div></article>`).join("") : empty({title: "Nothing in this stage", description: lane.emptyDescription || "Matching work will appear here."})}</div></section>`;
    }).join("")}</div>`;
  }
  return Object.freeze({escape, metric, action, steps, empty, filterItems, board});
})();
