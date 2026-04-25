"use client";

import { useEffect, useState } from "react";

interface StrategyItem {
  text: string;
  done: boolean;
}

interface StrategyLog {
  text: string;
  date: string;
}

interface StrategyChecklist {
  items: StrategyItem[];
  log: StrategyLog[];
}

interface Lead {
  id: number;
  name: string;
  company: string;
  community: string;
  stage: string;
  source: string;
  estimated_value: string;
  next_action: string;
  next_date: string;
  notes: string;
  strategy_checklist: StrategyChecklist;
}

const STAGES = [
  { value: "aware", label: "Aware", color: "bg-zinc-500/15 text-zinc-400" },
  { value: "interested", label: "Interested", color: "bg-blue-400/15 text-blue-400" },
  { value: "meeting", label: "Meeting Set", color: "bg-accent/15 text-accent" },
  { value: "proposal", label: "Proposal Sent", color: "bg-yellow-500/15 text-yellow-400" },
  { value: "negotiating", label: "Negotiating", color: "bg-purple-400/15 text-purple-400" },
  { value: "won", label: "Won", color: "bg-emerald-500/15 text-emerald-500" },
  { value: "lost", label: "Lost", color: "bg-red-400/15 text-red-400" },
];

export default function PipelinePage() {
  const [leads, setLeads] = useState<Lead[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", company: "", community: "Kutchi", stage: "aware", source: "", estimated_value: "", next_action: "", next_date: "", notes: "" });

  useEffect(() => { fetch("/api/pipeline").then(r => r.json()).then(setLeads).catch(() => {}); }, []);

  const refresh = async () => { const r = await fetch("/api/pipeline"); setLeads(await r.json()); };

  const addLead = async () => {
    if (!form.name) return;
    await fetch("/api/pipeline", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
    await refresh();
    setForm({ name: "", company: "", community: "Kutchi", stage: "aware", source: "", estimated_value: "", next_action: "", next_date: "", notes: "" });
    setShowForm(false);
  };

  const updateStage = async (lead: Lead, stage: string) => {
    await fetch("/api/pipeline", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...lead, stage }) });
    await refresh();
    if (stage === "won") {
      alert(`Deal won! "${lead.name}" has been auto-added to your Projects page.`);
    }
  };

  const deleteLead = async (id: number) => {
    if (!confirm("Delete?")) return;
    await fetch("/api/pipeline", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    await refresh();
  };

  const stageInfo = (s: string) => STAGES.find(x => x.value === s) || STAGES[0];
  const pipelineValue = leads.filter(l => !["won", "lost"].includes(l.stage)).reduce((s, l) => s + (parseInt(l.estimated_value?.replace(/[^\d]/g, "") || "0")), 0);
  const wonValue = leads.filter(l => l.stage === "won").reduce((s, l) => s + (parseInt(l.estimated_value?.replace(/[^\d]/g, "") || "0")), 0);

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Sales Pipeline</h1>
          <p className="mt-2 text-muted">Track every lead from awareness to deal closed.</p>
        </div>
        <button onClick={() => setShowForm(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ Add Lead</button>
      </div>

      {/* Stats */}
      <div className="mb-8 grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">In Pipeline</p>
          <p className="mt-1 font-mono text-xl font-bold text-accent">{leads.filter(l => !["won", "lost"].includes(l.stage)).length}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">Pipeline Value</p>
          <p className="mt-1 font-mono text-xl font-bold text-accent">₹{(pipelineValue / 100000).toFixed(1)}L</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">Won</p>
          <p className="mt-1 font-mono text-xl font-bold text-emerald-500">₹{(wonValue / 100000).toFixed(1)}L</p>
        </div>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <h2 className="mb-4 text-lg font-semibold">New Lead</h2>
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-3">
              <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Person name *" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.company} onChange={e => setForm({ ...form, company: e.target.value })} placeholder="Company / Business" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.estimated_value} onChange={e => setForm({ ...form, estimated_value: e.target.value })} placeholder="Estimated value (e.g., Rs 2L)" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <input type="text" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} placeholder="Source (gymkhana, referral...)" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.next_action} onChange={e => setForm({ ...form, next_action: e.target.value })} placeholder="Next action" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="date" value={form.next_date} onChange={e => setForm({ ...form, next_date: e.target.value })} className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowForm(false)} className="rounded-lg border border-border px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={addLead} disabled={!form.name} className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-white disabled:opacity-40">Add Lead</button>
            </div>
          </div>
        </div>
      )}

      {/* Pipeline by stage */}
      {STAGES.map(stage => {
        const stageLeads = leads.filter(l => l.stage === stage.value);
        if (stageLeads.length === 0) return null;
        return (
          <div key={stage.value} className="mb-6">
            <div className="mb-3 flex items-center gap-2">
              <span className={`rounded-md px-2.5 py-1 text-xs font-bold ${stage.color}`}>{stage.label}</span>
              <span className="text-xs text-muted">({stageLeads.length})</span>
            </div>
            <div className="space-y-3">
              {stageLeads.map(lead => (
                <div key={lead.id} className="group rounded-xl border border-border bg-surface p-4 transition-colors hover:border-accent/30">
                  {/* Header */}
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-lg font-semibold">{lead.name}</span>
                        <select value={lead.stage} onChange={e => updateStage(lead, e.target.value)} className={`rounded-md border-0 px-2 py-0.5 text-xs font-medium ${stageInfo(lead.stage).color} cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent`}>
                          {STAGES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                        </select>
                      </div>
                      {lead.company && <p className="text-sm text-accent">{lead.company}</p>}
                      <div className="mt-1 flex flex-wrap gap-2">
                        {lead.estimated_value && <span className="font-mono text-sm font-bold text-emerald-500">{lead.estimated_value}</span>}
                        {lead.community && <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs text-accent">{lead.community}</span>}
                        {lead.source && <span className="rounded-md bg-surface-hover px-2 py-0.5 text-xs text-muted">{lead.source}</span>}
                      </div>
                    </div>
                    <button onClick={() => deleteLead(lead.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100 sm:opacity-0">✕</button>
                  </div>

                  {/* Editable Next Action */}
                  <div className="mt-3 rounded-lg bg-accent/5 p-3">
                    <div className="flex items-start gap-2">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mt-1.5 size-4 shrink-0 text-accent"><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" /></svg>
                      <div className="flex-1">
                        <input
                          type="text"
                          defaultValue={lead.next_action}
                          onBlur={async (e) => {
                            await fetch("/api/pipeline", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...lead, next_action: e.target.value }) });
                          }}
                          placeholder="Next action..."
                          className="w-full rounded border-0 bg-transparent px-1 py-0.5 text-xs text-accent placeholder:text-accent/40 focus:bg-surface focus:outline-none focus:ring-1 focus:ring-accent/30"
                        />
                        <input
                          type="date"
                          defaultValue={lead.next_date ? String(lead.next_date).split("T")[0] : ""}
                          onChange={async (e) => {
                            await fetch("/api/pipeline", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...lead, next_date: e.target.value }) });
                          }}
                          className="mt-1 rounded border-0 bg-transparent px-1 py-0.5 font-mono text-xs text-accent/60 focus:bg-surface focus:outline-none focus:ring-1 focus:ring-accent/30"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Strategy & Action Plan */}
                  {(lead.strategy_checklist?.items?.length > 0 || lead.strategy_checklist?.log?.length > 0) && (
                    <div className="mt-3 border-t border-border pt-3">
                      <details className="rounded-lg bg-[var(--background)]">
                        <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-accent hover:text-accent-hover">
                          Strategy & Action Plan ({lead.strategy_checklist.items.filter(i => !i.done).length} pending, {lead.strategy_checklist.items.filter(i => i.done).length} done)
                        </summary>
                        <div className="px-3 pb-3">
                          {/* Checklist */}
                          <div className="space-y-2 mt-2">
                            {lead.strategy_checklist.items.map((item, idx) => (
                              <label key={idx} className={`flex items-start gap-2.5 rounded-lg px-2 py-1.5 cursor-pointer hover:bg-surface-hover transition-colors ${item.done ? "opacity-50" : ""}`}>
                                <input
                                  type="checkbox"
                                  checked={item.done}
                                  onChange={async () => {
                                    const newDone = !item.done;
                                    // Optimistic update
                                    setLeads(prev => prev.map(l => l.id === lead.id ? {
                                      ...l,
                                      strategy_checklist: {
                                        ...l.strategy_checklist,
                                        items: l.strategy_checklist.items.map((it, i) => i === idx ? { ...it, done: newDone } : it)
                                      }
                                    } : l));
                                    await fetch("/api/pipeline", {
                                      method: "PUT",
                                      headers: { "Content-Type": "application/json" },
                                      body: JSON.stringify({ id: lead.id, action: "toggle_checklist_item", index: idx, done: newDone })
                                    });
                                  }}
                                  className="mt-0.5 size-4 shrink-0 rounded border-border accent-accent"
                                />
                                <span className={`text-xs leading-relaxed ${item.done ? "line-through text-muted" : ""} ${item.text.startsWith("DO NOT") ? "text-red-400" : ""}`}>
                                  {item.text}
                                </span>
                              </label>
                            ))}
                          </div>

                          {/* Add checklist item */}
                          <div className="mt-3 flex gap-2">
                            <input
                              type="text"
                              placeholder="Add action item..."
                              onKeyDown={async (e) => {
                                if (e.key === "Enter" && (e.target as HTMLInputElement).value.trim()) {
                                  const text = (e.target as HTMLInputElement).value.trim();
                                  (e.target as HTMLInputElement).value = "";
                                  await fetch("/api/pipeline", {
                                    method: "PUT",
                                    headers: { "Content-Type": "application/json" },
                                    body: JSON.stringify({ id: lead.id, action: "add_checklist_item", text })
                                  });
                                  await refresh();
                                }
                              }}
                              className="flex-1 rounded-lg border border-border bg-transparent px-2.5 py-1.5 text-xs placeholder:text-muted/50 focus:border-accent focus:outline-none"
                            />
                          </div>

                          {/* Activity Log */}
                          <div className="mt-4 border-t border-border/50 pt-3">
                            <p className="text-xs font-semibold text-muted mb-2">What happened</p>
                            <div className="flex gap-2 mb-3">
                              <input
                                type="text"
                                placeholder="e.g. Bumped into him at Gymkhana, kept it casual..."
                                onKeyDown={async (e) => {
                                  if (e.key === "Enter" && (e.target as HTMLInputElement).value.trim()) {
                                    const text = (e.target as HTMLInputElement).value.trim();
                                    (e.target as HTMLInputElement).value = "";
                                    await fetch("/api/pipeline", {
                                      method: "PUT",
                                      headers: { "Content-Type": "application/json" },
                                      body: JSON.stringify({ id: lead.id, action: "add_strategy_log", text })
                                    });
                                    await refresh();
                                  }
                                }}
                                className="flex-1 rounded-lg border border-border bg-transparent px-2.5 py-1.5 text-xs placeholder:text-muted/50 focus:border-accent focus:outline-none"
                              />
                            </div>
                            {lead.strategy_checklist.log?.length > 0 && (
                              <div className="space-y-1.5">
                                {lead.strategy_checklist.log.map((entry, idx) => (
                                  <div key={idx} className="flex items-start gap-2 text-xs">
                                    <span className="shrink-0 font-mono text-accent/70">{entry.date}</span>
                                    <span className="leading-relaxed">{entry.text}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </details>
                    </div>
                  )}

                  {/* Collapsible Notes + Add Update */}
                  <div className="mt-3 border-t border-border pt-3">
                    <div className="mb-2 flex items-center justify-between">
                      <p className="text-xs font-medium text-muted">Notes & Conversation Log</p>
                      <button
                        onClick={async () => {
                          const update = prompt("Add an update (conversation, decision, note):");
                          if (!update) return;
                          const timestamp = new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
                          const newNotes = `\n[${timestamp}] ${update}` + (lead.notes ? "\n" + lead.notes : "");
                          await fetch("/api/pipeline", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...lead, notes: newNotes.trim() }) });
                          await refresh();
                        }}
                        className="rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                      >
                        + Add Update
                      </button>
                    </div>
                    {lead.notes && (
                      <details className="rounded-lg bg-[var(--background)]">
                        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-muted hover:text-[var(--foreground)]">
                          View full details ({lead.notes.split("\n").filter((l: string) => l.trim()).length} entries)
                        </summary>
                        <div className="max-h-72 overflow-y-auto px-3 pb-3">
                          <div className="space-y-1.5">
                            {lead.notes.split("\n").filter((l: string) => l.trim()).map((line: string, i: number) => {
                              const isHeader = line.startsWith("===");
                              const isTimestamp = line.startsWith("[");
                              const isDivider = line.startsWith("---");
                              if (isDivider) return <hr key={i} className="border-border" />;
                              if (isHeader) return <p key={i} className="mt-2 text-xs font-bold text-accent">{line.replace(/===/g, "").trim()}</p>;
                              if (isTimestamp) return <p key={i} className="text-xs leading-relaxed"><span className="font-mono text-accent">{line.match(/\[.*?\]/)?.[0]}</span> {line.replace(/\[.*?\]\s*/, "")}</p>;
                              return <p key={i} className="text-xs leading-relaxed text-muted">{line}</p>;
                            })}
                          </div>
                        </div>
                      </details>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {leads.length === 0 && (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No leads yet</p>
          <p className="mt-1 text-sm text-muted">Add gymkhana contacts, referrals, anyone who might need software.</p>
        </div>
      )}
    </div>
  );
}
