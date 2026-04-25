"use client";

import { useEffect, useState } from "react";

interface FollowUp {
  id: number;
  contact_name: string;
  related_project: string;
  action: string;
  due_date: string;
  done: boolean;
  outcome: string;
}

export default function FollowUpsPage() {
  const [items, setItems] = useState<FollowUp[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ contact_name: "", related_project: "", action: "", due_date: "" });
  const [doneModal, setDoneModal] = useState<FollowUp | null>(null);
  const [doneOutcome, setDoneOutcome] = useState("");

  useEffect(() => { fetch("/api/follow-ups").then(r => r.json()).then(setItems).catch(() => {}); }, []);

  const refresh = async () => { const r = await fetch("/api/follow-ups"); setItems(await r.json()); };

  const add = async () => {
    if (!form.contact_name || !form.action || !form.due_date) return;
    await fetch("/api/follow-ups", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
    await refresh();
    setForm({ contact_name: "", related_project: "", action: "", due_date: "" });
    setShowAdd(false);
  };

  const openDoneModal = (item: FollowUp) => {
    setDoneModal(item);
    setDoneOutcome("");
  };

  const confirmDone = async () => {
    if (!doneModal) return;
    const outcome = doneOutcome.trim() || "Done";
    await fetch("/api/follow-ups", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: doneModal.id, done: true, outcome }) });
    setDoneModal(null);
    setDoneOutcome("");
    await refresh();
  };

  const deleteItem = async (id: number) => {
    await fetch("/api/follow-ups", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    await refresh();
  };

  const today = new Date().toISOString().split("T")[0];
  const overdue = items.filter(i => !i.done && String(i.due_date).split("T")[0] < today);
  const dueToday = items.filter(i => !i.done && String(i.due_date).split("T")[0] === today);
  const upcoming = items.filter(i => !i.done && String(i.due_date).split("T")[0] > today);
  const completed = items.filter(i => i.done);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Follow-ups</h1>
          <p className="mt-2 text-muted">Never miss a follow-up. Deals die in silence.</p>
        </div>
        <button onClick={() => setShowAdd(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ Add</button>
      </div>

      {showAdd && (
        <div className="mb-6 rounded-xl border border-border bg-surface p-5">
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <input type="text" value={form.contact_name} onChange={e => setForm({ ...form, contact_name: e.target.value })} placeholder="Contact name *" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.related_project} onChange={e => setForm({ ...form, related_project: e.target.value })} placeholder="Related project" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <input type="text" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })} placeholder="What do you need to do? *" className="w-full rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <div className="flex items-center gap-3">
              <input type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })} className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <button onClick={() => setShowAdd(false)} className="rounded-lg border border-border px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={add} className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-white disabled:opacity-40">Add</button>
            </div>
          </div>
        </div>
      )}

      {/* Overdue */}
      {overdue.length > 0 && (
        <div className="mb-6">
          <h2 className="mb-3 text-sm font-bold uppercase tracking-wide text-red-400">Overdue ({overdue.length})</h2>
          <div className="space-y-2">
            {overdue.map(i => (
              <div key={i.id} className="flex items-center justify-between rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3">
                <div>
                  <p className="text-sm font-semibold">{i.contact_name} {i.related_project && <span className="text-muted">· {i.related_project}</span>}</p>
                  <p className="text-xs text-red-400">{i.action}</p>
                  <p className="mt-0.5 font-mono text-xs text-red-400">{String(i.due_date).split("T")[0]}</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => openDoneModal(i)} className="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-500 hover:bg-emerald-500/25">Done</button>
                  <button onClick={() => deleteItem(i.id)} className="text-xs text-muted hover:text-red-400">✕</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Due Today */}
      {dueToday.length > 0 && (
        <div className="mb-6">
          <h2 className="mb-3 text-sm font-bold uppercase tracking-wide text-accent">Today ({dueToday.length})</h2>
          <div className="space-y-2">
            {dueToday.map(i => (
              <div key={i.id} className="flex items-center justify-between rounded-xl border border-accent/30 bg-accent/5 px-4 py-3">
                <div>
                  <p className="text-sm font-semibold">{i.contact_name} {i.related_project && <span className="text-muted">· {i.related_project}</span>}</p>
                  <p className="text-xs text-accent">{i.action}</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => openDoneModal(i)} className="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-500 hover:bg-emerald-500/25">Done</button>
                  <button onClick={() => deleteItem(i.id)} className="text-xs text-muted hover:text-red-400">✕</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Upcoming */}
      {upcoming.length > 0 && (
        <div className="mb-6">
          <h2 className="mb-3 text-sm font-bold uppercase tracking-wide text-muted">Upcoming ({upcoming.length})</h2>
          <div className="space-y-2">
            {upcoming.map(i => (
              <div key={i.id} className="flex items-center justify-between rounded-xl border border-border bg-surface px-4 py-3">
                <div>
                  <p className="text-sm font-semibold">{i.contact_name} {i.related_project && <span className="text-muted">· {i.related_project}</span>}</p>
                  <p className="text-xs text-muted">{i.action}</p>
                  <p className="mt-0.5 font-mono text-xs text-muted">{String(i.due_date).split("T")[0]}</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => openDoneModal(i)} className="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-medium text-emerald-500 hover:bg-emerald-500/25">Done</button>
                  <button onClick={() => deleteItem(i.id)} className="text-xs text-muted hover:text-red-400">✕</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Done Modal */}
      {doneModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setDoneModal(null)}>
          <div className="w-full max-w-sm rounded-2xl border border-border bg-[var(--background)] p-6 shadow-xl" onClick={e => e.stopPropagation()}>
            <h3 className="mb-1 text-lg font-bold">Mark as Done</h3>
            <p className="mb-4 text-sm text-muted">
              <span className="font-medium text-[var(--foreground)]">{doneModal.contact_name}</span> · {doneModal.action}
            </p>
            <label className="mb-2 block text-sm font-medium">What happened?</label>
            <textarea
              value={doneOutcome}
              onChange={e => setDoneOutcome(e.target.value)}
              placeholder="e.g., Called and discussed pricing, will send proposal by Friday..."
              className="mb-4 w-full rounded-xl border border-border bg-surface p-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
              rows={3}
              autoFocus
            />
            <div className="flex gap-3">
              <button onClick={() => setDoneModal(null)} className="flex-1 rounded-xl border border-border py-3 text-center text-sm font-medium text-muted hover:bg-surface-hover">Cancel</button>
              <button onClick={confirmDone} className="flex-1 rounded-xl bg-emerald-500 py-3 text-center text-sm font-bold text-white hover:bg-emerald-600">Done</button>
            </div>
          </div>
        </div>
      )}

      {/* Completed */}
      {completed.length > 0 && (
        <details className="mb-6">
          <summary className="cursor-pointer text-sm font-bold uppercase tracking-wide text-emerald-500">Completed ({completed.length})</summary>
          <div className="mt-3 space-y-2">
            {completed.map(i => (
              <div key={i.id} className="flex items-center justify-between rounded-xl border border-border bg-surface px-4 py-3 opacity-60">
                <div>
                  <p className="text-sm font-semibold line-through">{i.contact_name} · {i.action}</p>
                  {i.outcome && <p className="text-xs text-emerald-500">→ {i.outcome}</p>}
                </div>
                <button onClick={() => deleteItem(i.id)} className="text-xs text-muted hover:text-red-400">✕</button>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
