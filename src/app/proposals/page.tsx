"use client";

import { useEffect, useState } from "react";

interface Proposal {
  id: number;
  client_name: string;
  project_name: string;
  problem: string;
  solution: string;
  timeline: string;
  price: string;
  payment_terms: string;
  status: string;
  created_at: string;
}

const STATUSES = [
  { value: "draft", label: "Draft", color: "bg-zinc-500/15 text-zinc-400" },
  { value: "sent", label: "Sent", color: "bg-blue-400/15 text-blue-400" },
  { value: "accepted", label: "Accepted", color: "bg-emerald-500/15 text-emerald-500" },
  { value: "rejected", label: "Rejected", color: "bg-red-400/15 text-red-400" },
];

export default function ProposalsPage() {
  const [proposals, setProposals] = useState<Proposal[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ client_name: "", project_name: "", problem: "", solution: "", timeline: "", price: "", payment_terms: "50% advance, 50% on delivery", status: "draft" });
  const [editId, setEditId] = useState<number | null>(null);

  useEffect(() => { fetch("/api/proposals").then(r => r.json()).then(setProposals).catch(() => {}); }, []);

  const refresh = async () => { const r = await fetch("/api/proposals"); setProposals(await r.json()); };

  const save = async () => {
    if (!form.client_name || !form.project_name) return;
    if (editId) {
      await fetch("/api/proposals", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...form, id: editId }) });
    } else {
      await fetch("/api/proposals", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
    }
    await refresh();
    setForm({ client_name: "", project_name: "", problem: "", solution: "", timeline: "", price: "", payment_terms: "50% advance, 50% on delivery", status: "draft" });
    setEditId(null);
    setShowForm(false);
  };

  const copyAsText = (p: Proposal) => {
    const text = `PROPOSAL — AREA KPI Technology
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Client: ${p.client_name}
Project: ${p.project_name}
Date: ${new Date(p.created_at).toLocaleDateString("en-IN")}

THE PROBLEM:
${p.problem}

OUR SOLUTION:
${p.solution}

TIMELINE: ${p.timeline}

INVESTMENT: ${p.price}

PAYMENT TERMS:
${p.payment_terms}

WHAT'S INCLUDED:
• Custom development
• Deployment and setup
• User training
• Post-launch support

ABOUT US:
AREA KPI Technology builds custom software for organizations. Our clients include SEBI India, Jain Social Group (1050+ members), and fitness studios. 25+ years of development experience.

Contact: Ashish Kamdar
WhatsApp: +91 98198 00214
Web: areakpi.in`;

    navigator.clipboard.writeText(text);
    alert("Proposal copied! Paste into WhatsApp or email.");
  };

  const startEdit = (p: Proposal) => {
    setForm({ client_name: p.client_name, project_name: p.project_name, problem: p.problem, solution: p.solution, timeline: p.timeline, price: p.price, payment_terms: p.payment_terms, status: p.status });
    setEditId(p.id);
    setShowForm(true);
  };

  const updateStatus = async (p: Proposal, status: string) => {
    await fetch("/api/proposals", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...p, status }) });
    await refresh();
  };

  const deleteProposal = async (id: number) => {
    if (!confirm("Delete?")) return;
    await fetch("/api/proposals", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    await refresh();
  };

  const statusInfo = (s: string) => STATUSES.find(x => x.value === s) || STATUSES[0];

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Proposals</h1>
          <p className="mt-2 text-muted">Create, send, and track proposals. Copy to WhatsApp in one tap.</p>
        </div>
        <button onClick={() => { setEditId(null); setShowForm(true); }} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ New Proposal</button>
      </div>

      {showForm && (
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <h2 className="mb-4 text-lg font-semibold">{editId ? "Edit Proposal" : "New Proposal"}</h2>
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <input type="text" value={form.client_name} onChange={e => setForm({ ...form, client_name: e.target.value })} placeholder="Client name *" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.project_name} onChange={e => setForm({ ...form, project_name: e.target.value })} placeholder="Project name *" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <textarea value={form.problem} onChange={e => setForm({ ...form, problem: e.target.value })} rows={2} placeholder="The problem they have..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <textarea value={form.solution} onChange={e => setForm({ ...form, solution: e.target.value })} rows={2} placeholder="What you'll build to solve it..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <div className="grid gap-3 sm:grid-cols-3">
              <input type="text" value={form.timeline} onChange={e => setForm({ ...form, timeline: e.target.value })} placeholder="Timeline (e.g., 4-6 weeks)" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.price} onChange={e => setForm({ ...form, price: e.target.value })} placeholder="Price (e.g., Rs 2,00,000)" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.payment_terms} onChange={e => setForm({ ...form, payment_terms: e.target.value })} placeholder="Payment terms" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => { setShowForm(false); setEditId(null); }} className="rounded-lg border border-border px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={save} className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-white disabled:opacity-40">Save</button>
            </div>
          </div>
        </div>
      )}

      {proposals.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No proposals yet</p>
          <p className="mt-1 text-sm text-muted">Create your first proposal and send it via WhatsApp.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {proposals.map(p => {
            const si = statusInfo(p.status);
            return (
              <div key={p.id} className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">{p.client_name}</span>
                    <select value={p.status} onChange={e => updateStatus(p, e.target.value)} className={`rounded-md border-0 px-2 py-0.5 text-xs font-medium ${si.color} cursor-pointer focus:outline-none`}>
                      {STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                    </select>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => copyAsText(p)} className="rounded-lg bg-[#25D366]/15 px-3 py-1.5 text-xs font-medium text-[#25D366] hover:bg-[#25D366]/25">📋 Copy for WhatsApp</button>
                    <button onClick={() => startEdit(p)} className="rounded p-1 text-muted opacity-0 hover:text-[var(--foreground)] group-hover:opacity-100">✎</button>
                    <button onClick={() => deleteProposal(p.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100">✕</button>
                  </div>
                </div>
                <p className="text-sm text-accent">{p.project_name}</p>
                {p.price && <p className="mt-1 font-mono text-sm font-bold">{p.price}</p>}
                <div className="mt-2 grid gap-2 text-xs sm:grid-cols-2">
                  {p.problem && <p><strong className="text-muted">Problem:</strong> {p.problem}</p>}
                  {p.solution && <p><strong className="text-muted">Solution:</strong> {p.solution}</p>}
                </div>
                <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted">
                  {p.timeline && <span>Timeline: {p.timeline}</span>}
                  {p.payment_terms && <span>Terms: {p.payment_terms}</span>}
                  <span>{new Date(p.created_at).toLocaleDateString("en-IN")}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
