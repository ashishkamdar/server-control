"use client";

import { useEffect, useState } from "react";

interface RevenueEntry {
  id: number;
  entry_date: string;
  type: "income" | "expense";
  amount: number;
  category: string;
  description: string;
  project_name: string;
}

const INCOME_CATS = ["Project Payment", "Maintenance/AMC", "Freelance", "Consulting", "Other Income"];
const EXPENSE_CATS = ["Server/Hosting", "Software/Tools", "Internet", "Phone", "Travel", "Food/Entertainment", "Domain/SSL", "Other Expense"];

export default function RevenuePage() {
  const [entries, setEntries] = useState<RevenueEntry[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [type, setType] = useState<"income" | "expense">("income");
  const [amount, setAmount] = useState("");
  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");
  const [projectName, setProjectName] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => { fetchEntries(); }, []);

  const fetchEntries = async () => {
    try {
      const res = await fetch("/api/revenue");
      setEntries(await res.json());
    } catch { /* offline */ }
  };

  const saveEntry = async () => {
    if (!amount) return;
    setSaving(true);
    await fetch("/api/revenue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, amount: parseFloat(amount), category, description, project_name: projectName }),
    });
    await fetchEntries();
    setShowForm(false);
    setAmount(""); setCategory(""); setDescription(""); setProjectName("");
    setSaving(false);
  };

  const deleteEntry = async (id: number) => {
    if (!confirm("Delete?")) return;
    await fetch("/api/revenue", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    setEntries(entries.filter((e) => e.id !== id));
  };

  const totalIncome = entries.filter((e) => e.type === "income").reduce((s, e) => s + Number(e.amount), 0);
  const totalExpense = entries.filter((e) => e.type === "expense").reduce((s, e) => s + Number(e.amount), 0);
  const profit = totalIncome - totalExpense;

  const fmt = (n: number) => new Intl.NumberFormat("en-IN").format(Math.round(n));

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Revenue Tracker</h1>
          <p className="mt-2 text-muted">Track every rupee — income, expenses, profit.</p>
        </div>
        <button onClick={() => setShowForm(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ Add Entry</button>
      </div>

      {/* Summary cards */}
      <div className="mb-8 grid grid-cols-3 gap-3">
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">Income</p>
          <p className="mt-1 font-mono text-xl font-bold text-emerald-500">₹{fmt(totalIncome)}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">Expenses</p>
          <p className="mt-1 font-mono text-xl font-bold text-red-400">₹{fmt(totalExpense)}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-xs text-muted">Profit</p>
          <p className={`mt-1 font-mono text-xl font-bold ${profit >= 0 ? "text-emerald-500" : "text-red-400"}`}>₹{fmt(profit)}</p>
        </div>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <div className="mb-4 flex gap-2">
            <button onClick={() => setType("income")} className={`flex-1 rounded-lg py-2.5 text-sm font-medium ${type === "income" ? "bg-emerald-500 text-white" : "bg-[var(--background)] text-muted"}`}>Income</button>
            <button onClick={() => setType("expense")} className={`flex-1 rounded-lg py-2.5 text-sm font-medium ${type === "expense" ? "bg-red-400 text-white" : "bg-[var(--background)] text-muted"}`}>Expense</button>
          </div>
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-sm font-medium">Amount (₹) *</label>
              <input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="e.g., 100000" className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 font-mono text-lg focus:border-accent focus:outline-none" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Category</label>
              <div className="flex flex-wrap gap-2">
                {(type === "income" ? INCOME_CATS : EXPENSE_CATS).map((c) => (
                  <button key={c} onClick={() => setCategory(c)} className={`rounded-lg px-3 py-1.5 text-xs font-medium ${category === c ? "bg-accent text-white" : "bg-[var(--background)] text-muted"}`}>{c}</button>
                ))}
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-muted">Description</label>
                <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g., Olistic Studios payment" className="w-full rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted">Project (if applicable)</label>
                <input type="text" value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="e.g., Olistic Studios" className="w-full rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowForm(false)} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted">Cancel</button>
              <button onClick={saveEntry} disabled={saving || !amount} className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40">{saving ? "Saving..." : "Save"}</button>
            </div>
          </div>
        </div>
      )}

      {/* Entries */}
      {entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No entries yet</p>
          <p className="mt-1 text-sm text-muted">Start tracking your income and expenses.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {entries.map((e) => (
            <div key={e.id} className="group flex items-center justify-between rounded-xl border border-border bg-surface px-5 py-3 transition-colors hover:border-accent/30">
              <div className="flex items-center gap-3">
                <span className={`flex size-8 items-center justify-center rounded-full text-sm font-bold ${e.type === "income" ? "bg-emerald-500/15 text-emerald-500" : "bg-red-400/15 text-red-400"}`}>
                  {e.type === "income" ? "+" : "−"}
                </span>
                <div>
                  <p className="text-sm font-medium">{e.description || e.category || e.type}</p>
                  <p className="text-xs text-muted">{new Date(e.entry_date).toLocaleDateString("en-IN")} {e.project_name && `· ${e.project_name}`}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`font-mono text-sm font-bold ${e.type === "income" ? "text-emerald-500" : "text-red-400"}`}>
                  {e.type === "income" ? "+" : "−"}₹{fmt(Number(e.amount))}
                </span>
                <button onClick={() => deleteEntry(e.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100">✕</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
