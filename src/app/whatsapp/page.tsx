"use client";

import { useEffect, useState } from "react";

interface Template {
  id: number;
  name: string;
  category: string;
  message: string;
}

export default function WhatsAppPage() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [copied, setCopied] = useState<number | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState("");
  const [newCategory, setNewCategory] = useState("Business");
  const [newMessage, setNewMessage] = useState("");
  const [filter, setFilter] = useState("All");

  useEffect(() => { fetch("/api/whatsapp-templates").then((r) => r.json()).then(setTemplates).catch(() => {}); }, []);

  const copyToClipboard = async (id: number, text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const addTemplate = async () => {
    if (!newName || !newMessage) return;
    await fetch("/api/whatsapp-templates", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newName, category: newCategory, message: newMessage }),
    });
    const res = await fetch("/api/whatsapp-templates");
    setTemplates(await res.json());
    setShowAdd(false); setNewName(""); setNewMessage("");
  };

  const deleteTemplate = async (id: number) => {
    if (!confirm("Delete this template?")) return;
    await fetch("/api/whatsapp-templates", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    setTemplates(templates.filter((t) => t.id !== id));
  };

  const categories = ["All", ...new Set(templates.map((t) => t.category))];
  const filtered = filter === "All" ? templates : templates.filter((t) => t.category === filter);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">WhatsApp Templates</h1>
          <p className="mt-2 text-muted">Tap to copy, paste into WhatsApp. Replace [brackets] with real names.</p>
        </div>
        <button onClick={() => setShowAdd(!showAdd)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ Add</button>
      </div>

      {showAdd && (
        <div className="mb-6 rounded-xl border border-border bg-surface p-5">
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <input type="text" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Template name" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={newCategory} onChange={(e) => setNewCategory(e.target.value)} placeholder="Category" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <textarea value={newMessage} onChange={(e) => setNewMessage(e.target.value)} rows={4} placeholder="Message text... use [Name], [project], etc. for placeholders" className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowAdd(false)} className="rounded-lg border border-border px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={addTemplate} disabled={!newName || !newMessage} className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-white disabled:opacity-40">Save</button>
            </div>
          </div>
        </div>
      )}

      <div className="mb-6 flex flex-wrap gap-2">
        {categories.map((c) => (
          <button key={c} onClick={() => setFilter(c)} className={`rounded-full px-3 py-1.5 text-xs font-medium ${filter === c ? "bg-accent text-white" : "bg-surface text-muted"}`}>{c}</button>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {filtered.map((t) => (
          <div key={t.id} className="group rounded-xl border border-border bg-surface p-4 transition-colors hover:border-accent/30">
            <div className="mb-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm">{t.name}</span>
                <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs text-accent">{t.category}</span>
              </div>
              <button onClick={() => deleteTemplate(t.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100 text-xs">✕</button>
            </div>
            <p className="mb-3 whitespace-pre-wrap text-xs leading-relaxed text-muted">{t.message}</p>
            <button
              onClick={() => copyToClipboard(t.id, t.message)}
              className={`flex w-full items-center justify-center gap-2 rounded-lg py-2.5 text-xs font-semibold transition-colors ${
                copied === t.id ? "bg-emerald-500 text-white" : "bg-[var(--background)] text-accent hover:bg-accent/10"
              }`}
            >
              {copied === t.id ? "✓ Copied!" : "📋 Copy to Clipboard"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
