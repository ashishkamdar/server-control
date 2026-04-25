"use client";

import { useEffect, useState } from "react";

interface GymkhanaContact {
  id: string | number;
  name: string;
  business: string;
  department: string;
  age: string;
  relationship: "coffee-group" | "acquaintance" | "friend" | "prospect" | "client";
  softwareNeeds: string;
  approachNotes: string;
  lastInteraction: string;
  nextMove: string;
  potential: string;
}

const DEPARTMENTS = ["Gym", "Badminton", "Swimming", "Squash", "Tennis", "Card Room", "Zumba", "Table Tennis", "Billiards & Pool", "Coffee Group"];
const RELATIONSHIPS = [
  { value: "coffee-group", label: "Coffee Group (Inner Circle)", color: "bg-sky-400/15 text-sky-400" },
  { value: "friend", label: "Friend", color: "bg-emerald-500/15 text-emerald-500" },
  { value: "acquaintance", label: "Acquaintance", color: "bg-blue-400/15 text-blue-400" },
  { value: "prospect", label: "Prospect", color: "bg-accent/15 text-accent" },
  { value: "client", label: "Client", color: "bg-emerald-500/15 text-emerald-500" },
];

export default function GymkhanaPage() {
  const [contacts, setContacts] = useState<GymkhanaContact[]>([]);
  const [editing, setEditing] = useState<GymkhanaContact | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [filter, setFilter] = useState("All");

  useEffect(() => {
    fetchContacts();
  }, []);

  const fetchContacts = async () => {
    try {
      const res = await fetch("/api/gymkhana");
      const data = await res.json();
      const mapped = data.map((c: Record<string, unknown>) => ({
        id: c.id, name: c.name || "", business: c.business || "", department: c.department || "Gym",
        age: c.age || "", relationship: c.relationship || "acquaintance",
        softwareNeeds: c.software_needs || "", approachNotes: c.approach_notes || "",
        lastInteraction: c.last_interaction || "", nextMove: c.next_move || "", potential: c.potential || "",
      }));
      setContacts(mapped);
    } catch { /* offline */ }
  };

  const save = async (contact: GymkhanaContact) => {
    const body = {
      id: isNew ? undefined : contact.id,
      name: contact.name, business: contact.business, department: contact.department,
      age: contact.age, relationship: contact.relationship, software_needs: contact.softwareNeeds,
      approach_notes: contact.approachNotes, last_interaction: contact.lastInteraction,
      next_move: contact.nextMove, potential: contact.potential,
    };
    await fetch("/api/gymkhana", {
      method: isNew ? "POST" : "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await fetchContacts();
    setShowForm(false);
    setEditing(null);
    setIsNew(false);
  };

  const deleteContact = async (id: string | number) => {
    if (!confirm("Remove this contact?")) return;
    await fetch("/api/gymkhana", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    await fetchContacts();
  };

  const startNew = () => {
    setEditing({
      id: Date.now().toString(),
      name: "", business: "", department: "Gym", age: "",
      relationship: "acquaintance", softwareNeeds: "", approachNotes: "",
      lastInteraction: "", nextMove: "", potential: "",
    });
    setIsNew(true);
    setShowForm(true);
  };

  const filtered = filter === "All" ? contacts : contacts.filter((c) => c.department === filter || c.relationship === filter);

  const relInfo = (rel: string) => RELATIONSHIPS.find((r) => r.value === rel) || RELATIONSHIPS[2];

  // Stats
  const stats = {
    total: contacts.length,
    coffeeGroup: contacts.filter((c) => c.relationship === "coffee-group" || c.department === "Coffee Group").length,
    prospects: contacts.filter((c) => c.relationship === "prospect").length,
    clients: contacts.filter((c) => c.relationship === "client").length,
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Gymkhana Network</h1>
        <p className="mt-2 text-muted">
          Matunga Gymkhana — your daily networking ground. Track relationships and opportunities.
        </p>
      </div>

      {/* Stats */}
      <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-2xl font-bold font-mono text-accent">{stats.total}</p>
          <p className="text-xs text-muted">Total Contacts</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-2xl font-bold font-mono text-sky-400">{stats.coffeeGroup}</p>
          <p className="text-xs text-muted">Coffee Group</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-2xl font-bold font-mono text-accent">{stats.prospects}</p>
          <p className="text-xs text-muted">Prospects</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4 text-center">
          <p className="text-2xl font-bold font-mono text-emerald-500">{stats.clients}</p>
          <p className="text-xs text-muted">Clients</p>
        </div>
      </div>

      {/* Strategy card */}
      <div className="mb-8 rounded-xl border border-accent/20 bg-accent/5 p-5">
        <h3 className="font-semibold text-accent">Your Strategy</h3>
        <p className="mt-2 text-sm leading-relaxed">
          You have <strong>daily face-time</strong> with wealthy decision-makers. Most people pay thousands for this access — you get it for free at morning coffee.
          Every contact here is a potential <strong>Rs 1-5 lakh project + yearly maintenance</strong>. Your goal: convert 5 gymkhana members into clients this year = <strong>Rs 5-25 lakhs + recurring revenue</strong>.
        </p>
        <div className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
          <div className="rounded-lg bg-accent/10 p-2.5 text-accent">
            <strong>Step 1:</strong> Add every person you know here. Note their business.
          </div>
          <div className="rounded-lg bg-accent/10 p-2.5 text-accent">
            <strong>Step 2:</strong> For each, think: what software problem do they probably have?
          </div>
          <div className="rounded-lg bg-accent/10 p-2.5 text-accent">
            <strong>Step 3:</strong> Next coffee, casually ask about their business pain. Listen, don&apos;t sell.
          </div>
        </div>
      </div>

      {/* Filters + Add */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-2">
          {["All", "Coffee Group", "Gym", "Badminton", "Swimming"].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                filter === f ? "bg-accent text-white" : "bg-surface text-muted hover:text-[var(--foreground)]"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <button
          onClick={startNew}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white hover:bg-accent-hover"
        >
          + Add Contact
        </button>
      </div>

      {/* Form Modal */}
      {showForm && editing && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 sm:pt-20">
          <div className="w-full max-w-lg rounded-2xl border border-border bg-[var(--background)] p-5 shadow-2xl">
            <div className="mb-5 flex items-center justify-between">
              <h2 className="text-lg font-semibold">{isNew ? "Add Contact" : "Edit Contact"}</h2>
              <button onClick={() => { setShowForm(false); setEditing(null); }} className="rounded-lg p-2 text-muted hover:text-[var(--foreground)]">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            <div className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">Name *</label>
                  <input type="text" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="e.g., Rajesh Mehta" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Business / Profession</label>
                  <input type="text" value={editing.business} onChange={(e) => setEditing({ ...editing, business: e.target.value })} placeholder="e.g., Construction, Doctor, Financer" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <div>
                  <label className="mb-1 block text-xs font-medium">Department</label>
                  <select value={editing.department} onChange={(e) => setEditing({ ...editing, department: e.target.value })} className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none">
                    {DEPARTMENTS.map((d) => <option key={d} value={d}>{d}</option>)}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Relationship</label>
                  <select value={editing.relationship} onChange={(e) => setEditing({ ...editing, relationship: e.target.value as GymkhanaContact["relationship"] })} className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none">
                    {RELATIONSHIPS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Age</label>
                  <input type="text" value={editing.age} onChange={(e) => setEditing({ ...editing, age: e.target.value })} placeholder="e.g., 60+" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">What software could they need?</label>
                <input type="text" value={editing.softwareNeeds} onChange={(e) => setEditing({ ...editing, softwareNeeds: e.target.value })} placeholder="e.g., Construction project tracker, clinic management..." className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Approach Notes</label>
                <textarea value={editing.approachNotes} onChange={(e) => setEditing({ ...editing, approachNotes: e.target.value })} rows={2} placeholder="How do you know them? Any mutual connections?" className="w-full resize-none rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium">Last Interaction</label>
                  <input type="text" value={editing.lastInteraction} onChange={(e) => setEditing({ ...editing, lastInteraction: e.target.value })} placeholder="e.g., Yesterday at coffee" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">Revenue Potential</label>
                  <input type="text" value={editing.potential} onChange={(e) => setEditing({ ...editing, potential: e.target.value })} placeholder="e.g., Rs 2-3L + yearly AMC" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">Next Move</label>
                <input type="text" value={editing.nextMove} onChange={(e) => setEditing({ ...editing, nextMove: e.target.value })} placeholder="e.g., Ask about their billing system at tomorrow's coffee" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button onClick={() => { setShowForm(false); setEditing(null); }} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted hover:text-[var(--foreground)]">Cancel</button>
                <button onClick={() => save(editing)} disabled={!editing.name.trim()} className="rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40">
                  {isNew ? "Add" : "Save"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Contact cards */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No contacts yet</p>
          <p className="mt-1 text-sm text-muted">Start adding the people you see at the gymkhana every day.</p>
          <button onClick={startNew} className="mt-4 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white">+ Add Contact</button>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {filtered.map((c) => {
            const ri = relInfo(c.relationship);
            return (
              <div key={c.id} className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
                <div className="mb-2 flex items-start justify-between">
                  <div>
                    <p className="font-semibold">{c.name}</p>
                    <p className="text-sm text-muted">{c.business}</p>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${ri.color}`}>{ri.label}</span>
                    <button onClick={() => { setEditing({ ...c }); setIsNew(false); setShowForm(true); }} className="rounded p-1 text-muted opacity-0 hover:text-[var(--foreground)] group-hover:opacity-100">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5"><path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Z" /></svg>
                    </button>
                    <button onClick={() => deleteContact(c.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                    </button>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 text-xs">
                  <span className="rounded bg-surface-hover px-2 py-0.5 text-muted">{c.department}</span>
                  {c.age && <span className="rounded bg-surface-hover px-2 py-0.5 text-muted">{c.age}</span>}
                </div>
                {c.softwareNeeds && (
                  <p className="mt-2 text-xs"><strong className="text-accent">Needs:</strong> {c.softwareNeeds}</p>
                )}
                {c.potential && (
                  <p className="mt-1 font-mono text-xs font-bold text-emerald-500">{c.potential}</p>
                )}
                {c.nextMove && (
                  <div className="mt-2 rounded-lg bg-accent/5 p-2">
                    <p className="text-xs text-accent"><strong>Next:</strong> {c.nextMove}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
