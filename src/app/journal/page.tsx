"use client";

import { useEffect, useState } from "react";

interface JournalEntry {
  id: number;
  entry_date: string;
  mood: string;
  energy_level: number;
  grooming_done: boolean;
  people_met: string;
  practiced: string;
  wins: string;
  challenges: string;
  notes: string;
}

const MOODS = [
  { value: "great", label: "Great", emoji: "😊" },
  { value: "good", label: "Good", emoji: "🙂" },
  { value: "okay", label: "Okay", emoji: "😐" },
  { value: "low", label: "Low", emoji: "😔" },
  { value: "bad", label: "Bad", emoji: "😞" },
];

export default function JournalPage() {
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [mood, setMood] = useState("okay");
  const [energy, setEnergy] = useState(3);
  const [grooming, setGrooming] = useState(false);
  const [peopleMet, setPeopleMet] = useState("");
  const [practiced, setPracticed] = useState("");
  const [wins, setWins] = useState("");
  const [challenges, setChallenges] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => { fetchEntries(); }, []);

  const fetchEntries = async () => {
    try {
      const res = await fetch("/api/journal");
      setEntries(await res.json());
    } catch { /* offline */ }
  };

  const saveEntry = async () => {
    setSaving(true);
    await fetch("/api/journal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mood, energy_level: energy, grooming_done: grooming,
        people_met: peopleMet, practiced, wins, challenges, notes,
      }),
    });
    await fetchEntries();
    setShowForm(false);
    setMood("okay"); setEnergy(3); setGrooming(false);
    setPeopleMet(""); setPracticed(""); setWins(""); setChallenges(""); setNotes("");
    setSaving(false);
  };

  const deleteEntry = async (id: number) => {
    if (!confirm("Delete this entry?")) return;
    await fetch("/api/journal", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    setEntries(entries.filter((e) => e.id !== id));
  };

  const today = new Date().toISOString().split("T")[0];
  const hasToday = entries.some((e) => String(e.entry_date).split("T")[0] === today);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Daily Journal</h1>
          <p className="mt-2 text-muted">Track your day — mood, grooming, people, wins.</p>
        </div>
        {!hasToday && (
          <button onClick={() => setShowForm(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">
            + Today&apos;s Entry
          </button>
        )}
      </div>

      {showForm && (
        <div className="mb-8 rounded-xl border border-accent/20 bg-surface p-5">
          <h2 className="mb-4 text-lg font-semibold">How was today?</h2>
          <div className="space-y-4">
            <div>
              <label className="mb-2 block text-sm font-medium">Mood</label>
              <div className="flex gap-2">
                {MOODS.map((m) => (
                  <button key={m.value} onClick={() => setMood(m.value)}
                    className={`flex-1 rounded-lg py-3 text-center transition-colors ${mood === m.value ? "bg-accent text-white" : "bg-[var(--background)] text-muted"}`}>
                    <span className="text-xl">{m.emoji}</span>
                    <span className="mt-1 block text-xs">{m.label}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium">Energy Level: {energy}/5</label>
              <input type="range" min="1" max="5" value={energy} onChange={(e) => setEnergy(Number(e.target.value))} className="w-full" />
            </div>

            <label className="flex items-center gap-3 rounded-lg bg-[var(--background)] p-3">
              <input type="checkbox" checked={grooming} onChange={(e) => setGrooming(e.target.checked)} className="size-5 rounded" />
              <span className="text-sm font-medium">Completed daily grooming checklist</span>
            </label>

            <div>
              <label className="mb-1 block text-sm font-medium">People I met / talked to</label>
              <input type="text" value={peopleMet} onChange={(e) => setPeopleMet(e.target.value)} placeholder="e.g., Sunil bhai at coffee, Navin bhai at gym..." className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm focus:border-accent focus:outline-none" />
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">What I practiced today</label>
              <input type="text" value={practiced} onChange={(e) => setPracticed(e.target.value)} placeholder="e.g., Smiled first, no complaints, slow speech..." className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm focus:border-accent focus:outline-none" />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-sm font-medium text-emerald-500">Wins</label>
                <textarea value={wins} onChange={(e) => setWins(e.target.value)} rows={2} placeholder="What went well today?" className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-red-400">Challenges</label>
                <textarea value={challenges} onChange={(e) => setChallenges(e.target.value)} rows={2} placeholder="What was hard today?" className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm focus:border-accent focus:outline-none" />
              </div>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium">Notes</label>
              <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} placeholder="Anything else..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm focus:border-accent focus:outline-none" />
            </div>

            <div className="flex justify-end gap-3">
              <button onClick={() => setShowForm(false)} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted">Cancel</button>
              <button onClick={saveEntry} disabled={saving} className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-50">
                {saving ? "Saving..." : "Save Entry"}
              </button>
            </div>
          </div>
        </div>
      )}

      {entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No journal entries yet</p>
          <p className="mt-1 text-sm text-muted">Start logging your daily progress.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {entries.map((e) => {
            const moodInfo = MOODS.find((m) => m.value === e.mood) || MOODS[2];
            return (
              <div key={e.id} className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{moodInfo.emoji}</span>
                    <div>
                      <p className="font-semibold">{new Date(e.entry_date).toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "short", year: "numeric" })}</p>
                      <p className="text-xs text-muted">Energy: {"⚡".repeat(e.energy_level || 3)}{"·".repeat(5 - (e.energy_level || 3))} {e.grooming_done ? "✓ Groomed" : ""}</p>
                    </div>
                  </div>
                  <button onClick={() => deleteEntry(e.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100">✕</button>
                </div>
                <div className="grid gap-3 text-sm sm:grid-cols-2">
                  {e.people_met && <div><strong className="text-muted">People:</strong> {e.people_met}</div>}
                  {e.practiced && <div><strong className="text-muted">Practiced:</strong> {e.practiced}</div>}
                  {e.wins && <div><strong className="text-emerald-500">Wins:</strong> {e.wins}</div>}
                  {e.challenges && <div><strong className="text-red-400">Challenges:</strong> {e.challenges}</div>}
                </div>
                {e.notes && <p className="mt-2 text-xs italic text-muted">{e.notes}</p>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
