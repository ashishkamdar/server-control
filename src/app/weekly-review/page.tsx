"use client";

import { useEffect, useState } from "react";

interface WeeklyReview {
  id: number;
  week_start: string;
  what_worked: string;
  what_didnt: string;
  people_contacted: number;
  projects_progressed: string;
  personality_progress: string;
  goals_next_week: string;
  mood_rating: number;
}

export default function WeeklyReviewPage() {
  const [reviews, setReviews] = useState<WeeklyReview[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ what_worked: "", what_didnt: "", people_contacted: 0, projects_progressed: "", personality_progress: "", goals_next_week: "", mood_rating: 3 });
  const [saving, setSaving] = useState(false);

  useEffect(() => { fetch("/api/weekly-review").then((r) => r.json()).then(setReviews).catch(() => {}); }, []);

  const save = async () => {
    setSaving(true);
    const monday = new Date();
    monday.setDate(monday.getDate() - monday.getDay() + 1);
    await fetch("/api/weekly-review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...form, week_start: monday.toISOString().split("T")[0] }),
    });
    const res = await fetch("/api/weekly-review");
    setReviews(await res.json());
    setShowForm(false);
    setForm({ what_worked: "", what_didnt: "", people_contacted: 0, projects_progressed: "", personality_progress: "", goals_next_week: "", mood_rating: 3 });
    setSaving(false);
  };

  const moodEmoji = (r: number) => ["", "😞", "😔", "😐", "🙂", "😊"][r] || "😐";

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Weekly Review</h1>
          <p className="mt-2 text-muted">Reflect on your week. What worked, what didn&apos;t, goals ahead.</p>
        </div>
        <button onClick={() => setShowForm(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ This Week</button>
      </div>

      {showForm && (
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <h2 className="mb-4 text-lg font-semibold">Week in Review</h2>
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium">Overall mood: {moodEmoji(form.mood_rating)} {form.mood_rating}/5</label>
              <input type="range" min="1" max="5" value={form.mood_rating} onChange={(e) => setForm({ ...form, mood_rating: Number(e.target.value) })} className="w-full" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">People contacted this week</label>
              <input type="number" value={form.people_contacted} onChange={(e) => setForm({ ...form, people_contacted: Number(e.target.value) })} className="w-24 rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-sm font-medium text-emerald-500">What worked well</label>
                <textarea value={form.what_worked} onChange={(e) => setForm({ ...form, what_worked: e.target.value })} rows={3} placeholder="e.g., Smiled first at coffee, got compliment on dressing..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-red-400">What didn&apos;t work</label>
                <textarea value={form.what_didnt} onChange={(e) => setForm({ ...form, what_didnt: e.target.value })} rows={3} placeholder="e.g., Complained about market at dinner, forgot grooming..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Projects progressed</label>
              <textarea value={form.projects_progressed} onChange={(e) => setForm({ ...form, projects_progressed: e.target.value })} rows={2} placeholder="e.g., Olistic confirmed Rs 1L, JSG page updated..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Personality progress</label>
              <textarea value={form.personality_progress} onChange={(e) => setForm({ ...form, personality_progress: e.target.value })} rows={2} placeholder="e.g., Practiced no-complaint day 3 times, better posture..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-accent">Goals for next week</label>
              <textarea value={form.goals_next_week} onChange={(e) => setForm({ ...form, goals_next_week: e.target.value })} rows={2} placeholder="e.g., Follow up Uttambhai Apr 15, collect Olistic payment..." className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowForm(false)} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted">Cancel</button>
              <button onClick={save} disabled={saving} className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-50">{saving ? "Saving..." : "Save Review"}</button>
            </div>
          </div>
        </div>
      )}

      {reviews.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg font-medium">No reviews yet</p>
          <p className="mt-1 text-sm text-muted">Do your first weekly review this Sunday.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {reviews.map((r) => (
            <div key={r.id} className="rounded-xl border border-border bg-surface p-5">
              <div className="mb-3 flex items-center gap-3">
                <span className="text-2xl">{moodEmoji(r.mood_rating)}</span>
                <div>
                  <p className="font-semibold">Week of {new Date(r.week_start).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}</p>
                  <p className="text-xs text-muted">{r.people_contacted} people contacted</p>
                </div>
              </div>
              <div className="grid gap-3 text-sm sm:grid-cols-2">
                {r.what_worked && <div><strong className="text-emerald-500">Worked:</strong> {r.what_worked}</div>}
                {r.what_didnt && <div><strong className="text-red-400">Didn&apos;t work:</strong> {r.what_didnt}</div>}
                {r.projects_progressed && <div><strong className="text-muted">Projects:</strong> {r.projects_progressed}</div>}
                {r.personality_progress && <div><strong className="text-muted">Personality:</strong> {r.personality_progress}</div>}
              </div>
              {r.goals_next_week && (
                <div className="mt-3 rounded-lg bg-accent/5 p-3">
                  <p className="text-xs text-accent"><strong>Goals:</strong> {r.goals_next_week}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
