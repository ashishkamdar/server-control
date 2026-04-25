"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface FollowUp { id: number; contact_name: string; related_project: string; action: string; due_date: string; done: boolean; }
interface Project { id: number; client_name: string; project_name: string; status: string; next_step: string; cost: string; }
interface JournalEntry { id: number; entry_date: string; }
interface RevenueEntry { type: string; amount: number; }

export default function TodayPage() {
  const [followUps, setFollowUps] = useState<FollowUp[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [hasJournal, setHasJournal] = useState(false);
  const [revenue, setRevenue] = useState({ income: 0, expense: 0 });
  const [groomingDone, setGroomingDone] = useState(false);

  useEffect(() => {
    const today = new Date().toISOString().split("T")[0];

    fetch("/api/follow-ups").then(r => r.json()).then((data: FollowUp[]) => {
      setFollowUps(data.filter(f => !f.done && String(f.due_date).split("T")[0] <= today));
    }).catch(() => {});

    fetch("/api/projects").then(r => r.json()).then((data: Project[]) => {
      setProjects(data.filter(p => ["in-progress", "blocked", "quoted"].includes(p.status)));
    }).catch(() => {});

    fetch("/api/journal").then(r => r.json()).then((data: JournalEntry[]) => {
      setHasJournal(data.some(j => String(j.entry_date).split("T")[0] === today));
    }).catch(() => {});

    fetch("/api/revenue").then(r => r.json()).then((data: RevenueEntry[]) => {
      setRevenue({
        income: data.filter(e => e.type === "income").reduce((s, e) => s + Number(e.amount), 0),
        expense: data.filter(e => e.type === "expense").reduce((s, e) => s + Number(e.amount), 0),
      });
    }).catch(() => {});

    const checkDate = localStorage.getItem("mmam-checklist-date");
    if (checkDate === today) {
      const checklist = JSON.parse(localStorage.getItem("mmam-checklist") || "[]");
      setGroomingDone(checklist.length > 0 && checklist.every((c: { checked: boolean }) => c.checked));
    }
  }, []);

  const fmt = (n: number) => new Intl.NumberFormat("en-IN").format(Math.round(n));
  const profit = revenue.income - revenue.expense;
  const today = new Date().toLocaleDateString("en-IN", { weekday: "long", day: "numeric", month: "long", year: "numeric" });

  const markFollowUpDone = async (f: FollowUp) => {
    const outcome = prompt("What happened?") || "Done";
    await fetch("/api/follow-ups", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: f.id, done: true, outcome }) });
    setFollowUps(followUps.filter(x => x.id !== f.id));
  };

  return (
    <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Today</h1>
        <p className="mt-1 text-muted">{today}</p>
      </div>

      {/* Priority 1: Follow-ups due */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-red-500 text-xs font-bold text-white">1</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Follow Up NOW</h2>
        </div>
        {followUps.length === 0 ? (
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-center text-sm text-emerald-500">All caught up. No overdue follow-ups.</div>
        ) : (
          <div className="space-y-2">
            {followUps.map(f => (
              <div key={f.id} className="flex items-center justify-between rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3">
                <div>
                  <p className="text-sm font-semibold">{f.contact_name}</p>
                  <p className="text-xs text-red-400">{f.action}</p>
                </div>
                <button onClick={() => markFollowUpDone(f)} className="rounded-lg bg-emerald-500/15 px-3 py-1.5 text-xs font-semibold text-emerald-500 active:scale-95">Done</button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Priority 2: Collect money */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-accent text-xs font-bold text-white">2</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Collect Money</h2>
        </div>
        <div className="space-y-2">
          {projects.filter(p => p.cost && p.status !== "blocked").map(p => (
            <div key={p.id} className="rounded-xl border border-accent/20 bg-accent/5 px-4 py-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">{p.client_name}</span>
                <span className="font-mono text-sm font-bold text-emerald-500">{p.cost}</span>
              </div>
              <p className="text-xs text-accent">{p.next_step}</p>
            </div>
          ))}
          {projects.filter(p => p.cost && p.status !== "blocked").length === 0 && (
            <div className="rounded-xl border border-border bg-surface p-4 text-center text-sm text-muted">No pending collections right now.</div>
          )}
        </div>
      </div>

      {/* Priority 3: Unblock stuck projects */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-red-400 text-xs font-bold text-white">3</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Unblock Projects</h2>
        </div>
        {projects.filter(p => p.status === "blocked").map(p => (
          <div key={p.id} className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold">{p.client_name}</span>
              <span className="rounded-md bg-red-500/15 px-2 py-0.5 text-xs font-medium text-red-400">Blocked</span>
            </div>
            <p className="mt-1 text-xs text-muted">{p.project_name}</p>
            <p className="mt-1 text-xs text-accent">{p.next_step}</p>
          </div>
        ))}
      </div>

      {/* Priority 4: Daily habits */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-blue-400 text-xs font-bold text-white">4</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Daily Habits</h2>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          <Link href="/personality" className={`rounded-xl border px-4 py-3 text-sm transition-colors ${groomingDone ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-500" : "border-accent/20 bg-accent/5 text-accent"}`}>
            {groomingDone ? "✓ Grooming checklist done" : "→ Complete grooming checklist"}
          </Link>
          <Link href="/journal" className={`rounded-xl border px-4 py-3 text-sm transition-colors ${hasJournal ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-500" : "border-accent/20 bg-accent/5 text-accent"}`}>
            {hasJournal ? "✓ Journal entry logged" : "→ Write today's journal"}
          </Link>
          <Link href="/motivation" className="rounded-xl border border-border bg-surface px-4 py-3 text-sm text-muted hover:border-accent/20">
            → Read a motivation card
          </Link>
          <Link href="/pipeline" className="rounded-xl border border-border bg-surface px-4 py-3 text-sm text-muted hover:border-accent/20">
            → Add a new lead to pipeline
          </Link>
        </div>
      </div>

      {/* Priority 5: Talk to people */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-purple-400 text-xs font-bold text-white">5</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Talk to 3 People</h2>
        </div>
        <div className="rounded-xl border border-border bg-surface p-4">
          <p className="text-sm text-muted">At gymkhana today, have a meaningful conversation with at least 3 people. Ask about their business. Listen more than you talk. Log it in your <Link href="/journal" className="text-accent hover:underline">journal</Link> tonight.</p>
        </div>
      </div>

      {/* Money snapshot */}
      <div className="mb-6">
        <div className="mb-3 flex items-center gap-2">
          <span className="flex size-6 items-center justify-center rounded-full bg-emerald-500 text-xs font-bold text-white">₹</span>
          <h2 className="text-sm font-bold uppercase tracking-wide">Money Snapshot</h2>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <div className="rounded-xl border border-border bg-surface p-3 text-center">
            <p className="font-mono text-lg font-bold text-emerald-500">₹{fmt(revenue.income)}</p>
            <p className="text-xs text-muted">Income</p>
          </div>
          <div className="rounded-xl border border-border bg-surface p-3 text-center">
            <p className="font-mono text-lg font-bold text-red-400">₹{fmt(revenue.expense)}</p>
            <p className="text-xs text-muted">Expenses</p>
          </div>
          <div className="rounded-xl border border-border bg-surface p-3 text-center">
            <p className={`font-mono text-lg font-bold ${profit >= 0 ? "text-emerald-500" : "text-red-400"}`}>₹{fmt(profit)}</p>
            <p className="text-xs text-muted">Profit</p>
          </div>
        </div>
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-2 gap-2 text-center text-xs sm:grid-cols-4">
        <Link href="/gymkhana" className="rounded-lg border border-border bg-surface py-3 text-muted hover:border-accent/20 hover:text-accent">Gymkhana</Link>
        <Link href="/approach" className="rounded-lg border border-border bg-surface py-3 text-muted hover:border-accent/20 hover:text-accent">Approach</Link>
        <Link href="/event-prep" className="rounded-lg border border-border bg-surface py-3 text-muted hover:border-accent/20 hover:text-accent">Event Prep</Link>
        <Link href="/whatsapp" className="rounded-lg border border-border bg-surface py-3 text-muted hover:border-accent/20 hover:text-accent">WhatsApp</Link>
      </div>
    </div>
  );
}
