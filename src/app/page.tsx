"use client";

import Link from "next/link";
import { useEffect, useState, useMemo } from "react";
import { DailyTips } from "@/components/daily-tips";
import { ProjectsSummary } from "@/components/projects-summary";
import { motivationCards } from "@/lib/motivation-cards";
import { getDailyPowerChecks } from "@/lib/power-checks";

interface FollowUp {
  id: number;
  person_name: string;
  action: string;
  due_date: string;
  status: string;
}

interface PowerCheck {
  id: string;
  label: string;
  done: boolean;
}

export default function Dashboard() {
  const [checks, setChecks] = useState<PowerCheck[]>([]);
  const [launched, setLaunched] = useState(false);
  const [dueFollowUp, setDueFollowUp] = useState<FollowUp | null>(null);
  const [suggestionsCount, setSuggestionsCount] = useState(0);
  const [chatCount, setChatCount] = useState(0);
  const [hasApiKey, setHasApiKey] = useState(false);
  const [powerRound, setPowerRound] = useState(0);
  const [seenIds, setSeenIds] = useState<Set<string>>(new Set());
  const [totalChecked, setTotalChecked] = useState(0);
  const [noMoreChecks, setNoMoreChecks] = useState(false);

  // Pick one motivation card per day
  const todaysCard = useMemo(() => {
    const dayOfYear = Math.floor(
      (Date.now() - new Date(new Date().getFullYear(), 0, 0).getTime()) / 86400000
    );
    return motivationCards[dayOfYear % motivationCards.length];
  }, []);

  useEffect(() => {
    // Restore morning launch state for today
    const today = new Date().toDateString();
    const savedDate = localStorage.getItem("mmam-launch-date");

    if (savedDate === today) {
      const savedChecks = JSON.parse(localStorage.getItem("mmam-launch-checks") || "[]");
      const savedRound = parseInt(localStorage.getItem("mmam-launch-round") || "0", 10);
      const savedSeenIds: string[] = JSON.parse(localStorage.getItem("mmam-launch-seen") || "[]");
      const savedTotal = parseInt(localStorage.getItem("mmam-launch-total-checked") || "0", 10);
      setChecks(savedChecks);
      setPowerRound(savedRound);
      setSeenIds(new Set(savedSeenIds));
      setTotalChecked(savedTotal);
      setLaunched(localStorage.getItem("mmam-launched") === "true");
    } else {
      // New day — pick fresh power checks for today
      const todaysChecks = getDailyPowerChecks();
      const fresh = todaysChecks.map((c) => ({ id: c.id, label: c.label, done: false }));
      const freshIds = new Set(todaysChecks.map((c) => c.id));
      setChecks(fresh);
      setPowerRound(0);
      setSeenIds(freshIds);
      setTotalChecked(0);
      setNoMoreChecks(false);
      setLaunched(false);
      localStorage.setItem("mmam-launch-date", today);
      localStorage.setItem("mmam-launch-checks", JSON.stringify(fresh));
      localStorage.setItem("mmam-launch-round", "0");
      localStorage.setItem("mmam-launch-seen", JSON.stringify([...freshIds]));
      localStorage.setItem("mmam-launch-total-checked", "0");
      localStorage.removeItem("mmam-launched");
    }

    // Fetch one due follow-up
    fetch("/api/follow-ups")
      .then((r) => r.json())
      .then((data: FollowUp[]) => {
        const todayStr = new Date().toISOString().split("T")[0];
        const due = data.find(
          (f) =>
            f.status !== "completed" &&
            f.due_date &&
            f.due_date.split("T")[0] <= todayStr
        );
        if (due) setDueFollowUp(due);
      })
      .catch(() => {});

    // Dashboard stats
    fetch("/api/suggestions").then(r => r.json()).then(d => setSuggestionsCount(d.length)).catch(() => {});
    fetch("/api/chat-sessions").then(r => r.json()).then(d => setChatCount(d.length)).catch(() => {});
    const provider = localStorage.getItem("mmam-provider") || "gemini";
    const key = provider === "gemini" ? localStorage.getItem("mmam-gemini-key") : localStorage.getItem("mmam-api-key");
    setHasApiKey(!!key);
  }, []);

  const toggleCheck = (id: string) => {
    const wasChecked = checks.find((c) => c.id === id)?.done;
    const updated = checks.map((c) =>
      c.id === id ? { ...c, done: !c.done } : c
    );
    setChecks(updated);
    localStorage.setItem("mmam-launch-checks", JSON.stringify(updated));

    // Track total across all rounds
    const newTotal = totalChecked + (wasChecked ? -1 : 1);
    setTotalChecked(newTotal);
    localStorage.setItem("mmam-launch-total-checked", String(newTotal));
  };

  const allChecked = checks.length > 0 && checks.every((c) => c.done);

  const handleLaunch = () => {
    setLaunched(true);
    localStorage.setItem("mmam-launched", "true");
  };

  const handleNextSet = () => {
    const nextRound = powerRound + 1;
    const nextChecks = getDailyPowerChecks(new Date(), nextRound, seenIds);

    if (nextChecks.length === 0) {
      setNoMoreChecks(true);
      return;
    }

    const fresh = nextChecks.map((c) => ({ id: c.id, label: c.label, done: false }));
    const newSeenIds = new Set([...seenIds, ...nextChecks.map((c) => c.id)]);

    setChecks(fresh);
    setPowerRound(nextRound);
    setSeenIds(newSeenIds);
    setNoMoreChecks(false);

    localStorage.setItem("mmam-launch-checks", JSON.stringify(fresh));
    localStorage.setItem("mmam-launch-round", String(nextRound));
    localStorage.setItem("mmam-launch-seen", JSON.stringify([...newSeenIds]));
  };

  const completedCount = checks.filter((c) => c.done).length;

  // Morning Launch — the first thing you see
  if (!launched) {
    return (
      <div className="mx-auto max-w-lg px-6 py-10">
        {/* Motivation card */}
        <div className="mb-8 rounded-2xl border border-accent/30 bg-accent/5 p-6">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-accent">
            Today&apos;s Fuel
          </p>
          <p className="text-lg font-medium leading-relaxed">
            &ldquo;{todaysCard.text}&rdquo;
          </p>
          {todaysCard.author && (
            <p className="mt-3 text-sm text-muted">— {todaysCard.author}</p>
          )}
        </div>

        {/* 5 Power Checks */}
        <div className="mb-8">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-bold">Morning Power Check</h2>
            <span className="font-mono text-sm font-bold text-accent">
              {completedCount}/{checks.length}
            </span>
          </div>

          <div className="space-y-3">
            {checks.map((check) => (
              <button
                key={check.id}
                onClick={() => toggleCheck(check.id)}
                className={`flex w-full items-center gap-4 rounded-xl border p-4 text-left transition-all ${
                  check.done
                    ? "border-emerald-500/30 bg-emerald-500/5"
                    : "border-border bg-surface hover:border-accent/30"
                }`}
              >
                <div
                  className={`flex size-7 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                    check.done
                      ? "border-emerald-500 bg-emerald-500"
                      : "border-border"
                  }`}
                >
                  {check.done && (
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="white"
                      strokeWidth="3"
                      className="size-4"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M4.5 12.75l6 6 9-13.5"
                      />
                    </svg>
                  )}
                </div>
                <span
                  className={`text-sm font-medium ${
                    check.done ? "text-muted line-through" : ""
                  }`}
                >
                  {check.label}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Due follow-up */}
        {dueFollowUp && (
          <div className="mb-8 rounded-xl border border-sky-400/30 bg-sky-400/5 p-4">
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-sky-400">
              Follow-up Due
            </p>
            <p className="text-sm font-medium">{dueFollowUp.person_name}</p>
            <p className="mt-1 text-sm text-muted">{dueFollowUp.action}</p>
            <Link
              href="/follow-ups"
              className="mt-2 inline-block text-xs font-medium text-accent hover:text-accent-hover"
            >
              Open Follow-ups →
            </Link>
          </div>
        )}

        {/* Total progress across rounds */}
        {powerRound > 0 && totalChecked > 0 && (
          <div className="mb-4 text-center">
            <span className="text-sm font-medium text-muted">
              {totalChecked} tips absorbed today across {powerRound + 1} sets
            </span>
          </div>
        )}

        {/* Action buttons */}
        <div className="flex gap-3">
          {/* More Tips */}
          {!noMoreChecks ? (
            <button
              onClick={handleNextSet}
              className="flex-1 rounded-xl border border-accent/30 bg-accent/5 py-4 text-center text-sm font-bold text-accent transition-all hover:border-accent/50 hover:bg-accent/10"
            >
              More Tips
            </button>
          ) : (
            <div className="flex-1 rounded-xl border border-emerald-500/20 bg-emerald-500/5 py-4 text-center text-sm font-medium text-emerald-500">
              You&apos;ve seen them all — go conquer!
            </div>
          )}

          {/* Done — go to dashboard */}
          <button
            onClick={handleLaunch}
            className={`flex-1 rounded-xl py-4 text-center text-sm font-bold transition-all ${
              allChecked
                ? "bg-accent text-white hover:bg-accent-hover"
                : "bg-accent/80 text-white hover:bg-accent"
            }`}
          >
            {allChecked ? "I'm Ready — Let's Go" : "I'm Done"}
          </button>
        </div>
      </div>
    );
  }

  // Regular dashboard (after launch)
  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      {/* Power Check reset button */}
      <button
        onClick={() => setLaunched(false)}
        className="mb-6 flex w-full items-center justify-center gap-2 rounded-xl border border-accent/20 bg-accent/5 p-4 text-center transition-colors hover:border-accent/40 hover:bg-accent/10"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5 text-accent">
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.362 5.214A8.252 8.252 0 0 1 12 21 8.25 8.25 0 0 1 6.038 7.047 8.287 8.287 0 0 0 9 9.601a8.983 8.983 0 0 1 3.361-6.867 8.21 8.21 0 0 0 3 2.48Z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 18a3.75 3.75 0 0 0 .495-7.468 5.99 5.99 0 0 0-1.925 3.547 5.975 5.975 0 0 1-2.133-1.001A3.75 3.75 0 0 0 12 18Z" />
        </svg>
        <span className="text-sm font-semibold text-accent">
          {allChecked ? "Recharge — You've got this" : `Power Check (${completedCount}/{checks.length})`}
        </span>
      </button>

      <div className="mb-10">
        <h1 className="text-3xl font-bold tracking-tight">
          Welcome back, Ashish
        </h1>
        <p className="mt-2 text-muted">
          Your personal AI coach for building a millionaire-level software business.
        </p>
      </div>

      {/* Quick stats */}
      <div className="mb-10 grid gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-border bg-surface p-6">
          <p className="text-sm font-medium text-muted">Suggestions Saved</p>
          <p className="mt-2 text-3xl font-bold font-mono text-accent">{suggestionsCount}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-6">
          <p className="text-sm font-medium text-muted">Chat Sessions</p>
          <p className="mt-2 text-3xl font-bold font-mono text-accent">{chatCount}</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-6">
          <p className="text-sm font-medium text-muted">AI Connected</p>
          <p className={`mt-2 text-3xl font-bold ${hasApiKey ? "text-emerald-500" : "text-red-400"}`}>
            {hasApiKey ? "Yes" : "No"}
          </p>
        </div>
      </div>

      {/* Quick actions */}
      <div className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">Quick Actions</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Link
            href="/chat"
            className="group flex items-center gap-4 rounded-xl border border-border bg-surface p-6 transition-colors hover:border-accent/50 hover:bg-surface-hover"
          >
            <div className="flex size-12 items-center justify-center rounded-lg bg-accent/15 text-accent transition-colors group-hover:bg-accent/25">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-6">
                <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 0 1-.825-.242m9.345-8.334a2.126 2.126 0 0 0-.476-.095 48.64 48.64 0 0 0-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0 0 11.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155" />
              </svg>
            </div>
            <div>
              <p className="font-semibold">Start a Conversation</p>
              <p className="text-sm text-muted">Discuss strategy, get advice, make decisions</p>
            </div>
          </Link>

          <Link
            href="/suggestions"
            className="group flex items-center gap-4 rounded-xl border border-border bg-surface p-6 transition-colors hover:border-accent/50 hover:bg-surface-hover"
          >
            <div className="flex size-12 items-center justify-center rounded-lg bg-accent/15 text-accent transition-colors group-hover:bg-accent/25">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-6">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 0 0 1.5-.189m-1.5.189a6.01 6.01 0 0 1-1.5-.189m3.75 7.478a12.06 12.06 0 0 1-4.5 0m3.75 2.383a14.406 14.406 0 0 1-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 1 0-7.517 0c.85.493 1.509 1.333 1.509 2.316V18" />
              </svg>
            </div>
            <div>
              <p className="font-semibold">View Suggestions</p>
              <p className="text-sm text-muted">Browse saved advice and action items</p>
            </div>
          </Link>

          {!hasApiKey && (
            <Link
              href="/settings"
              className="group flex items-center gap-4 rounded-xl border border-red-500/30 bg-surface p-6 transition-colors hover:border-red-500/50 hover:bg-surface-hover sm:col-span-2"
            >
              <div className="flex size-12 items-center justify-center rounded-lg bg-red-500/15 text-red-400">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-6">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
                </svg>
              </div>
              <div>
                <p className="font-semibold text-red-400">Set Up API Key</p>
                <p className="text-sm text-muted">Add your Gemini API key in Settings to enable AI features</p>
              </div>
            </Link>
          )}
        </div>
      </div>

      {/* Daily Tips */}
      <div className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">Today&apos;s Focus</h2>
        <DailyTips />
      </div>

      {/* Projects Summary */}
      <div className="mb-10">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Active Projects</h2>
          <Link href="/projects" className="text-sm font-medium text-accent hover:text-accent-hover">
            View all →
          </Link>
        </div>
        <ProjectsSummary />
      </div>

      {/* Focus areas */}
      <div>
        <h2 className="mb-4 text-lg font-semibold">Your Focus Areas</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { title: "Grooming & Style", desc: "Dress, personal care, and looking the part" },
            { title: "Body Language & Posture", desc: "Walk, stand, and sit like a leader" },
            { title: "Speech & Communication", desc: "What you say and how you say it" },
            { title: "Personality & Aura", desc: "Be magnetic — the person everyone remembers" },
            { title: "Client Acquisition", desc: "Win high-value clients from your community" },
            { title: "Business Strategy", desc: "Pricing, positioning, portfolio, and growth" },
          ].map((area) => (
            <div key={area.title} className="rounded-xl border border-border bg-surface p-5">
              <p className="font-medium">{area.title}</p>
              <p className="mt-1 text-sm text-muted">{area.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
