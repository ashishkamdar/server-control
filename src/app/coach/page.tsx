"use client";

import { useEffect, useState } from "react";

interface CoachingEntry {
  id: number;
  question: string;
  answer: string;
  category: string;
  created_at: string;
}

const CATEGORIES = ["General", "Personality", "Business", "Grooming", "Body Language", "Speech", "Strategy", "Pricing", "Client Approach"];

export default function CoachPage() {
  const [entries, setEntries] = useState<CoachingEntry[]>([]);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [category, setCategory] = useState("General");
  const [step, setStep] = useState<"ask" | "paste" | "confirm">("ask");
  const [saving, setSaving] = useState(false);
  const [askingAI, setAskingAI] = useState(false);
  const [filter, setFilter] = useState("All");

  useEffect(() => {
    fetchEntries();
  }, []);

  const fetchEntries = async () => {
    try {
      const res = await fetch("/api/coaching");
      const data = await res.json();
      setEntries(data);
    } catch {
      // offline — will retry
    }
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setAnswer(text);
    } catch {
      // clipboard denied
    }
  };

  const saveEntry = async () => {
    if (!question.trim() || !answer.trim()) return;
    setSaving(true);
    try {
      await fetch("/api/coaching", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: question.trim(), answer: answer.trim(), category }),
      });
      await fetchEntries();
      setQuestion("");
      setAnswer("");
      setCategory("General");
      setStep("ask");
    } catch {
      alert("Failed to save. Check your connection.");
    } finally {
      setSaving(false);
    }
  };

  const deleteEntry = async (id: number) => {
    if (!confirm("Delete this entry?")) return;
    await fetch("/api/coaching", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    setEntries(entries.filter((e) => e.id !== id));
  };

  const filtered = filter === "All" ? entries : entries.filter((e) => e.category === filter);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Coach</h1>
        <p className="mt-2 text-muted">
          Ask AI directly or paste from claude.ai → saved forever in your database.
        </p>
      </div>

      {/* Workflow steps */}
      <div className="mb-8 rounded-xl border border-border bg-surface p-5">
        {/* Step indicators */}
        <div className="mb-5 flex items-center gap-2">
          {[
            { id: "ask" as const, label: "1. Your Question" },
            { id: "paste" as const, label: "2. Paste Answer" },
            { id: "confirm" as const, label: "3. Confirm & Save" },
          ].map((s, i) => (
            <div key={s.id} className="flex items-center gap-2">
              {i > 0 && <div className="h-px w-4 bg-border sm:w-8" />}
              <button
                onClick={() => setStep(s.id)}
                className={`rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
                  step === s.id ? "bg-accent text-white" : "bg-surface-hover text-muted"
                }`}
              >
                {s.label}
              </button>
            </div>
          ))}
        </div>

        {/* Step 1: Question */}
        {step === "ask" && (
          <div>
            <label className="mb-2 block text-sm font-medium">What did you ask Claude?</label>
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              rows={3}
              placeholder="e.g., How should I approach a textile exporter for custom software?"
              className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
            />
            <div className="mt-3">
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="mb-3 rounded-lg border border-border bg-[var(--background)] px-3 py-2 text-sm focus:border-accent focus:outline-none"
              >
                {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              <div className="flex gap-2">
                <button
                  onClick={async () => {
                    if (!question.trim()) return;
                    const provider = localStorage.getItem("mmam-provider") || "gemini";
                    const apiKey = provider === "gemini" ? localStorage.getItem("mmam-gemini-key") || "" : localStorage.getItem("mmam-api-key") || "";
                    if (!apiKey) { alert("Set your API key in Settings first"); return; }
                    setAskingAI(true);
                    setAnswer("");
                    setStep("paste");
                    try {
                      const systemPrompt = localStorage.getItem("mmam-system-prompt") || "";
                      const res = await fetch("/api/chat", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ messages: [{ role: "user", content: question }], apiKey, provider, systemPrompt }),
                      });
                      const reader = res.body?.getReader();
                      const decoder = new TextDecoder();
                      let full = "";
                      if (reader) {
                        while (true) {
                          const { done, value } = await reader.read();
                          if (done) break;
                          full += decoder.decode(value, { stream: true });
                          setAnswer(full);
                        }
                      }
                    } catch { setAnswer("Error — check API key in Settings"); }
                    finally { setAskingAI(false); }
                  }}
                  disabled={!question.trim() || askingAI}
                  className="flex-1 rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40"
                >
                  {askingAI ? "Thinking..." : "Ask AI & Save"}
                </button>
                <button
                  onClick={() => setStep("paste")}
                  disabled={!question.trim()}
                  className="rounded-lg border border-border px-4 py-2.5 text-sm font-medium text-muted hover:text-[var(--foreground)] disabled:opacity-40"
                >
                  Paste manually →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Step 2: Paste Answer */}
        {step === "paste" && (
          <div>
            <div className="mb-3 rounded-lg bg-surface-hover p-3">
              <p className="text-xs text-muted">Your question:</p>
              <p className="mt-1 text-sm font-medium">{question}</p>
            </div>
            <div className="mb-2 flex items-center justify-between">
              <label className="text-sm font-medium">Claude&apos;s Response</label>
              <button
                onClick={pasteFromClipboard}
                className="flex items-center gap-1.5 rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0 0 13.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 0 1-.75.75H9.75a.75.75 0 0 1-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 0 1-2.25 2.25H6.75A2.25 2.25 0 0 1 4.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 0 1 1.927-.184" />
                </svg>
                Paste from Clipboard
              </button>
            </div>
            <textarea
              value={answer}
              onChange={(e) => setAnswer(e.target.value)}
              rows={8}
              placeholder="Paste Claude's response here..."
              className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm leading-relaxed placeholder:text-muted focus:border-accent focus:outline-none"
            />
            <div className="mt-3 flex justify-between">
              <button onClick={() => setStep("ask")} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted hover:text-[var(--foreground)]">
                ← Back
              </button>
              <button
                onClick={() => setStep("confirm")}
                disabled={!answer.trim()}
                className="rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40"
              >
                Review →
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Confirm */}
        {step === "confirm" && (
          <div>
            <div className="mb-4 rounded-lg bg-surface-hover p-4">
              <div className="mb-1 flex items-center gap-2">
                <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">{category}</span>
              </div>
              <p className="mt-2 text-sm font-medium">Q: {question}</p>
              <div className="mt-3 max-h-60 overflow-y-auto rounded-lg bg-[var(--background)] p-3">
                <p className="whitespace-pre-wrap text-sm leading-relaxed text-muted">{answer}</p>
              </div>
            </div>
            <div className="flex justify-between">
              <button onClick={() => setStep("paste")} className="rounded-lg border border-border px-4 py-2.5 text-sm text-muted hover:text-[var(--foreground)]">
                ← Edit
              </button>
              <button
                onClick={saveEntry}
                disabled={saving}
                className="rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
              >
                {saving ? "Saving..." : "Confirm & Save to Database"}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Saved entries */}
      <div>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Saved Coaching ({entries.length})</h2>
        </div>

        <div className="mb-4 flex flex-wrap gap-2">
          <button onClick={() => setFilter("All")} className={`rounded-full px-3 py-1.5 text-xs font-medium ${filter === "All" ? "bg-accent text-white" : "bg-surface text-muted"}`}>All</button>
          {CATEGORIES.map((c) => (
            <button key={c} onClick={() => setFilter(c)} className={`rounded-full px-3 py-1.5 text-xs font-medium ${filter === c ? "bg-accent text-white" : "bg-surface text-muted"}`}>{c}</button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border py-16 text-center">
            <p className="text-sm text-muted">No coaching entries yet. Start by asking Claude something above.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {filtered.map((e) => (
              <div key={e.id} className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">{e.category}</span>
                    <span className="text-xs text-muted">{new Date(e.created_at).toLocaleDateString()}</span>
                  </div>
                  <button onClick={() => deleteEntry(e.id)} className="rounded p-1 text-muted opacity-0 hover:text-red-400 group-hover:opacity-100">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-4">
                      <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
                    </svg>
                  </button>
                </div>
                <p className="text-sm font-semibold">Q: {e.question}</p>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-muted">{e.answer}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
