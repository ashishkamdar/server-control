"use client";

import { useEffect, useState } from "react";

interface Suggestion {
  id: number;
  category: string;
  content: string;
  source: string;
  created_at: string;
}

const CATEGORIES = ["All", "Personality", "Business", "Technical", "Strategy", "Networking"];

export default function SuggestionsPage() {
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [filter, setFilter] = useState("All");
  const [search, setSearch] = useState("");

  useEffect(() => {
    fetch("/api/suggestions").then(r => r.json()).then(setSuggestions).catch(() => {});
  }, []);

  const filtered = suggestions.filter((s) => {
    const matchesCategory = filter === "All" || s.category === filter;
    const matchesSearch = s.content.toLowerCase().includes(search.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const [showAdd, setShowAdd] = useState(false);
  const [newContent, setNewContent] = useState("");
  const [newCategory, setNewCategory] = useState("Strategy");

  const deleteSuggestion = async (id: number) => {
    await fetch("/api/suggestions", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) });
    setSuggestions(suggestions.filter((s) => s.id !== id));
  };

  const addFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setNewContent(text);
    } catch {
      // clipboard access denied — user can type manually
    }
  };

  const saveSuggestion = async () => {
    if (!newContent.trim()) return;
    await fetch("/api/suggestions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: newContent.trim(), category: newCategory, source: "Saved from claude.ai" }),
    });
    const res = await fetch("/api/suggestions");
    setSuggestions(await res.json());
    setNewContent("");
    setShowAdd(false);
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Suggestions</h1>
          <p className="mt-2 text-muted">
            Save advice from claude.ai or anywhere else. Your personal coaching notebook.
          </p>
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="shrink-0 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover"
        >
          + Add
        </button>
      </div>

      {/* Add suggestion form */}
      {showAdd && (
        <div className="mb-6 rounded-xl border border-accent/20 bg-accent/5 p-5">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-sm font-semibold text-accent">Save Advice</p>
            <button
              onClick={addFromClipboard}
              className="flex items-center gap-1.5 rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0 0 13.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 0 1-.75.75H9.75a.75.75 0 0 1-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 0 1-2.25 2.25H6.75A2.25 2.25 0 0 1 4.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 0 1 1.927-.184" />
              </svg>
              Paste from Clipboard
            </button>
          </div>
          <textarea
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            rows={5}
            placeholder="Paste or type advice from claude.ai here..."
            className="mb-3 w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
          />
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2">
              {CATEGORIES.filter((c) => c !== "All").map((cat) => (
                <button
                  key={cat}
                  onClick={() => setNewCategory(cat)}
                  className={`rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                    newCategory === cat ? "bg-accent text-white" : "bg-surface text-muted"
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
            <button
              onClick={saveSuggestion}
              disabled={!newContent.trim()}
              className="shrink-0 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40"
            >
              Save
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center">
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                filter === cat
                  ? "bg-accent text-white"
                  : "bg-surface text-muted hover:bg-surface-hover hover:text-[var(--foreground)]"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="Search suggestions..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-border bg-surface px-4 py-2 text-sm placeholder:text-muted focus:border-accent focus:outline-none sm:ml-auto sm:w-64"
        />
      </div>

      {/* List */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-border bg-surface py-20 text-center">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mb-4 size-12 text-muted">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 18v-5.25m0 0a6.01 6.01 0 0 0 1.5-.189m-1.5.189a6.01 6.01 0 0 1-1.5-.189m3.75 7.478a12.06 12.06 0 0 1-4.5 0m3.75 2.383a14.406 14.406 0 0 1-3 0M14.25 18v-.192c0-.983.658-1.823 1.508-2.316a7.5 7.5 0 1 0-7.517 0c.85.493 1.509 1.333 1.509 2.316V18" />
          </svg>
          <p className="text-lg font-medium">No suggestions yet</p>
          <p className="mt-1 text-sm text-muted">
            Start a chat conversation and save suggestions from there.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((s) => (
            <div
              key={s.id}
              className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30"
            >
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">
                    {s.category}
                  </span>
                  <span className="text-xs text-muted">{new Date(s.created_at).toLocaleDateString("en-IN")}</span>
                </div>
                <button
                  onClick={() => deleteSuggestion(s.id)}
                  className="rounded p-1 text-muted opacity-0 transition-all hover:bg-red-500/15 hover:text-red-400 group-hover:opacity-100"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-4">
                    <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
                  </svg>
                </button>
              </div>
              <p className="whitespace-pre-wrap text-sm leading-relaxed">{s.content}</p>
              {s.source && (
                <p className="mt-2 text-xs text-muted">From: {s.source}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
