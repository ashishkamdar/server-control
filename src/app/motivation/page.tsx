"use client";

import { useEffect, useState } from "react";
import { motivationCards } from "@/lib/motivation-cards";

const CATEGORIES = ["All", "Mindset", "Confidence", "Energy", "Business", "Grooming", "Body Language", "Speech", "Family", "Parenting", "Sports", "Athletics", "Leadership", "Trust", "Habits", "Self-Worth", "Emotions", "Networking", "Money", "Health", "Inner Peace", "Excellence", "Gratitude", "Wealth", "Community", "Action", "Resilience", "Wisdom", "Power"];
// Filter out Father-in-Law cards — they have their own page
const filteredMotivationCards = motivationCards.filter(c => c.category !== "Father-in-Law");

export default function MotivationPage() {
  const [filter, setFilter] = useState("All");
  const [favs, setFavs] = useState<Set<number>>(new Set());
  const [showFavsOnly, setShowFavsOnly] = useState(false);
  const [shuffled, setShuffled] = useState(false);

  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem("mmam-fav-cards") || "[]");
    setFavs(new Set(saved));
  }, []);

  const toggleFav = (id: number) => {
    const next = new Set(favs);
    if (next.has(id)) next.delete(id); else next.add(id);
    setFavs(next);
    localStorage.setItem("mmam-fav-cards", JSON.stringify([...next]));
  };

  let cards = filteredMotivationCards;
  if (filter !== "All") cards = cards.filter((c) => c.category === filter);
  if (showFavsOnly) cards = cards.filter((c) => favs.has(c.id));
  if (shuffled) cards = [...cards].sort(() => Math.random() - 0.5);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight">Motivation</h1>
        <p className="mt-2 text-muted">
          {filteredMotivationCards.length} cards to rebuild you. Read one every morning. Heart the ones that hit hard.
        </p>
      </div>

      {/* Controls */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <button
          onClick={() => setShowFavsOnly(!showFavsOnly)}
          className={`rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            showFavsOnly ? "bg-red-500 text-white" : "bg-surface text-muted"
          }`}
        >
          ♥ Favourites ({favs.size})
        </button>
        <button
          onClick={() => setShuffled(!shuffled)}
          className={`rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
            shuffled ? "bg-accent text-white" : "bg-surface text-muted"
          }`}
        >
          🔀 Shuffle
        </button>
      </div>

      {/* Category pills — scrollable */}
      <div className="mb-6 flex gap-2 overflow-x-auto pb-2">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => { setFilter(cat); setShowFavsOnly(false); }}
            className={`shrink-0 rounded-full px-3 py-1.5 text-xs font-medium transition-colors ${
              filter === cat && !showFavsOnly ? "bg-accent text-white" : "bg-surface text-muted"
            }`}
          >
            {cat} {cat !== "All" ? `(${motivationCards.filter((c) => c.category === cat).length})` : ""}
          </button>
        ))}
      </div>

      {/* Cards */}
      {cards.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg">No cards here yet</p>
          <p className="mt-1 text-sm text-muted">{showFavsOnly ? "Heart some cards first" : "Try a different category"}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {cards.map((card) => (
            <div
              key={card.id}
              className={`group relative rounded-xl border p-5 transition-all ${
                favs.has(card.id) ? "border-accent/30 bg-accent/5" : "border-border bg-surface"
              }`}
            >
              <div className="mb-2 flex items-center justify-between">
                <span className="rounded-md bg-surface-hover px-2 py-0.5 text-xs font-medium text-muted">
                  {card.category}
                </span>
                <button
                  onClick={() => toggleFav(card.id)}
                  className={`rounded-full p-1.5 transition-all ${
                    favs.has(card.id) ? "text-red-500" : "text-muted sm:opacity-0 sm:group-hover:opacity-100"
                  }`}
                >
                  <svg viewBox="0 0 24 24" fill={favs.has(card.id) ? "currentColor" : "none"} stroke="currentColor" strokeWidth="1.5" className="size-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 8.25c0-2.485-2.099-4.5-4.688-4.5-1.935 0-3.597 1.126-4.312 2.733-.715-1.607-2.377-2.733-4.313-2.733C5.1 3.75 3 5.765 3 8.25c0 7.22 9 12 9 12s9-4.78 9-12Z" />
                  </svg>
                </button>
              </div>
              <p className="text-sm leading-relaxed sm:text-base">{card.text}</p>
              {card.author && (
                <p className="mt-2 text-xs font-medium text-accent">— {card.author}</p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 text-center text-xs text-muted">
        {cards.length} cards showing · {favs.size} favourited
      </div>
    </div>
  );
}
