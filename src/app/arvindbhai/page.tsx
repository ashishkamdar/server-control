"use client";

import { useEffect, useState } from "react";
import { motivationCards } from "@/lib/motivation-cards";

const arvindbhaiCards = motivationCards.filter(c => c.category === "Father-in-Law");

export default function ArvindbhaiPage() {
  const [favs, setFavs] = useState<Set<number>>(new Set());
  const [showFavsOnly, setShowFavsOnly] = useState(false);
  const [shuffled, setShuffled] = useState(false);
  const [search, setSearch] = useState("");

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

  let cards = arvindbhaiCards;
  if (showFavsOnly) cards = cards.filter((c) => favs.has(c.id));
  if (search) cards = cards.filter((c) => c.text.toLowerCase().includes(search.toLowerCase()));
  if (shuffled) cards = [...cards].sort(() => Math.random() - 0.5);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight">Arvindbhai&apos;s Wisdom</h1>
        <p className="mt-2 text-muted">
          {arvindbhaiCards.length} quotes from your father-in-law. Daily wisdom he shares every morning.
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
          ♥ Favourites
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

      {/* Search */}
      <div className="mb-6">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search quotes..."
          className="w-full rounded-xl border border-border bg-surface px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
        />
      </div>

      {/* Cards */}
      {cards.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border py-16 text-center">
          <p className="text-lg">No quotes found</p>
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
                <span className="text-xs font-medium text-accent">— Arvindbhai</span>
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
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 text-center text-xs text-muted">
        {cards.length} quotes showing · From Hetal Pappa Arvindbhai&apos;s daily WhatsApp messages
      </div>
    </div>
  );
}
