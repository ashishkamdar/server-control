"use client";

import { useState } from "react";

const EVENTS = [
  // Business
  { value: "client-first-meeting", label: "Meeting a Client (First Time)", category: "Business" },
  { value: "client-followup", label: "Follow-up Meeting with Client", category: "Business" },
  { value: "client-demo", label: "Giving a Software Demo", category: "Business" },
  { value: "client-negotiation", label: "Price Negotiation / Deal Closing", category: "Business" },
  { value: "business-lunch", label: "Business Lunch", category: "Business" },
  { value: "networking-event", label: "Networking / Industry Event", category: "Business" },
  { value: "conference", label: "Tech Conference / Seminar", category: "Business" },

  // Social
  { value: "gymkhana-coffee", label: "Morning Coffee at Gymkhana", category: "Social" },
  { value: "gymkhana-sport", label: "After Sports at Gymkhana", category: "Social" },
  { value: "friends-casual", label: "Meeting Friends (Casual)", category: "Social" },
  { value: "friends-drinks", label: "Going for Drinks", category: "Social" },
  { value: "friends-dinner", label: "Dinner with Friends", category: "Social" },
  { value: "group-outing", label: "Group Outing / Day Trip", category: "Social" },

  // Formal
  { value: "formal-dinner", label: "Formal Dinner", category: "Formal" },
  { value: "wedding", label: "Wedding / Reception", category: "Formal" },
  { value: "engagement", label: "Engagement Ceremony", category: "Formal" },
  { value: "birthday-party", label: "Birthday Party", category: "Formal" },
  { value: "anniversary", label: "Anniversary Celebration", category: "Formal" },
  { value: "housewarming", label: "Housewarming / Griha Pravesh", category: "Formal" },

  // Religious / Cultural
  { value: "temple", label: "Temple Visit", category: "Cultural" },
  { value: "puja", label: "Puja / Religious Ceremony", category: "Cultural" },
  { value: "community-event", label: "Community / Samaj Event", category: "Cultural" },
  { value: "drama-show", label: "Cultural Drama / Show", category: "Cultural" },
  { value: "navratri", label: "Navratri / Garba", category: "Cultural" },
  { value: "diwali-party", label: "Diwali Party", category: "Cultural" },

  // Family
  { value: "relatives", label: "Meeting Relatives", category: "Family" },
  { value: "family-dinner", label: "Family Dinner Out", category: "Family" },
  { value: "in-laws", label: "Visiting In-Laws", category: "Family" },
  { value: "family-function", label: "Family Function / Get-together", category: "Family" },

  // Professional
  { value: "bank-meeting", label: "Bank / Financial Meeting", category: "Professional" },
  { value: "lawyer-meeting", label: "Meeting a Lawyer", category: "Professional" },
  { value: "government-office", label: "Government Office Visit", category: "Professional" },
  { value: "doctor-visit", label: "Doctor / Hospital Visit", category: "Professional" },

  // Online
  { value: "video-call-client", label: "Video Call with Client", category: "Online" },
  { value: "video-call-interview", label: "Freelance Video Interview", category: "Online" },
  { value: "webinar-speaker", label: "Speaking at Webinar", category: "Online" },
];

export default function EventPrepPage() {
  const [selectedEvent, setSelectedEvent] = useState("");
  const [activeCategory, setActiveCategory] = useState("Business");
  const [search, setSearch] = useState("");
  const [customNote, setCustomNote] = useState("");
  const [advice, setAdvice] = useState("");
  const [loading, setLoading] = useState(false);

  const getAdvice = async () => {
    if (!selectedEvent) return;
    const provider = localStorage.getItem("mmam-provider") || "gemini";
    const apiKey = provider === "gemini" ? localStorage.getItem("mmam-gemini-key") || "" : localStorage.getItem("mmam-api-key") || "";
    if (!apiKey) { alert("Set API key in Settings first"); return; }

    const event = EVENTS.find((e) => e.value === selectedEvent);
    if (!event) return;

    setLoading(true);
    setAdvice("");

    const prompt = `I am Ashish Kamdar, 51 years old, software developer. I need you to completely prepare me for this event:

**Event:** ${event.label}
**Category:** ${event.category}
${customNote ? `**Additional context:** ${customNote}` : ""}

**Important context about me:**
- I've been told I sometimes project negative energy
- I need to consciously work on being positive, warm, and approachable
- I'm part of a wealthy Kutchi community at Matunga Gymkhana
- I want people to see me as a confident, well-groomed, successful software developer
- I'm 51, average build, Indian male

Give me a COMPLETE preparation guide:

## 1. GROOMING (30 mins before)
- Shower? Yes/No and why
- Shave? Clean shave / trimmed beard / as-is — be specific
- Hair styling — what product, what style
- Skin — moisturizer, sunscreen, anything else
- Cologne — yes/no, how much, where to apply
- Teeth — brush, mouthwash, breath freshener to carry?
- Nails — check?
- Nose/ear hair — check?

## 2. CLOTHES — EXACT OUTFIT
- Top: exact type, color, fit
- Bottom: exact type, color, fit
- Shoes: exact type, color
- Accessories: watch, belt, ring, glasses
- Bag/wallet: what to carry
- What NOT to wear
- Backup plan if weather changes

## 3. BODY LANGUAGE FOR THIS EVENT
- How to enter the room/venue
- How to stand
- How to sit
- What to do with your hands
- Eye contact rules for this event
- Smile intensity — formal events need different smiles than casual
- Personal space rules
- How to greet people (handshake? namaste? hug? depends on event)

## 4. WHAT TO TALK ABOUT
- 3-5 safe topics for this specific event
- Conversation starters specific to this event
- How to keep conversations going
- How to exit conversations gracefully
- How much to talk vs listen (give me a ratio)

## 5. WHAT NOT TO DO
- Specific things to avoid at this type of event
- Topics to never bring up
- Behaviors that will repel people
- Common mistakes people make at this type of event

## 6. ENERGY & VIBE
- What energy to bring — calm confidence? high enthusiasm? quiet strength?
- How to manage if you're feeling low that day
- A mantra or thought to hold in your mind during the event
- How to recover if something goes wrong (awkward moment, spill, etc.)

## 7. PHONE RULES
- When to check phone
- When to keep it away
- What about photos/social media at this event

## 8. BEFORE YOU LEAVE HOME
- Final mirror check — what to look for
- Items to carry (breath freshener, handkerchief, business cards?)
- Mindset exercise (2 minutes)

Be VERY specific. Not "dress well" — tell me exactly what. Not "be positive" — tell me exactly how. I need step-by-step instructions like a manual.`;

    try {
      const systemPrompt = localStorage.getItem("mmam-system-prompt") || "";
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: [{ role: "user", content: prompt }], apiKey, provider, systemPrompt }),
      });

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let full = "";
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          full += decoder.decode(value, { stream: true });
          setAdvice(full);
        }
      }
    } catch {
      setAdvice("Error. Check your API key in Settings.");
    } finally {
      setLoading(false);
    }
  };

  const categories = [...new Set(EVENTS.map((e) => e.category))];

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Event Prep</h1>
        <p className="mt-2 text-muted">
          Select where you&apos;re going → get a complete preparation guide: grooming, clothes, body language, what to say.
        </p>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search... e.g., dinner, wedding, client, drinks"
          className="w-full rounded-xl border border-border bg-surface px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
        />
      </div>

      {/* Category tabs — horizontally scrollable on mobile */}
      <div className="mb-4 flex gap-2 overflow-x-auto pb-2">
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`shrink-0 rounded-full px-4 py-2 text-sm font-medium transition-colors ${
              activeCategory === cat ? "bg-accent text-white" : "bg-surface text-muted hover:text-[var(--foreground)]"
            }`}
          >
            {cat === "Business" ? "💼 Business" : cat === "Social" ? "🍻 Social" : cat === "Formal" ? "🎩 Formal" : cat === "Cultural" ? "🛕 Cultural" : cat === "Family" ? "👨‍👩‍👧‍👦 Family" : cat === "Professional" ? "📋 Professional" : "💻 Online"}
          </button>
        ))}
      </div>

      {/* Event cards — tap to select */}
      <div className="mb-6 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        {EVENTS.filter((e) => search ? e.label.toLowerCase().includes(search.toLowerCase()) : e.category === activeCategory).map((e) => (
          <button
            key={e.value}
            onClick={() => setSelectedEvent(e.value)}
            className={`rounded-xl border p-4 text-left text-sm font-medium transition-all active:scale-95 ${
              selectedEvent === e.value
                ? "border-accent bg-accent/10 text-accent"
                : "border-border bg-surface text-[var(--foreground)] hover:border-accent/30"
            }`}
          >
            {e.label}
          </button>
        ))}
      </div>

      {/* Context + Go button */}
      {selectedEvent && (
        <div className="mb-8 rounded-xl border border-accent/20 bg-accent/5 p-4">
          <p className="mb-3 text-sm font-medium text-accent">
            Preparing for: {EVENTS.find((e) => e.value === selectedEvent)?.label}
          </p>
          <input
            type="text"
            value={customNote}
            onChange={(e) => setCustomNote(e.target.value)}
            placeholder="Any details? e.g., Taj hotel, client is a doctor, evening event..."
            className="mb-3 w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
          />
          <button
            onClick={getAdvice}
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent py-3.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40"
          >
            {loading ? (
              <>
                <svg className="size-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Preparing your guide...
              </>
            ) : (
              "Prepare Me Now"
            )}
          </button>
        </div>
      )}

      {/* Result */}
      {advice ? (
        <div className="rounded-xl border border-border bg-surface p-5 sm:p-6">
          <div className="mb-4 flex items-center gap-2">
            <h2 className="text-lg font-semibold">Your Preparation Guide</h2>
            <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">
              {EVENTS.find((e) => e.value === selectedEvent)?.label}
            </span>
          </div>
          <div className="whitespace-pre-wrap text-sm leading-relaxed">{advice}</div>
          {loading && <span className="ml-1 inline-block size-2 animate-pulse rounded-full bg-accent" />}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border py-20 text-center">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mb-4 size-12 text-muted">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
          </svg>
          <p className="text-lg font-medium">Select an event above</p>
          <p className="mt-1 max-w-sm text-sm text-muted">
            Choose what you&apos;re preparing for and get a complete guide — from grooming to body language to conversation topics.
          </p>
        </div>
      )}
    </div>
  );
}
