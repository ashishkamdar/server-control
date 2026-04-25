"use client";

import { useEffect, useState } from "react";

interface DailyCheckItem {
  id: string;
  category: string;
  item: string;
  checked: boolean;
}

const DAILY_CHECKLIST: Omit<DailyCheckItem, "checked">[] = [
  // Morning Body
  { id: "shower", category: "Body", item: "Shower, use good soap, scrub properly" },
  { id: "deodorant", category: "Body", item: "Apply deodorant/antiperspirant" },
  { id: "cologne", category: "Body", item: "Light cologne — one spray on wrist, one on neck (NOT a bath in it)" },
  { id: "teeth", category: "Body", item: "Brush thoroughly, use mouthwash, check for food in teeth" },
  { id: "nails", category: "Body", item: "Check nails — clean, trimmed, no dirt" },
  { id: "nose-ear", category: "Body", item: "Check nose hair, ear hair — trim if visible" },

  // Hair & Face
  { id: "hair", category: "Face", item: "Hair styled and set — not just combed, STYLED" },
  { id: "beard", category: "Face", item: "Beard/face clean-shaven or neatly trimmed — no in-between" },
  { id: "moisturizer", category: "Face", item: "Apply face moisturizer (prevents that tired/dry look)" },
  { id: "eyebrows", category: "Face", item: "Eyebrows groomed — no unibrow, no wild hairs" },

  // Clothes
  { id: "ironed", category: "Clothes", item: "Clothes ironed — ZERO wrinkles" },
  { id: "fit", category: "Clothes", item: "Clothes fit well — not too loose, not too tight" },
  { id: "shoes", category: "Clothes", item: "Shoes clean and polished" },
  { id: "watch", category: "Clothes", item: "Watch on — a good, clean watch (your signature)" },

  // Energy & Mindset (THE MOST IMPORTANT)
  { id: "smile-mirror", category: "Energy", item: "Look in the mirror and SMILE — practice it. This is your warmest outfit." },
  { id: "no-complain", category: "Energy", item: "ZERO complaints today. Not one. About anything. To anyone." },
  { id: "gratitude", category: "Energy", item: "Name 3 things you're grateful for (out loud, to yourself)" },
  { id: "posture-check", category: "Energy", item: "Shoulders back, chin up, chest open — check every hour" },
  { id: "first-greet", category: "Energy", item: "Be the FIRST to greet people today. Don't wait for them." },
  { id: "compliment", category: "Energy", item: "Give one genuine compliment to someone today" },
  { id: "listen", category: "Energy", item: "When someone talks, LISTEN fully. Don't think about what to say next." },
  { id: "no-negative", category: "Energy", item: "No negative talk about markets, money, or problems. Talk about solutions, ideas, and other people's achievements." },
];

const WARDROBE_GUIDE = [
  {
    occasion: "Morning Coffee at Gymkhana",
    outfit: "Well-fitted polo shirt (navy, olive, or burgundy) + clean chinos or tailored joggers + clean white sneakers or loafers",
    avoid: "Old t-shirts, baggy shorts, rubber slippers, gym clothes at coffee table",
    tip: "You're sitting with millionaires. Dress like you belong there — smart casual, not sloppy casual.",
  },
  {
    occasion: "Badminton / Swimming",
    outfit: "Good quality sports wear — branded if possible (Nike, Adidas, Puma). Clean, matching. After sport: change into fresh clothes before socializing.",
    avoid: "Worn out sports gear, sweaty clothes during social time",
    tip: "Many business conversations happen AFTER the game. Always carry a fresh change of clothes.",
  },
  {
    occasion: "Client Meeting (First Time)",
    outfit: "Crisp light-colored shirt (white, light blue, light pink) + dark tailored trousers + leather belt + leather shoes + good watch. Optional: blazer if meeting is in AC office.",
    avoid: "Jeans, casual shoes, no watch, wrinkled clothes",
    tip: "For Kutchi clients: smart business casual. Don't overdress (no full suit) — they'll think you're trying too hard. But underdressing signals you don't care.",
  },
  {
    occasion: "Community Events / Weddings",
    outfit: "Option A: Well-fitted kurta with churidar (traditional = respect). Option B: Blazer + shirt + trousers (modern = professional). Both work — pick based on the event.",
    avoid: "Under-dressing for weddings, over-dressing for small gatherings",
    tip: "This is where people JUDGE you. Wedding photos circulate. Look like someone who has it together.",
  },
  {
    occasion: "Dinners with Coffee Group",
    outfit: "Smart casual — good shirt or polo, dark jeans or chinos, leather shoes or clean loafers, watch, optional blazer",
    avoid: "Looking like you just came from home. Sandals. Old clothes.",
    tip: "These men notice quality. You don't need expensive brands — you need clean, well-fitted, intentional dressing.",
  },
  {
    occasion: "Working from Home (Even Alone)",
    outfit: "Get dressed properly EVERY DAY. At minimum: clean shirt, proper pants. Not pajamas.",
    avoid: "Working in night clothes, not showering until afternoon",
    tip: "How you dress alone affects your energy. Dress well → feel capable → project confidence when you step out.",
  },
];

const BODY_LANGUAGE_RULES = [
  {
    rule: "The 3-Second Smile Rule",
    desc: "When you see someone, make eye contact for 1 second → smile for 2 seconds → THEN speak. Most people talk first — the smile-first approach makes you instantly warmer.",
    practice: "Practice in the mirror. Your smile should reach your eyes. A fake smile only moves the mouth — a real smile crinkles the eyes.",
  },
  {
    rule: "Open Posture — Always",
    desc: "Never cross your arms. Never put hands in pockets. Keep your chest open, shoulders relaxed (not tensed up), palms visible. This signals: I'm open, approachable, confident.",
    practice: "Set hourly reminders on your phone: 'Check posture.' Shoulders back, arms open, chin level.",
  },
  {
    rule: "The Power of Nodding",
    desc: "When someone is talking, nod slowly (not frantically). This makes them feel heard. It's the simplest way to make someone like you — just SHOW that you're listening.",
    practice: "At tomorrow's coffee, practice slow nodding while someone talks. Watch how they open up more.",
  },
  {
    rule: "Slow Down Everything",
    desc: "Walk 20% slower. Talk 20% slower. React 2 seconds slower. Rushing signals anxiety and low status. People with power move slowly and deliberately.",
    practice: "When someone asks you a question, pause for 2 seconds before answering. It shows you're thinking, not reactive.",
  },
  {
    rule: "Stop Fidgeting",
    desc: "No phone checking. No tapping. No adjusting clothes. No playing with things on the table. Stillness = confidence. Fidgeting = nervousness.",
    practice: "Put your phone on silent and KEEP IT IN YOUR POCKET during all social interactions.",
  },
  {
    rule: "The Lean-In",
    desc: "When someone tells you something, lean slightly forward (10-15 degrees). This tiny movement says 'what you're saying matters to me.' It's incredibly powerful.",
    practice: "At coffee tomorrow, when someone shares something, lean in slightly and say 'Tell me more about that.'",
  },
  {
    rule: "Mirror Their Energy",
    desc: "If they're excited, match it with enthusiasm. If they're calm, be calm. If they're serious, be serious. Mirroring makes people feel you 'get' them.",
    practice: "Observe the mood of the person before responding. Match, don't dominate.",
  },
  {
    rule: "Exit Gracefully",
    desc: "Don't overstay conversations. Leave when the energy is still high. Say: 'This was great, let me let you get on with your day.' People remember the feeling of wanting MORE of you, not less.",
    practice: "Set a mental timer — 5-10 minutes per conversation unless they keep asking you things.",
  },
];

const NEGATIVE_TO_POSITIVE = [
  { negative: "The market is terrible, I lost so much money", positive: "Markets are cyclical — I'm looking at it as a learning experience. What are you invested in these days?" },
  { negative: "Nobody is giving me work", positive: "I've been building some interesting software lately — let me show you what I made for [client]" },
  { negative: "That accountant is blocking everything", positive: "(Don't mention it at all. Nobody wants to hear about your problems.)" },
  { negative: "I'm running out of money", positive: "(NEVER say this. Ever. To anyone. It repels people and opportunities.)" },
  { negative: "Software business is not working", positive: "I'm working on some exciting projects — one for a fitness studio, another for a 5000-member community" },
  { negative: "I don't know what to do", positive: "I've been thinking about a new approach — what do you think about [specific idea]?" },
  { negative: "This guy is not paying me", positive: "(Don't discuss. Handle privately. Talking about unpaid invoices makes YOU look bad.)" },
];

export default function PersonalityPage() {
  const [checklist, setChecklist] = useState<DailyCheckItem[]>([]);
  const [activeTab, setActiveTab] = useState<"checklist" | "wardrobe" | "bodylang" | "speech">("checklist");

  useEffect(() => {
    const today = new Date().toDateString();
    const saved = localStorage.getItem("mmam-checklist-date");
    if (saved === today) {
      setChecklist(JSON.parse(localStorage.getItem("mmam-checklist") || "[]"));
    } else {
      const fresh = DAILY_CHECKLIST.map((item) => ({ ...item, checked: false }));
      setChecklist(fresh);
      localStorage.setItem("mmam-checklist-date", today);
      localStorage.setItem("mmam-checklist", JSON.stringify(fresh));
    }
  }, []);

  const toggleItem = (id: string) => {
    const updated = checklist.map((item) =>
      item.id === id ? { ...item, checked: !item.checked } : item
    );
    setChecklist(updated);
    localStorage.setItem("mmam-checklist", JSON.stringify(updated));
  };

  const completedCount = checklist.filter((c) => c.checked).length;
  const progress = checklist.length > 0 ? Math.round((completedCount / checklist.length) * 100) : 0;

  const tabs = [
    { id: "checklist" as const, label: "Daily Checklist" },
    { id: "wardrobe" as const, label: "Wardrobe" },
    { id: "bodylang" as const, label: "Body Language" },
    { id: "speech" as const, label: "What to Say" },
  ];

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Rebuild Yourself</h1>
        <p className="mt-2 text-muted">
          Your daily transformation guide. Grooming, body language, energy, and presence.
        </p>
      </div>

      {/* The hard truth */}
      <div className="mb-8 rounded-xl border border-accent/30 bg-accent/5 p-5">
        <p className="text-sm font-semibold text-accent">The Truth You Need to Hear</p>
        <p className="mt-2 text-sm leading-relaxed">
          People decide if they want to be around you in <strong>7 seconds</strong>. Before you open your mouth, they&apos;ve already judged your posture, your grooming, your facial expression, and your energy.
          If you walk into gymkhana with slumped shoulders, a stressed face, and start talking about market losses — people will find reasons to leave the conversation.
          But if you walk in straight, smiling, well-dressed, and ask THEM about their life — they&apos;ll want to sit next to you every morning.
        </p>
        <p className="mt-3 text-sm font-semibold text-accent">
          You don&apos;t need to fake happiness. You need to CHOOSE what energy you bring into a room.
        </p>
      </div>

      {/* Tabs */}
      <div className="mb-6 flex gap-1 overflow-x-auto rounded-xl bg-surface p-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 whitespace-nowrap rounded-lg px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === tab.id ? "bg-accent text-white" : "text-muted hover:text-[var(--foreground)]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Daily Checklist */}
      {activeTab === "checklist" && (
        <div>
          {/* Progress bar */}
          <div className="mb-6 rounded-xl border border-border bg-surface p-5">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm font-medium">Today&apos;s Progress</p>
              <p className="font-mono text-sm font-bold text-accent">{completedCount}/{checklist.length}</p>
            </div>
            <div className="h-3 rounded-full bg-border">
              <div
                className="h-3 rounded-full bg-accent transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            {progress === 100 && (
              <p className="mt-3 text-sm font-semibold text-emerald-500">
                You&apos;re fully prepared. Go out there and be magnetic.
              </p>
            )}
          </div>

          {/* Grouped checklist */}
          {["Energy", "Body", "Face", "Clothes"].map((category) => (
            <div key={category} className="mb-6">
              <h3 className="mb-3 text-sm font-semibold text-muted uppercase tracking-wide">
                {category === "Energy" ? "Energy & Mindset (Most Important)" : category}
              </h3>
              <div className="space-y-2">
                {checklist
                  .filter((item) => item.category === category)
                  .map((item) => (
                    <button
                      key={item.id}
                      onClick={() => toggleItem(item.id)}
                      className={`flex w-full items-center gap-3 rounded-xl border p-4 text-left transition-all ${
                        item.checked
                          ? "border-emerald-500/30 bg-emerald-500/5"
                          : "border-border bg-surface hover:border-accent/30"
                      }`}
                    >
                      <div className={`flex size-6 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                        item.checked ? "border-emerald-500 bg-emerald-500" : "border-border"
                      }`}>
                        {item.checked && (
                          <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" className="size-3.5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                          </svg>
                        )}
                      </div>
                      <span className={`text-sm ${item.checked ? "text-muted line-through" : ""}`}>
                        {item.item}
                      </span>
                    </button>
                  ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Wardrobe Guide */}
      {activeTab === "wardrobe" && (
        <div className="space-y-4">
          {WARDROBE_GUIDE.map((w) => (
            <div key={w.occasion} className="rounded-xl border border-border bg-surface p-5">
              <h3 className="text-base font-semibold">{w.occasion}</h3>
              <div className="mt-3 space-y-2">
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 text-emerald-500">✓</span>
                  <p className="text-sm"><strong>Wear:</strong> {w.outfit}</p>
                </div>
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 text-red-400">✗</span>
                  <p className="text-sm"><strong>Avoid:</strong> {w.avoid}</p>
                </div>
                <div className="rounded-lg bg-accent/5 p-3">
                  <p className="text-xs text-accent">{w.tip}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Body Language */}
      {activeTab === "bodylang" && (
        <div className="space-y-4">
          {BODY_LANGUAGE_RULES.map((bl, i) => (
            <div key={i} className="rounded-xl border border-border bg-surface p-5">
              <h3 className="text-base font-semibold">{bl.rule}</h3>
              <p className="mt-2 text-sm text-muted leading-relaxed">{bl.desc}</p>
              <div className="mt-3 rounded-lg bg-accent/5 p-3">
                <p className="text-xs text-accent"><strong>Practice:</strong> {bl.practice}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* What to Say / Not Say */}
      {activeTab === "speech" && (
        <div>
          <div className="mb-6 rounded-xl border border-red-500/20 bg-red-500/5 p-5">
            <h3 className="text-base font-semibold text-red-400">The #1 Rule</h3>
            <p className="mt-2 text-sm leading-relaxed">
              <strong>Nobody wants to hear about your problems.</strong> Not at coffee. Not at dinners. Not at the gymkhana.
              Rich, successful people are <em>attracted to energy, solutions, and positivity</em>. They <em>avoid</em> complainers, victims, and negativity.
              This doesn&apos;t mean you lie. It means you CHOOSE what to share. Your financial stress is private. Your client problems are private. What you share publicly is your work, your ideas, your curiosity about THEIR lives.
            </p>
          </div>

          <h3 className="mb-3 text-sm font-semibold text-muted uppercase tracking-wide">Replace These</h3>
          <div className="space-y-3">
            {NEGATIVE_TO_POSITIVE.map((item, i) => (
              <div key={i} className="rounded-xl border border-border bg-surface p-4">
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 text-red-400">✗</span>
                  <p className="text-sm line-through text-muted">&quot;{item.negative}&quot;</p>
                </div>
                <div className="mt-2 flex items-start gap-2">
                  <span className="mt-0.5 text-emerald-500">✓</span>
                  <p className="text-sm font-medium">&quot;{item.positive}&quot;</p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 rounded-xl border border-accent/20 bg-accent/5 p-5">
            <h3 className="text-base font-semibold text-accent">The 3 Power Topics at Coffee</h3>
            <div className="mt-3 space-y-2 text-sm">
              <p><strong>1. Ask about THEM:</strong> &quot;How&apos;s the new project going?&quot; &quot;I heard your son is doing well — what is he up to?&quot;</p>
              <p><strong>2. Share something interesting:</strong> A news article, a tech insight, something you learned. Be the person who brings VALUE to the table.</p>
              <p><strong>3. Show your work casually:</strong> &quot;I just built this interesting booking system...&quot; Show your phone. Let THEM ask for more. Don&apos;t push.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
