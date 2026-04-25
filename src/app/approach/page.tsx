"use client";

import { useRef, useState } from "react";
import { communityResearch } from "@/lib/community-research";

interface ApproachEntry {
  id: string;
  name: string;
  profession: string;
  community: string;
  venue: string;
  notes: string;
  approach: string;
  date: string;
}

const COMMUNITIES = [
  "Kutchi",
  "Gujarati",
  "Marathi",
  "Punjabi",
  "Sindhi",
  "South Indian",
  "Bengali",
  "Other",
];

export default function ApproachPage() {
  const [name, setName] = useState("");
  const [profession, setProfession] = useState("");
  const [community, setCommunity] = useState("Kutchi");
  const [venue, setVenue] = useState("");
  const [notes, setNotes] = useState("");
  const [approach, setApproach] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<ApproachEntry[]>(() => {
    if (typeof window !== "undefined") {
      return JSON.parse(localStorage.getItem("mmam-approaches") || "[]");
    }
    return [];
  });
  const [showHistory, setShowHistory] = useState(false);
  const resultRef = useRef<HTMLDivElement>(null);

  const generateApproach = async () => {
    if (!name.trim() || !profession.trim()) return;

    const provider = localStorage.getItem("mmam-provider") || "gemini";
    const apiKey = provider === "gemini" ? localStorage.getItem("mmam-gemini-key") || "" : localStorage.getItem("mmam-api-key") || "";
    if (!apiKey) {
      alert("Please set your API key in Settings first.");
      return;
    }

    setLoading(true);
    setApproach("");

    const prompt = `I need your help approaching a potential client for my custom software development business.

**Person:** ${name.trim()}
**Profession/Business:** ${profession.trim()}
**Community:** ${community}
${venue.trim() ? `**Meeting venue:** ${venue.trim()}` : ""}
${notes.trim() ? `**Additional context:** ${notes.trim()}` : ""}

**About me:** I'm Ashish Kamdar, a software developer with 25+ years of experience. I build custom software solutions. I live in the same community as this person. I need you to groom me completely for this interaction — from what I wear to how I speak to how I follow up.

**IMPORTANT RESEARCH — Use this deep community knowledge to power your recommendations:**
${communityResearch[community] || communityResearch["Other"]}

Using the above research as your foundation, give me a highly specific, actionable approach plan:

1. **Cultural context** — What should I know about approaching a ${community} businessperson? What do they value? What turns them off?

2. **Conversation opener** — Give me 2-3 natural ways to start a conversation with them. Not salesy. Think community gatherings, mutual connections, or genuine interest in their business.

3. **Understanding their pain** — What software problems does someone in "${profession.trim()}" likely face? What questions should I ask to uncover their real needs?

4. **The pitch angle** — How to naturally transition from conversation to "I can help you with that." Give me exact words I could use.

5. **Dress code** — Be very specific: formal suit? Business casual? Smart casual? What colors? What shoes? What accessories (watch, pen, bag)? Match the dress code to this person's profession and community norms. Consider where we'll likely meet (office, restaurant, community event, temple).

6. **Body language & presentation** — How should I carry myself? How to stand, sit, walk into the room, eye contact patterns, handshake style, tone and pace of voice. Be specific to ${community} cultural expectations.

7. **Follow-up strategy** — What to do after the first meeting. How to stay top-of-mind without being pushy.

8. **Red flags to avoid** — What NOT to do with a ${community} businessperson. Common mistakes that would lose their trust.

Be specific to their profession and community. No generic advice.`;

    try {
      const systemPrompt = localStorage.getItem("mmam-system-prompt") || "";
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: [{ role: "user", content: prompt }],
          apiKey,
          provider,
          systemPrompt,
        }),
      });

      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || "API request failed");
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let fullResponse = "";

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          fullResponse += chunk;
          setApproach(fullResponse);
        }
      }

      // Save to history
      const entry: ApproachEntry = {
        id: Date.now().toString(),
        name: name.trim(),
        profession: profession.trim(),
        community,
        venue: venue.trim(),
        notes: notes.trim(),
        approach: fullResponse,
        date: new Date().toLocaleDateString(),
      };
      const updated = [entry, ...history];
      setHistory(updated);
      localStorage.setItem("mmam-approaches", JSON.stringify(updated));

      resultRef.current?.scrollIntoView({ behavior: "smooth" });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Something went wrong";
      setApproach(`Error: ${errorMsg}`);
    } finally {
      setLoading(false);
    }
  };

  const loadEntry = (entry: ApproachEntry) => {
    setName(entry.name);
    setProfession(entry.profession);
    setCommunity(entry.community);
    setVenue(entry.venue || "");
    setNotes(entry.notes);
    setApproach(entry.approach);
    setShowHistory(false);
  };

  const deleteEntry = (id: string) => {
    const updated = history.filter((h) => h.id !== id);
    setHistory(updated);
    localStorage.setItem("mmam-approaches", JSON.stringify(updated));
  };

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Approach Planner</h1>
        <p className="mt-2 text-muted">
          Enter a person&apos;s details and get a tailored strategy for how to approach them.
        </p>
      </div>

      <div className="flex flex-col gap-6 lg:flex-row">
        {/* Input form */}
        <div className="lg:w-96 lg:shrink-0">
          <div className="rounded-xl border border-border bg-surface p-5">
            <div className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium">Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Rajesh Mehta"
                  className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-sm font-medium">Profession / Business</label>
                <input
                  type="text"
                  value={profession}
                  onChange={(e) => setProfession(e.target.value)}
                  placeholder="e.g., Textile exporter, Restaurant chain owner"
                  className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-sm font-medium">Community</label>
                <div className="flex flex-wrap gap-2">
                  {COMMUNITIES.map((c) => (
                    <button
                      key={c}
                      onClick={() => setCommunity(c)}
                      className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                        community === c
                          ? "bg-accent text-white"
                          : "bg-[var(--background)] text-muted hover:text-[var(--foreground)]"
                      }`}
                    >
                      {c}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Where will you meet? <span className="text-muted">(optional)</span>
                </label>
                <input
                  type="text"
                  value={venue}
                  onChange={(e) => setVenue(e.target.value)}
                  placeholder="e.g., Community event, his office, restaurant, temple"
                  className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>

              <div>
                <label className="mb-1.5 block text-sm font-medium">
                  Additional Notes <span className="text-muted">(optional)</span>
                </label>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g., Met him at a wedding, his son uses our gym..."
                  rows={3}
                  className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>

              <button
                onClick={generateApproach}
                disabled={loading || !name.trim() || !profession.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-accent py-3 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-40"
              >
                {loading ? (
                  <>
                    <svg className="size-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Generating approach...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-4">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
                    </svg>
                    Generate Approach Strategy
                  </>
                )}
              </button>
            </div>

            {/* History toggle */}
            <div className="mt-4 border-t border-border pt-4">
              <button
                onClick={() => setShowHistory(!showHistory)}
                className="flex w-full items-center justify-between text-sm font-medium text-muted hover:text-[var(--foreground)]"
              >
                <span>Past Approaches ({history.length})</span>
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  className={`size-4 transition-transform ${showHistory ? "rotate-180" : ""}`}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                </svg>
              </button>

              {showHistory && (
                <div className="mt-3 max-h-64 space-y-1 overflow-y-auto">
                  {history.length === 0 ? (
                    <p className="py-4 text-center text-xs text-muted">No approaches yet</p>
                  ) : (
                    history.map((h) => (
                      <div
                        key={h.id}
                        className="group flex items-center justify-between rounded-lg px-3 py-2 hover:bg-surface-hover"
                      >
                        <button
                          onClick={() => loadEntry(h)}
                          className="flex-1 text-left"
                        >
                          <p className="text-sm font-medium truncate">{h.name}</p>
                          <p className="text-xs text-muted truncate">
                            {h.profession} · {h.community} · {h.date}
                          </p>
                        </button>
                        <button
                          onClick={() => deleteEntry(h.id)}
                          className="ml-2 rounded p-1 text-muted opacity-0 transition-all hover:text-red-400 group-hover:opacity-100"
                        >
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Result */}
        <div ref={resultRef} className="min-w-0 flex-1">
          {approach ? (
            <div className="rounded-xl border border-border bg-surface p-5 sm:p-6">
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <h2 className="text-lg font-semibold">
                  Approach: {name}
                </h2>
                <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">
                  {community}
                </span>
                <span className="rounded-md bg-surface-hover px-2 py-0.5 text-xs font-medium text-muted">
                  {profession}
                </span>
              </div>
              <div className="prose-sm max-w-none whitespace-pre-wrap text-sm leading-relaxed">
                {approach}
              </div>
              {loading && (
                <span className="ml-1 inline-block size-2 animate-pulse rounded-full bg-accent" />
              )}
            </div>
          ) : (
            <div className="flex h-full flex-col items-center justify-center rounded-xl border border-dashed border-border py-20 text-center">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mb-4 size-12 text-muted">
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
              </svg>
              <p className="text-lg font-medium">Enter a person&apos;s details</p>
              <p className="mt-1 max-w-xs text-sm text-muted">
                Fill in the name, profession, and community to get a tailored approach strategy.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
