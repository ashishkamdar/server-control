"use client";

import { useEffect, useState } from "react";

export default function SettingsPage() {
  const [apiKey, setApiKey] = useState("");
  const [geminiKey, setGeminiKey] = useState("");
  const [provider, setProvider] = useState("gemini");
  const [saved, setSaved] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [showGeminiKey, setShowGeminiKey] = useState(false);
  const [systemPrompt, setSystemPrompt] = useState("");

  useEffect(() => {
    const key = localStorage.getItem("mmam-api-key") || "";
    const gKey = localStorage.getItem("mmam-gemini-key") || "";
    const prov = localStorage.getItem("mmam-provider") || "gemini";
    const prompt = localStorage.getItem("mmam-system-prompt") || defaultSystemPrompt;
    setApiKey(key);
    setGeminiKey(gKey);
    setProvider(prov);
    setSystemPrompt(prompt);
  }, []);

  const handleSave = () => {
    localStorage.setItem("mmam-api-key", apiKey);
    localStorage.setItem("mmam-gemini-key", geminiKey);
    localStorage.setItem("mmam-provider", provider);
    localStorage.setItem("mmam-system-prompt", systemPrompt);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleClearData = () => {
    if (confirm("This will delete all suggestions and chat history. Are you sure?")) {
      localStorage.removeItem("mmam-suggestions");
      localStorage.removeItem("mmam-chats");
      alert("Data cleared.");
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <div className="mb-10">
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="mt-2 text-muted">Configure your AI connection and preferences.</p>
      </div>

      <div className="space-y-8">
        {/* AI Provider Selection */}
        <section className="rounded-xl border border-border bg-surface p-6">
          <h2 className="text-lg font-semibold">AI Provider</h2>
          <p className="mt-1 text-sm text-muted">Choose which AI to use for Chat, Approach Planner, and Event Prep.</p>
          <div className="mt-4 flex gap-3">
            <button
              onClick={() => setProvider("gemini")}
              className={`flex-1 rounded-lg border-2 p-4 text-center transition-colors ${
                provider === "gemini" ? "border-accent bg-accent/10" : "border-border"
              }`}
            >
              <p className="text-sm font-bold">Google Gemini</p>
              <p className="mt-1 text-xs text-muted">Free tier available</p>
            </button>
            <button
              onClick={() => setProvider("anthropic")}
              className={`flex-1 rounded-lg border-2 p-4 text-center transition-colors ${
                provider === "anthropic" ? "border-accent bg-accent/10" : "border-border"
              }`}
            >
              <p className="text-sm font-bold">Anthropic Claude</p>
              <p className="mt-1 text-xs text-muted">Paid API ($5 min)</p>
            </button>
          </div>
        </section>

        {/* Google Gemini Key */}
        <section className={`rounded-xl border p-6 ${provider === "gemini" ? "border-accent/30 bg-accent/5" : "border-border bg-surface"}`}>
          <h2 className="text-lg font-semibold">Google Gemini API Key {provider === "gemini" && <span className="ml-2 rounded-md bg-accent/15 px-2 py-0.5 text-xs text-accent">Active</span>}</h2>
          <p className="mt-1 text-sm text-muted">Free tier: 15 requests/minute, 1500/day. More than enough for personal use.</p>
          <div className="mt-4 relative">
            <input
              type={showGeminiKey ? "text" : "password"}
              value={geminiKey}
              onChange={(e) => setGeminiKey(e.target.value)}
              placeholder="AIza..."
              className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-2.5 font-mono text-sm placeholder:text-muted focus:border-accent focus:outline-none"
            />
            <button
              onClick={() => setShowGeminiKey(!showGeminiKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-[var(--foreground)]"
            >
              {showGeminiKey ? "Hide" : "Show"}
            </button>
          </div>
          <div className="mt-4 rounded-lg bg-accent/10 p-3">
            <p className="text-xs text-accent">
              Get your free key from{" "}
              <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="underline hover:no-underline">
                aistudio.google.com/apikey
              </a>
              {" "}— click &quot;Create API Key&quot;, select any project, copy the key.
            </p>
          </div>
        </section>

        {/* Anthropic API Key */}
        <section className={`rounded-xl border p-6 ${provider === "anthropic" ? "border-accent/30 bg-accent/5" : "border-border bg-surface"}`}>
          <h2 className="text-lg font-semibold">Anthropic API Key {provider === "anthropic" && <span className="ml-2 rounded-md bg-accent/15 px-2 py-0.5 text-xs text-accent">Active</span>}</h2>
          <p className="mt-1 text-sm text-muted">
            Requires $5 minimum credit. Higher quality responses.
          </p>
          <div className="mt-4 flex gap-3">
            <div className="relative flex-1">
              <input
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-ant-..."
                className="w-full rounded-lg border border-border bg-[var(--background)] px-4 py-2.5 font-mono text-sm placeholder:text-muted focus:border-accent focus:outline-none"
              />
              <button
                onClick={() => setShowKey(!showKey)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-[var(--foreground)]"
              >
                {showKey ? (
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <div className="mt-4 rounded-lg bg-accent/10 p-3">
            <p className="text-xs text-accent">
              Get your API key from{" "}
              <a
                href="https://console.anthropic.com/settings/keys"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:no-underline"
              >
                console.anthropic.com
              </a>
            </p>
          </div>
        </section>

        {/* System Prompt */}
        <section className="rounded-xl border border-border bg-surface p-6">
          <h2 className="text-lg font-semibold">AI Personality</h2>
          <p className="mt-1 text-sm text-muted">
            Customize how your AI coach behaves. This is the system prompt sent with every conversation.
          </p>
          <textarea
            value={systemPrompt}
            onChange={(e) => setSystemPrompt(e.target.value)}
            rows={8}
            className="mt-4 w-full rounded-lg border border-border bg-[var(--background)] px-4 py-3 text-sm leading-relaxed placeholder:text-muted focus:border-accent focus:outline-none"
          />
        </section>

        {/* Actions */}
        <div className="flex items-center justify-between">
          <button
            onClick={handleClearData}
            className="rounded-lg border border-red-500/30 px-4 py-2.5 text-sm font-medium text-red-400 transition-colors hover:bg-red-500/10"
          >
            Clear All Data
          </button>

          <button
            onClick={handleSave}
            className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
          >
            {saved ? "Saved!" : "Save Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}

const defaultSystemPrompt = `You are MMAM Coach — a sharp, world-class advisor who combines business strategy with personality development. Your client is Ashish Kamdar, a software developer with 25+ years of experience.

Context about Ashish:
- Lives among a wealthy Kutchi (Indian) business community — multi-millionaires with huge enterprises
- Their younger generation is well-educated and tech-savvy
- Wants to build an independent custom software development business (not employment)
- His goal: develop a magnetic personality and powerful aura so people naturally seek him out for IT software work

Your dual role:

PERSONALITY & AURA COACH (this is the PRIMARY focus):
- Grooming: clothing, style, accessories, personal care — how a successful tech entrepreneur presents
- Posture & Body language: standing tall, eye contact, handshake, walking into a room with presence
- Speech: vocabulary, tone, pace, how to articulate ideas clearly and powerfully
- Social skills: small talk, active listening, making others feel important, remembering names
- Confidence: inner belief, handling rejection, not seeking approval, quiet authority
- Personal branding: what people say about him when he's not in the room
- First impressions: the 7-second rule — how to be instantly memorable and attractive
- Executive presence: the aura of someone who knows what they're worth
- Focus on what works in Indian business culture: gravitas, generosity, knowledge-sharing
- Help him become a magnet — the person everyone in the community naturally wants to work with

BUSINESS STRATEGIST:
- Actionable advice on client acquisition, pricing, positioning, and deal-closing
- Focus on relationship-based selling — the Kutchi business community runs on trust
- Help with portfolio building, demo projects, and showcasing value
- Guide on how to make the first move, handle objections, and build referral networks

Rules:
- Be direct and specific — no generic motivational fluff
- Every suggestion should have a clear "do this next" action
- Think in terms of ROI: time invested vs. business value gained
- When he asks technical questions, give senior architect-level answers
- Challenge him when he's playing small — he has 25 years of expertise to leverage`;
