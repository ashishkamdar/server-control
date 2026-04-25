"use client";

import { useState } from "react";

const PLATFORMS = [
  {
    name: "Upwork",
    url: "https://www.upwork.com",
    type: "Freelance Marketplace",
    best: "Long-term client relationships, hourly projects",
    earnings: "Rs 3,000–15,000/hr for senior devs",
    tips: "Build a strong profile. Start with lower rates to get reviews. Then raise rates. Your 25 years experience is GOLD here.",
    searchUrl: "https://www.upwork.com/nx/find-work/",
  },
  {
    name: "Toptal",
    url: "https://www.toptal.com",
    type: "Elite Freelance Network",
    best: "High-paying projects, top 3% developers",
    earnings: "Rs 5,000–25,000/hr",
    tips: "Tough screening process but worth it. Your experience qualifies you. Apply and prep for their coding test.",
    searchUrl: "https://www.toptal.com/talent/apply",
  },
  {
    name: "Freelancer.com",
    url: "https://www.freelancer.com",
    type: "Bid-based Marketplace",
    best: "Quick projects, competitive bidding",
    earnings: "Rs 1,000–8,000/hr",
    tips: "High competition. Stand out with detailed proposals. Focus on your niche (25 years experience in specific tech).",
    searchUrl: "https://www.freelancer.com/jobs/",
  },
  {
    name: "Fiverr",
    url: "https://www.fiverr.com",
    type: "Service Marketplace",
    best: "Productized services, fixed-price gigs",
    earnings: "Rs 5,000–50,000 per gig",
    tips: "Create specific service packages: 'I will build a custom CRM', 'I will create a member management system'. Your samaj project is a template.",
    searchUrl: "https://www.fiverr.com/start_selling",
  },
  {
    name: "LinkedIn",
    url: "https://www.linkedin.com",
    type: "Professional Network",
    best: "Direct client connections, contract work",
    earnings: "Variable — direct negotiation",
    tips: "Post about your work weekly. Share tech insights. Turn on 'Open to Work' for contract roles. Your 25-year story is compelling.",
    searchUrl: "https://www.linkedin.com/jobs/",
  },
  {
    name: "GitHub Jobs / Remote OK",
    url: "https://remoteok.com",
    type: "Remote Job Board",
    best: "Contract developer roles, remote work",
    earnings: "Rs 1.5L–5L/month for senior roles",
    tips: "Many companies hire senior contractors. Filter for 'contract' and your tech stack.",
    searchUrl: "https://remoteok.com/remote-dev-jobs",
  },
  {
    name: "Clutch.co",
    url: "https://clutch.co",
    type: "Agency Directory",
    best: "Position yourself as a development agency",
    earnings: "Project-based, Rs 1L–10L+",
    tips: "Create a company profile. List your projects (Sunil Saiya, Olistic Studios, Naranji Shamji). Get client reviews.",
    searchUrl: "https://clutch.co/developers",
  },
  {
    name: "IndiaMART / JustDial",
    url: "https://www.indiamart.com",
    type: "Local Business Directory",
    best: "Local business clients looking for software",
    earnings: "Project-based negotiation",
    tips: "List yourself as 'Custom Software Development'. Local businesses search here. Free to list.",
    searchUrl: "https://www.indiamart.com",
  },
];

const QUICK_WINS = [
  {
    title: "Productize your Samaj software",
    desc: "You've already built Members + Sanitarium + Marriage Hall booking. Package it as 'Community Management Software' and sell to other samajes. There are hundreds of them.",
    action: "List on your website, create a demo video, post in community WhatsApp groups",
    potential: "Rs 50K–2L per samaj",
  },
  {
    title: "Offer WordPress/website services",
    desc: "Many local businesses need basic websites. You can charge Rs 25K–75K per website. Quick turnaround with your experience.",
    action: "Tell people in your network you build business websites",
    potential: "Rs 25K–75K per project",
  },
  {
    title: "Tech consulting by the hour",
    desc: "Charge Rs 2,000–5,000/hour for tech consulting. Businesses need advice on which software to buy, how to automate, digital transformation.",
    action: "Offer free 30-min consultation, then charge for follow-ups",
    potential: "Rs 2K–5K/hour",
  },
  {
    title: "Build demo apps and sell to community",
    desc: "Build 3 demo apps targeting common community business needs: inventory management, billing/GST, customer CRM. Show them at community events.",
    action: "Pick one, build a clean demo this week, show it to 5 people",
    potential: "Rs 1L–3L per deployment",
  },
];

export default function OnlineWorkPage() {
  const [pricingAdvice, setPricingAdvice] = useState("");
  const [loadingAdvice, setLoadingAdvice] = useState(false);

  const getPricingAdvice = async () => {
    const provider = localStorage.getItem("mmam-provider") || "gemini";
    const apiKey = provider === "gemini" ? localStorage.getItem("mmam-gemini-key") || "" : localStorage.getItem("mmam-api-key") || "";
    if (!apiKey) { alert("Set API key in Settings first"); return; }

    setLoadingAdvice(true);
    setPricingAdvice("");

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apiKey,
          systemPrompt: localStorage.getItem("mmam-system-prompt") || "",
          messages: [{
            role: "user",
            content: `I'm Ashish Kamdar, 25+ years software developer in India. I need your help calculating my costs and setting my rates.

My current situation:
- I have a server (Hetzner dedicated/VPS) running 15+ apps — cost is shared
- I need to figure out: what should I charge per hour, per project, and for monthly maintenance?
- I'm running low on money and need income fast

Please calculate:
1. **My operating costs** — server (shared Hetzner, ~Rs 5,000-8,000/month shared across apps), internet, electricity, software licenses, domain costs, SSL (free Let's Encrypt). Break it down.
2. **My hourly rate** — for 25 years experience in India, what should my minimum and ideal hourly rate be? In INR and USD.
3. **Project pricing guide** — Small project (landing page), Medium (business app), Large (full ERP/management system). Give ranges in INR.
4. **Monthly maintenance charges** — what to charge for hosting, updates, bug fixes, support. Per app.
5. **Free support policy** — how many months/years of free support to give with each project? When to start charging?
6. **Dedicated vs shared server for clients** — when to give them their own server vs tenant on yours. Cost implications.
7. **Break-even analysis** — how many projects per month do I need to cover my costs + make Rs 1 lakh/month profit?

Be specific with numbers. Indian market context.`
          }],
        }),
      });

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let full = "";
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          full += decoder.decode(value, { stream: true });
          setPricingAdvice(full);
        }
      }
    } catch {
      setPricingAdvice("Error fetching advice. Check your API key.");
    } finally {
      setLoadingAdvice(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Online Work</h1>
        <p className="mt-2 text-muted">Freelance platforms, quick wins, and pricing guidance to start earning now.</p>
      </div>

      {/* Quick Wins — most important for immediate income */}
      <div className="mb-10">
        <h2 className="mb-4 text-lg font-semibold">Quick Money Moves</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {QUICK_WINS.map((qw) => (
            <div key={qw.title} className="rounded-xl border border-accent/20 bg-accent/5 p-5">
              <p className="font-semibold">{qw.title}</p>
              <p className="mt-1 text-sm text-muted">{qw.desc}</p>
              <div className="mt-3 rounded-lg bg-accent/10 p-2.5">
                <p className="text-xs text-accent"><strong>Action:</strong> {qw.action}</p>
              </div>
              <p className="mt-2 font-mono text-sm font-bold text-emerald-500">{qw.potential}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Pricing Calculator */}
      <div className="mb-10">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">My Costs & Pricing Guide</h2>
          <button
            onClick={getPricingAdvice}
            disabled={loadingAdvice}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-50"
          >
            {loadingAdvice ? "Calculating..." : "Calculate My Rates"}
          </button>
        </div>
        {pricingAdvice ? (
          <div className="rounded-xl border border-border bg-surface p-5">
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{pricingAdvice}</p>
          </div>
        ) : (
          <div className="rounded-xl border border-dashed border-border p-8 text-center text-sm text-muted">
            Click &quot;Calculate My Rates&quot; to get a personalized pricing guide based on your experience and costs.
          </div>
        )}
      </div>

      {/* Platforms */}
      <div>
        <h2 className="mb-4 text-lg font-semibold">Freelance Platforms</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {PLATFORMS.map((p) => (
            <div key={p.name} className="rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-semibold">{p.name}</h3>
                <span className="rounded-md bg-surface-hover px-2 py-0.5 text-xs text-muted">{p.type}</span>
              </div>
              <p className="text-sm text-muted">{p.best}</p>
              <p className="mt-2 font-mono text-sm font-bold text-emerald-500">{p.earnings}</p>
              <p className="mt-2 text-xs text-muted italic">{p.tips}</p>
              <a
                href={p.searchUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-3 inline-flex items-center gap-1 rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20"
              >
                Go to {p.name} →
              </a>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
