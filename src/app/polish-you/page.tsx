"use client";

import { useState } from "react";
import { CONVERSATION_TIPS } from "@/lib/conversation-tips";
import { SOCIAL_INTELLIGENCE_TIPS } from "@/lib/social-intelligence-tips";
import { DINING_ETIQUETTE_TIPS } from "@/lib/dining-etiquette-tips";
import { LANGUAGE_TIPS } from "@/lib/language-tips";
import { DIGITAL_PRESENCE_TIPS } from "@/lib/digital-presence-tips";
import { NETWORKING_TIPS } from "@/lib/networking-tips";
import { PERSONAL_BRAND_TIPS } from "@/lib/personal-brand-tips";
import { EMOTIONAL_INTELLIGENCE_TIPS } from "@/lib/emotional-intelligence-tips";
import { PRESENCE_AURA_TIPS } from "@/lib/presence-aura-tips";

interface PolishSection {
  id: string;
  title: string;
  subtitle: string;
  tips: { heading: string; detail: string }[];
}

const POLISH_SECTIONS: PolishSection[] = [
  {
    id: "conversation",
    title: "The Art of Conversation",
    subtitle: "Beyond what to say — how to be someone people want to talk to",
    tips: CONVERSATION_TIPS,
  },
  {
    id: "social-intelligence",
    title: "Social Intelligence",
    subtitle: "Reading rooms, remembering details, and building rapport",
    tips: SOCIAL_INTELLIGENCE_TIPS,
  },
  {
    id: "dining-etiquette",
    title: "Dining & Social Etiquette",
    subtitle: "The subtle rules that signal sophistication",
    tips: DINING_ETIQUETTE_TIPS,
  },
  {
    id: "language-refinement",
    title: "Language & Communication",
    subtitle: "Speak like someone worth listening to",
    tips: LANGUAGE_TIPS,
  },
  {
    id: "digital-presence",
    title: "Digital Presence & Messaging",
    subtitle: "Your WhatsApp, email, and online persona",
    tips: DIGITAL_PRESENCE_TIPS,
  },
  {
    id: "networking-mastery",
    title: "Networking Like a Pro",
    subtitle: "Turn casual encounters into lasting business relationships",
    tips: NETWORKING_TIPS,
  },
  {
    id: "personal-brand",
    title: "Building Your Personal Brand",
    subtitle: "Be known for something specific and valuable",
    tips: PERSONAL_BRAND_TIPS,
  },
  {
    id: "emotional-intelligence",
    title: "Emotional Intelligence",
    subtitle: "The invisible skill that makes everything else work",
    tips: EMOTIONAL_INTELLIGENCE_TIPS,
  },
  {
    id: "presence-aura",
    title: "Presence & Aura",
    subtitle: "The intangible quality that makes people gravitate toward you",
    tips: PRESENCE_AURA_TIPS,
  },
];

export default function PolishYouPage() {
  const [openSections, setOpenSections] = useState<Set<string>>(new Set());

  const toggleSection = (id: string) => {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const expandAll = () => {
    setOpenSections(new Set(POLISH_SECTIONS.map((s) => s.id)));
  };

  const collapseAll = () => {
    setOpenSections(new Set());
  };

  const totalTips = POLISH_SECTIONS.reduce((sum, s) => sum + s.tips.length, 0);

  return (
    <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Polish You</h1>
        <p className="mt-2 text-muted">
          Beyond the basics — refine your language, social skills, and presence to become magnetic.
        </p>
        <p className="mt-1 text-xs text-muted">
          {totalTips} tips across {POLISH_SECTIONS.length} categories
        </p>
      </div>

      {/* Context banner */}
      <div className="mb-8 rounded-xl border border-accent/30 bg-accent/5 p-5">
        <p className="text-sm font-semibold text-accent">Rebuild Me Handles the Foundation. This Is the Shine.</p>
        <p className="mt-2 text-sm leading-relaxed">
          You already know the basics — grooming, wardrobe, posture, what not to say. This page is about the <strong>next level</strong>. How you carry a conversation. How you enter a room. How you make people remember you for the right reasons. These are the subtle, invisible skills that separate someone who looks polished from someone who <em>is</em> polished.
        </p>
      </div>

      {/* Expand/Collapse all */}
      <div className="mb-6 flex justify-end gap-3">
        <button
          onClick={expandAll}
          className="text-xs font-medium text-accent hover:underline"
        >
          Expand All
        </button>
        <span className="text-xs text-muted">|</span>
        <button
          onClick={collapseAll}
          className="text-xs font-medium text-accent hover:underline"
        >
          Collapse All
        </button>
      </div>

      {/* Sections */}
      <div className="space-y-4">
        {POLISH_SECTIONS.map((section) => {
          const isOpen = openSections.has(section.id);
          return (
            <div
              key={section.id}
              className="rounded-xl border border-border bg-surface overflow-hidden"
            >
              {/* Section header */}
              <button
                onClick={() => toggleSection(section.id)}
                className="flex w-full items-center justify-between p-5 text-left transition-colors hover:bg-surface-hover"
              >
                <div>
                  <h2 className="text-base font-semibold">{section.title}</h2>
                  <p className="mt-0.5 text-xs text-muted">{section.subtitle}</p>
                </div>
                <div className="ml-4 flex items-center gap-2">
                  <span className="rounded-full bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">
                    {section.tips.length} tips
                  </span>
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    className={`size-4 text-muted transition-transform duration-200 ${
                      isOpen ? "rotate-180" : ""
                    }`}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
                  </svg>
                </div>
              </button>

              {/* Section content */}
              {isOpen && (
                <div className="border-t border-border px-5 pb-5">
                  <div className="mt-4 space-y-4">
                    {section.tips.map((tip, i) => (
                      <div key={i} className="rounded-lg border border-border/50 bg-[var(--background)] p-4">
                        <h3 className="text-sm font-semibold text-accent">{tip.heading}</h3>
                        <p className="mt-2 text-sm leading-relaxed text-muted whitespace-pre-line">
                          {tip.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
