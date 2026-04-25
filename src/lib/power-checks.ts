// Pool of power checks grouped by theme — 5 are picked each day using date-based rotation

import { corporateLanguageTips } from "./executive-corporate-language";
import { strategicThinkingTips } from "./executive-strategic-thinking";
import { executiveCommunicationTips } from "./executive-communication";
import { financialFluencyTips } from "./executive-financial-fluency";
import { ceoSpeaksTips } from "./executive-ceo-speaks";
import { decoderTips } from "./executive-decoder";
import { techieTalksTips } from "./executive-techie-talks";
import { highTrafficTips } from "./executive-high-traffic";

export interface PowerCheckItem {
  id: string;
  label: string;
  theme: string;
}

const POWER_CHECK_POOL: PowerCheckItem[] = [
  // --- Confidence & Presence ---
  { id: "smile", label: "Look in the mirror and SMILE — your warmest outfit", theme: "presence" },
  { id: "posture", label: "Shoulders back, chin up, chest open", theme: "presence" },
  { id: "walk-slow", label: "Walk 20% slower today — powerful people never rush", theme: "presence" },
  { id: "eye-contact", label: "Hold eye contact 1 second longer than usual in every conversation", theme: "presence" },
  { id: "pause-before-speak", label: "Pause 2 seconds before answering any question — it shows command", theme: "presence" },
  { id: "take-space", label: "Sit wide, stand tall, take up space — you belong in every room", theme: "presence" },
  { id: "deep-voice", label: "Speak from your chest, not your throat — deep, calm, steady", theme: "presence" },
  { id: "dress-sharp", label: "Dress 10% better than everyone you'll meet today", theme: "presence" },
  { id: "enter-room", label: "When you enter a room, pause at the door — own the entrance", theme: "presence" },
  { id: "firm-handshake", label: "Give one firm handshake today with full eye contact and a genuine smile", theme: "presence" },

  // --- Communication & Social ---
  { id: "greet", label: "Be the FIRST to greet people today", theme: "social" },
  { id: "remember-name", label: "Use someone's name 3 times in conversation today — it's magnetic", theme: "social" },
  { id: "ask-question", label: "Ask one thoughtful question about someone's business or family", theme: "social" },
  { id: "listen-fully", label: "Listen without interrupting — let them finish completely before you speak", theme: "social" },
  { id: "compliment", label: "Give one SPECIFIC compliment today — not generic, something you truly noticed", theme: "social" },
  { id: "tell-story", label: "Share one short, interesting story from your work today — practice storytelling", theme: "social" },
  { id: "laugh-genuine", label: "Laugh genuinely — a warm laugh draws people in like nothing else", theme: "social" },
  { id: "small-talk-master", label: "Start one conversation with a stranger or acquaintance at Gymkhana today", theme: "social" },
  { id: "thank-someone", label: "Thank someone today — specifically, for something they don't expect thanks for", theme: "social" },
  { id: "introduce-two", label: "Introduce two people who could benefit from knowing each other", theme: "social" },

  // --- Mindset & Energy ---
  { id: "no-complain", label: "ZERO complaints today — not one, to anyone", theme: "mindset" },
  { id: "no-negative", label: "No negative talk — markets, money, or problems", theme: "mindset" },
  { id: "abundance", label: "Think ABUNDANCE — there is more than enough work and money out there", theme: "mindset" },
  { id: "gratitude-3", label: "Name 3 things you're grateful for RIGHT NOW before stepping out", theme: "mindset" },
  { id: "no-compare", label: "Don't compare yourself to anyone today — run YOUR race", theme: "mindset" },
  { id: "forgive-one", label: "Let go of one grudge or frustration — carrying it costs you energy", theme: "mindset" },
  { id: "act-wealthy", label: "Act like someone who already has Rs 1 crore — calm, generous, unhurried", theme: "mindset" },
  { id: "problem-opportunity", label: "Reframe one problem as an opportunity today — what's the hidden gift?", theme: "mindset" },
  { id: "deserve-success", label: "Say it out loud: 'I deserve success. I'm building something real.'", theme: "mindset" },
  { id: "no-self-pity", label: "Catch yourself if self-pity creeps in — redirect to action immediately", theme: "mindset" },

  // --- Business & Hustle ---
  { id: "one-followup", label: "Send ONE follow-up message today — the fortune is in the follow-up", theme: "business" },
  { id: "mention-work", label: "Casually mention your software work in one conversation today — plant a seed", theme: "business" },
  { id: "collect-money", label: "Ask for money you're owed — politely, firmly, today", theme: "business" },
  { id: "think-client", label: "Who could become your NEXT paying client? Think of one name right now.", theme: "business" },
  { id: "showcase-win", label: "Share one recent project win in conversation — let people know you're busy", theme: "business" },
  { id: "price-confidence", label: "If pricing comes up, state your number confidently — no hesitation, no discount face", theme: "business" },
  { id: "linkedin-post", label: "Post something on LinkedIn today — even a simple insight from your work", theme: "business" },
  { id: "help-free", label: "Offer one small piece of helpful advice to someone — generosity builds trust", theme: "business" },
  { id: "pitch-ready", label: "If someone asks 'What do you do?' — have a crisp 15-second answer ready", theme: "business" },
  { id: "close-one", label: "Move one deal forward today — a call, a message, a meeting. Just one.", theme: "business" },

  // --- Physical & Grooming ---
  { id: "check-mirror", label: "Do a full mirror check before leaving — hair, shirt, shoes, nails", theme: "grooming" },
  { id: "cologne", label: "Wear your best fragrance today — smell is the strongest memory trigger", theme: "grooming" },
  { id: "iron-clothes", label: "Wear something freshly ironed — crispness signals you care about details", theme: "grooming" },
  { id: "clean-shoes", label: "Clean your shoes — successful people always notice shoes first", theme: "grooming" },
  { id: "hydrate", label: "Drink a full glass of water right now — your energy starts with hydration", theme: "grooming" },
  { id: "stand-straight", label: "Every time you catch yourself slouching today, reset — shoulders back", theme: "grooming" },
  { id: "trim-nails", label: "Check your nails — clean, trimmed nails are a small detail that speaks volumes", theme: "grooming" },
  { id: "fresh-breath", label: "Carry mints or mouth freshener — fresh breath is non-negotiable", theme: "grooming" },

  // --- Family & Relationships ---
  { id: "hug-family", label: "Hug your wife or daughters before leaving — start with love, not just tasks", theme: "relationships" },
  { id: "no-phone-dinner", label: "No phone at dinner — be fully present with family tonight", theme: "relationships" },
  { id: "call-mother", label: "Check on your mother today — a small gesture she'll remember", theme: "relationships" },
  { id: "positive-home", label: "Bring positive energy HOME — your family feels your mood first", theme: "relationships" },
  { id: "share-win", label: "Share one small win with your family today — let them feel part of your journey", theme: "relationships" },

  // --- Focus & Discipline ---
  { id: "one-thing", label: "What's the ONE thing that matters most today? Do that first.", theme: "discipline" },
  { id: "no-scroll", label: "No mindless scrolling for the first hour — protect your morning energy", theme: "discipline" },
  { id: "say-no", label: "Say NO to one thing that doesn't serve your goals today", theme: "discipline" },
  { id: "deep-work", label: "Block 2 hours today for deep work — no calls, no messages, just build", theme: "discipline" },
  { id: "end-strong", label: "Before bed, write down tomorrow's #1 priority — end the day with intention", theme: "discipline" },
  { id: "no-excuse", label: "Catch yourself making an excuse today and replace it with action", theme: "discipline" },
  { id: "ship-something", label: "Ship something today — even small progress counts. Push code, send that email.", theme: "discipline" },

  // --- Executive & MBA Tips (imported) ---
  ...corporateLanguageTips,
  ...strategicThinkingTips,
  ...executiveCommunicationTips,
  ...financialFluencyTips,
  ...ceoSpeaksTips,
  ...decoderTips,
  ...techieTalksTips,
  ...highTrafficTips,
];

/**
 * Returns 5 power checks for a given day + round, ensuring theme variety.
 * Each round gives a different set. Excludes IDs already seen.
 */
export function getDailyPowerChecks(
  date: Date = new Date(),
  round: number = 0,
  excludeIds: Set<string> = new Set()
): PowerCheckItem[] {
  const dayOfYear = Math.floor(
    (date.getTime() - new Date(date.getFullYear(), 0, 0).getTime()) / 86400000
  );

  // Seeded shuffle — deterministic for a given day+round
  const seed = (dayOfYear * 2654435761 + round * 1597334677) >>> 0;
  const available = POWER_CHECK_POOL.filter((c) => !excludeIds.has(c.id));
  if (available.length === 0) return [];

  const shuffled = [...available];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.abs(((seed * (i + 1) * 2246822519) >>> 0) % (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }

  // Pick up to 5, trying to get variety across themes
  const picked: PowerCheckItem[] = [];
  const usedThemes = new Set<string>();

  for (const check of shuffled) {
    if (picked.length >= 5) break;
    if (!usedThemes.has(check.theme)) {
      picked.push(check);
      usedThemes.add(check.theme);
    }
  }

  // Fill remaining slots if fewer than 5 unique themes available
  if (picked.length < 5) {
    const pickedIds = new Set(picked.map((p) => p.id));
    for (const check of shuffled) {
      if (picked.length >= 5) break;
      if (!pickedIds.has(check.id)) {
        picked.push(check);
      }
    }
  }

  return picked;
}

export const POWER_CHECK_POOL_SIZE = POWER_CHECK_POOL.length;
