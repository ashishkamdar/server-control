"use client";

import { useMemo } from "react";

const tips = [
  // Grooming & Style
  { category: "Grooming", tip: "Iron your shirt today. Wrinkle-free clothes signal discipline before you say a word.", icon: "👔" },
  { category: "Grooming", tip: "Trim your nails and check your shoes. People notice details — especially business people.", icon: "✂️" },
  { category: "Grooming", tip: "Wear one signature accessory — a good watch, clean glasses, or a quality pen. It becomes your brand.", icon: "⌚" },
  { category: "Grooming", tip: "Smell good. A subtle cologne creates a positive subconscious impression.", icon: "🧴" },
  { category: "Grooming", tip: "Check your reflection before leaving — teeth clean, hair set, collar straight.", icon: "🪞" },
  { category: "Grooming", tip: "Invest in one quality outfit for business meetings. Fit matters more than brand.", icon: "👔" },
  { category: "Grooming", tip: "Keep a lint roller handy. Small details separate professionals from amateurs.", icon: "✨" },

  // Body Language & Posture
  { category: "Posture", tip: "Stand straight with shoulders back for 2 minutes this morning. Power posing changes your hormone levels.", icon: "🧍" },
  { category: "Posture", tip: "When meeting someone, make eye contact first, then smile, then speak. This order builds instant rapport.", icon: "👁️" },
  { category: "Posture", tip: "Practice your handshake — firm but not crushing, 2-3 seconds, with eye contact.", icon: "🤝" },
  { category: "Posture", tip: "When seated in a meeting, lean slightly forward. It signals engagement and confidence.", icon: "💺" },
  { category: "Posture", tip: "Walk 10% slower than your instinct. Rushing signals anxiety. A measured pace signals authority.", icon: "🚶" },
  { category: "Posture", tip: "Uncross your arms when talking to people. Open posture = open personality.", icon: "🙌" },
  { category: "Posture", tip: "When entering a room, pause at the door for 1 second before walking in. It commands attention.", icon: "🚪" },

  // Speech & Communication
  { category: "Speech", tip: "Practice saying 'I build custom software that solves business problems' out loud — 3 times. Own your elevator pitch.", icon: "🎤" },
  { category: "Speech", tip: "Today, ask more questions than you give answers. People love talking about themselves.", icon: "❓" },
  { category: "Speech", tip: "Replace 'I think' with 'In my experience.' Authority comes from language.", icon: "💬" },
  { category: "Speech", tip: "Slow down your speech by 20%. Fast talkers seem nervous. Measured speakers seem confident.", icon: "🗣️" },
  { category: "Speech", tip: "Use someone's name in conversation today. It's the most powerful word in any language.", icon: "📛" },
  { category: "Speech", tip: "Practice active listening: repeat back what someone said before responding. 'So what you're saying is...'", icon: "👂" },
  { category: "Speech", tip: "Cut filler words — 'um', 'actually', 'basically'. Silence is more powerful than fillers.", icon: "🔇" },

  // Personality & Aura
  { category: "Aura", tip: "Compliment one person genuinely today — not flattery, but a real observation about their work.", icon: "⭐" },
  { category: "Aura", tip: "Help someone today without being asked. The most magnetic people are the most generous.", icon: "🎯" },
  { category: "Aura", tip: "Read for 20 minutes today. People with interesting knowledge are interesting people.", icon: "📖" },
  { category: "Aura", tip: "Practice the 'pause and smile' — when someone talks to you, pause for a beat before responding. It shows thoughtfulness.", icon: "😊" },
  { category: "Aura", tip: "Share a useful insight in a WhatsApp group or community chat today. Be the person who adds value.", icon: "💡" },
  { category: "Aura", tip: "Remember: confidence is not 'they will like me.' Confidence is 'I will be fine if they don't.'", icon: "🧠" },
  { category: "Aura", tip: "Be the first to greet others today. Initiative signals leadership.", icon: "👋" },

  // Business
  { category: "Business", tip: "Identify one local business that could use better software today. Write down the problem they probably have.", icon: "🏢" },
  { category: "Business", tip: "Post one useful tech tip on social media. Position yourself as the expert.", icon: "📱" },
  { category: "Business", tip: "Follow up with someone you met recently. A simple 'good meeting you' keeps you top of mind.", icon: "📩" },
  { category: "Business", tip: "Look at a competitor's website. What are they doing well? What can you do better?", icon: "🔍" },
  { category: "Business", tip: "Draft a one-page 'what I do' document. Keep it simple enough for a non-tech person.", icon: "📄" },
  { category: "Business", tip: "Think about your pricing. If you're the cheapest, you're not attracting the best clients.", icon: "💰" },
  { category: "Business", tip: "Attend one community event this week, even briefly. Showing up is 80% of networking.", icon: "🤝" },
];

export function DailyTips() {
  const todaysTips = useMemo(() => {
    const dayOfYear = Math.floor(
      (Date.now() - new Date(new Date().getFullYear(), 0, 0).getTime()) / 86400000
    );
    // Pick 3 tips rotating daily from different categories
    const categories = ["Grooming", "Posture", "Speech", "Aura", "Business"];
    const result = [];
    for (let i = 0; i < 3; i++) {
      const catIndex = (dayOfYear + i) % categories.length;
      const category = categories[catIndex];
      const categoryTips = tips.filter((t) => t.category === category);
      const tipIndex = (dayOfYear + i) % categoryTips.length;
      result.push(categoryTips[tipIndex]);
    }
    return result;
  }, []);

  return (
    <div className="grid gap-4 sm:grid-cols-3">
      {todaysTips.map((tip, i) => (
        <div
          key={i}
          className="rounded-xl border border-accent/20 bg-accent/5 p-5 transition-colors hover:border-accent/40"
        >
          <div className="mb-3 flex items-center gap-2">
            <span className="text-xl">{tip.icon}</span>
            <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">
              {tip.category}
            </span>
          </div>
          <p className="text-sm leading-relaxed">{tip.tip}</p>
        </div>
      ))}
    </div>
  );
}
