export interface PeopleCard {
  id: number;
  category: string;
  text: string;
}

export const peopleCards: PeopleCard[] = [
  // === KUTCHIS (1-25) ===
  { id: 1, category: "Kutchi", text: "Kutchis value trust above contracts. Your word IS your bond. If you say you'll deliver Friday, deliver Thursday. Breaking a promise costs you the entire community." },
  { id: 2, category: "Kutchi", text: "Never lead with price. Lead with relationship. Ask about family, business, children. The deal discussion comes after 3-4 meetings, not the first." },
  { id: 3, category: "Kutchi", text: "Kutchi elders (60+) are the real decision-makers even if the younger generation runs operations. Always pay respects to the patriarch first." },
  { id: 4, category: "Kutchi", text: "Community events are your networking gold — weddings, drama shows, puja, committee meetings. Show up. Be seen. Consistency builds trust." },
  { id: 5, category: "Kutchi", text: "Kutchis negotiate hard. It's not disrespect — it's sport. Don't take it personally. Hold your price calmly and they'll respect you more." },
  { id: 6, category: "Kutchi", text: "A warm introduction from someone they trust is 10x more effective than cold outreach. Always go through a mutual connection." },
  { id: 7, category: "Kutchi", text: "Accept their hospitality — chai, food, mithai. Refusing is seen as creating distance. Eat what they offer with gratitude." },
  { id: 8, category: "Kutchi", text: "Kutchi WhatsApp groups are powerful. Being helpful in community groups (tech tips, useful info) positions you as the knowledgeable, giving person." },
  { id: 9, category: "Kutchi", text: "Show respect for seva (service). If you help the community without expecting anything, the community rewards you tenfold." },
  { id: 10, category: "Kutchi", text: "Dress: smart business casual. Not too formal (they'll think you're a salesman), not too casual (they'll think you don't care). Clean, well-fitted, quality." },
  { id: 11, category: "Kutchi", text: "Use 'bhai' generously. 'Sunil bhai', 'Nirmal bhai'. It signals belonging. Never use first name alone for someone older." },
  { id: 12, category: "Kutchi", text: "They test you with small work first. Deliver perfectly. The big projects come after you prove yourself on the small ones." },
  { id: 13, category: "Kutchi", text: "Family decisions: the wife often has significant influence behind the scenes. If the wife doesn't approve, the deal may not happen." },
  { id: 14, category: "Kutchi", text: "Status symbols: real estate, children's education, business scale. Compliment their achievements genuinely — they take pride in what they've built." },
  { id: 15, category: "Kutchi", text: "When they say 'aavjo' (come over), they mean it. Visit them at their office or home. Face time builds bonds that phone calls can't." },

  // === GUJARATIS (16-40) ===
  { id: 16, category: "Gujarati", text: "Gujaratis are India's most commercially minded community. They think ROI instinctively. Frame everything as: this saves you X or earns you Y." },
  { id: 17, category: "Gujarati", text: "They respect hustle and resourcefulness. Telling them 'I started from scratch and built this' resonates deeply — they come from a culture of self-made success." },
  { id: 18, category: "Gujarati", text: "Food is social currency. If they invite you for thali or share dabba at office, accept enthusiastically. Business happens over food." },
  { id: 19, category: "Gujarati", text: "They're direct about money. Don't dance around pricing. State it clearly, confidently, and be ready for 'What's your best price?' on the spot." },
  { id: 20, category: "Gujarati", text: "Navratri and Diwali are prime networking seasons. Attend garba nights, Diwali parties. These are where 80% of yearly relationship-building happens." },
  { id: 21, category: "Gujarati", text: "Gujarati businesses are family operations. The son, daughter, nephew — anyone might be the actual decision-maker. Find out who runs what before pitching." },
  { id: 22, category: "Gujarati", text: "They value education highly in the new generation. Mention your 25 years of experience AND any technical knowledge. They respect both street-smart and book-smart." },
  { id: 23, category: "Gujarati", text: "Speed matters. They make fast decisions. If they like your pitch, they'll say 'chalo, let's start.' Be ready to begin immediately." },
  { id: 24, category: "Gujarati", text: "Community associations (samaj, mandal) have enormous influence. Get one samaj as a client and you'll be recommended to others." },
  { id: 25, category: "Gujarati", text: "The Gujarati guilt: if you do great work for free or cheap, they'll feel obligated to make it up. The first project plants the seed for much bigger ones." },

  // === MAHARASHTRIANS (26-50) ===
  { id: 26, category: "Maharashtrian", text: "Maharashtrians respect preparation and competence over relationships. Come to meetings with data, structure, and a written proposal. They evaluate thoroughly." },
  { id: 27, category: "Maharashtrian", text: "They value honesty and directness. Don't oversell. State what you can and can't do. 'I'll be transparent about the limitations' earns more trust than fake confidence." },
  { id: 28, category: "Maharashtrian", text: "Decision-making is slower — they like to evaluate, consult colleagues, and be thorough. Don't push for a quick decision. Give them space." },
  { id: 29, category: "Maharashtrian", text: "Ganpati season is sacred networking time. Visit their home Ganpati, bring modak or a fruit basket. This one visit builds a year's worth of goodwill." },
  { id: 30, category: "Maharashtrian", text: "They appreciate structured presentations. Agenda → Problem → Solution → Cost → Timeline → Questions. Follow this format and they'll respect your professionalism." },
  { id: 31, category: "Maharashtrian", text: "Many Maharashtrian businessmen are in manufacturing and IT services — they UNDERSTAND software. Don't oversimplify. Speak technically when appropriate." },
  { id: 32, category: "Maharashtrian", text: "Pride in Maharashtra's heritage is strong. Connecting your work to progress and modernization resonates. 'This brings your operations to world-class standards.'" },
  { id: 33, category: "Maharashtrian", text: "If you know some Marathi phrases — 'Namaskar', 'Dhanyavaad' — use them. It shows cultural respect and immediately warms the conversation." },
  { id: 34, category: "Maharashtrian", text: "Dress: business formal for first meetings. Shirt, trousers, leather shoes. They expect professionalism in appearance matching professionalism in delivery." },
  { id: 35, category: "Maharashtrian", text: "Follow-up with a detailed email after every meeting. Maharashtrians value documentation and thoroughness. Verbal agreements without written confirmation make them uneasy." },

  // === PUNJABIS (36-55) ===
  { id: 36, category: "Punjabi", text: "Punjabis warm up FAST. By the second meeting you're practically family. Match their energy — be warm, enthusiastic, and generous with your time." },
  { id: 37, category: "Punjabi", text: "Food and drinks are mandatory bonding. If they suggest lunch, dinner, or drinks — always say yes. Deals happen at the table, not in conference rooms." },
  { id: 38, category: "Punjabi", text: "They make gut decisions. If they like YOU, they'll give you the work. Logic comes second. Personality and trust come first." },
  { id: 39, category: "Punjabi", text: "Be confident and direct. Punjabis don't respect hesitation. 'I can deliver this in 6 weeks. Here's what I need from you.' Bold and clear." },
  { id: 40, category: "Punjabi", text: "They're generous and expect generosity back. If you receive hospitality, reciprocate. Take them out sometimes. The give-and-take builds the bond." },
  { id: 41, category: "Punjabi", text: "Visuals impress Punjabis more than documents. Show the demo on your phone. Show screenshots. They respond to what they SEE, not what they read." },
  { id: 42, category: "Punjabi", text: "Gurudwara events, langar, and Baisakhi are important. If invited, attend with genuine reverence. Covering your head and sitting for langar builds deep respect." },
  { id: 43, category: "Punjabi", text: "They're loyal once you're in. Deliver well and they'll refer you to every cousin, friend, and business partner they know. The Punjabi referral network is explosive." },
  { id: 44, category: "Punjabi", text: "Dress: slightly more stylish than with other communities. Good watch, quality shoes, well-fitted blazer. Punjabis notice and appreciate style." },
  { id: 45, category: "Punjabi", text: "Humour works with Punjabis. A well-timed joke breaks ice faster than any presentation. But keep it clean and self-deprecating — never at anyone else's expense." },

  // === SINDHIS (46-65) ===
  { id: 46, category: "Sindhi", text: "Sindhis rebuilt everything after Partition — from zero. They respect resilience. Your story of building a business from scratch resonates deeply with them." },
  { id: 47, category: "Sindhi", text: "They do business with 'apne log' first. Being introduced as a friend-of-a-friend is crucial. Cold approaches rarely work." },
  { id: 48, category: "Sindhi", text: "They're master negotiators. Expect 2-3 rounds of price discussion. Don't get frustrated. It's cultural, not personal. Hold firm and they'll respect you." },
  { id: 49, category: "Sindhi", text: "Speed and efficiency matter. They want solutions yesterday. If you can show a quick turnaround, you win. 'I can have a working prototype in 2 weeks.'" },
  { id: 50, category: "Sindhi", text: "Sindhis in electronics, textiles, and retail need inventory and billing software the most. Lead with these use cases." },
  { id: 51, category: "Sindhi", text: "Cheti Chand (Sindhi New Year) is important. A personalized greeting shows you know their culture. They notice and appreciate this." },
  { id: 52, category: "Sindhi", text: "They expect accessibility. Be available when they call. Quick WhatsApp responses. If they feel they can reach you anytime, they'll trust you with their business." },
  { id: 53, category: "Sindhi", text: "Community bonds are extremely strong. One good project for a Sindhi businessman can open 10 doors. They talk within their network constantly." },

  // === TAMILIANS (54-70) ===
  { id: 54, category: "Tamil", text: "Tamilians value education and technical depth. Your 25 years of experience + specific technical knowledge will earn instant respect. Be detailed in your explanations." },
  { id: 55, category: "Tamil", text: "They are methodical decision-makers. Expect a structured evaluation process. Provide documentation, case studies, and references. They'll check." },
  { id: 56, category: "Tamil", text: "Pongal and Tamil New Year are important festivals. A genuine greeting builds rapport beyond business." },
  { id: 57, category: "Tamil", text: "Many Tamilians in Mumbai are in IT, banking, and professional services. They understand technology well. Don't oversimplify — speak peer-to-peer." },
  { id: 58, category: "Tamil", text: "Punctuality is highly valued. Be on time — even 5 minutes early. Being late signals disrespect in South Indian business culture." },
  { id: 59, category: "Tamil", text: "Written proposals matter more than verbal promises. Send a structured proposal document. They'll evaluate it thoroughly before deciding." },
  { id: 60, category: "Tamil", text: "Respect for hierarchy is strong. Address seniors with 'Sir' or 'Madam' until told otherwise. This formality is expected and appreciated." },
  { id: 61, category: "Tamil", text: "Filter coffee or tea when offered — always accept. The 15-minute chai conversation is where trust starts in South Indian business culture." },
  { id: 62, category: "Tamil", text: "Learning 'Vanakkam' (hello) and 'Nandri' (thank you) in Tamil shows genuine respect. They light up when you make the effort." },

  // === KANNADIGAS (63-75) ===
  { id: 63, category: "Kannada", text: "Kannadigas in Mumbai often have strong Bangalore/tech connections. Mention any tech credentials and they'll instantly see you as credible." },
  { id: 64, category: "Kannada", text: "They value humility combined with competence. Don't be flashy — be solid. 'We quietly deliver' resonates better than 'We're the best.'" },
  { id: 65, category: "Kannada", text: "Rajyotsava (Karnataka Day, Nov 1) and Ugadi are important. Festival greetings show cultural awareness." },
  { id: 66, category: "Kannada", text: "Many Kannadigas in Mumbai are in engineering, manufacturing, and professional services. They appreciate structured, no-nonsense communication." },
  { id: 67, category: "Kannada", text: "'Namaskara' is the Kannada greeting. Using it immediately creates warmth and shows respect for their identity." },

  // === ANDHRAITES / TELUGU (68-80) ===
  { id: 68, category: "Telugu", text: "Telugu business community is massive in construction, real estate, film, and pharma. They think BIG. Don't pitch small — match their scale of thinking." },
  { id: 69, category: "Telugu", text: "Hospitality is lavish. When they host, they go all out. Reciprocate with genuine appreciation. Never understate their generosity." },
  { id: 70, category: "Telugu", text: "Family and hometown connections matter deeply. If you know anyone from their region or have been to Hyderabad/Vizag, mention it. Instant bonding." },
  { id: 71, category: "Telugu", text: "They appreciate ambition. Telling them your vision — 'I'm building a technology practice to serve India's top organizations' — resonates with their entrepreneurial DNA." },
  { id: 72, category: "Telugu", text: "Telugu people are generous tippers and big spenders. Don't undersell to them — they equate higher price with higher quality." },
  { id: 73, category: "Telugu", text: "Sankranti, Ugadi, and Bathukamma are important festivals. Personalized greetings make a lasting impression." },

  // === MALAYALIS (74-85) ===
  { id: 74, category: "Malayali", text: "Malayalis are among the most educated communities in India. They value intellectual conversation. Discuss ideas, trends, and technology — not just business." },
  { id: 75, category: "Malayali", text: "They have a strong Gulf connection. Many have business interests in Dubai/UAE. If you can build software for cross-border operations, that's a huge selling point." },
  { id: 76, category: "Malayali", text: "Onam is THE festival. A genuine 'Happy Onam' with a personal touch goes a long way." },
  { id: 77, category: "Malayali", text: "They're skeptical of overselling. Be understated and let your work speak. 'Here are the results' works better than 'We're amazing.'" },
  { id: 78, category: "Malayali", text: "Malayalis value work-life balance. Don't call them at odd hours unless it's urgent. Respect boundaries and they'll respect you." },
  { id: 79, category: "Malayali", text: "Political awareness is high. They're well-read. Having an opinion on current affairs makes you a more interesting conversation partner." },

  // === DOCTORS (80-100) ===
  { id: 80, category: "Doctors", text: "Doctors have money but zero time. Your pitch must be under 3 minutes. 'Doctor, this saves your clinic 2 hours daily. Can I show you in 90 seconds?'" },
  { id: 81, category: "Doctors", text: "They understand systems and processes — medical training is all about protocols. Frame your software as a 'practice management protocol' and they'll get it instantly." },
  { id: 82, category: "Doctors", text: "Pain points: appointment scheduling, patient records, billing, follow-up reminders, prescription management. Know these before you meet." },
  { id: 83, category: "Doctors", text: "Timing: Never pitch during clinic hours. Early morning before clinic, during lunch break, or evenings after clinic. Respect their patient time." },
  { id: 84, category: "Doctors", text: "Social proof matters enormously. 'Dr. [Name] at [Hospital] uses our system' immediately validates you. Get your first doctor client and leverage that name." },
  { id: 85, category: "Doctors", text: "They'll test your system rigorously. Medical professionals are detail-oriented. Ensure your demo is flawless — no bugs, no loading delays." },
  { id: 86, category: "Doctors", text: "Data privacy is paramount. Lead with: 'Your patient data is encrypted and stored on secure, HIPAA-adjacent infrastructure.' Security sells to doctors." },
  { id: 87, category: "Doctors", text: "The spouse often manages the business side of the clinic. If the doctor says 'talk to my wife/husband about the office management,' that's your real decision-maker." },
  { id: 88, category: "Doctors", text: "Specialists (surgeons, cardiologists) charge premium fees. They expect premium service. Price accordingly — Rs 1L+ is nothing for a specialist's clinic." },
  { id: 89, category: "Doctors", text: "Address them as 'Doctor' always. Never first name. Even socially. The title is earned and they value it." },

  // === SURGEONS (90-100) ===
  { id: 90, category: "Surgeons", text: "Surgeons have God complexes (honestly). Don't challenge their ego. Frame everything as 'This system supports your excellence.' Make THEM the hero." },
  { id: 91, category: "Surgeons", text: "They appreciate precision. Your proposal should be surgical — no fluff, no ambiguity. Exact scope. Exact timeline. Exact cost. Cut the fat." },
  { id: 92, category: "Surgeons", text: "OT scheduling, patient pre-op/post-op tracking, and surgical outcome analytics — these are the software needs no generic system covers. That's your niche." },
  { id: 93, category: "Surgeons", text: "Time is literally money — they bill per surgery. Any system that saves them even 15 minutes per day is worth Rs 5L to them. Frame the ROI in their terms." },

  // === IT PROFESSIONALS (94-110) ===
  { id: 94, category: "IT Professionals", text: "They'll judge your tech stack immediately. Know your architecture cold: 'Next.js, PostgreSQL, deployed on enterprise Linux infrastructure.' No hand-waving." },
  { id: 95, category: "IT Professionals", text: "They'll ask about scalability, security, and code quality. Be ready with specific answers: 'Connection pooling, parameterized queries, role-based access control.'" },
  { id: 96, category: "IT Professionals", text: "Don't oversell to IT people. They see through marketing instantly. Be honest about limitations: 'This is what it does well. This is what it doesn't cover yet.'" },
  { id: 97, category: "IT Professionals", text: "Open source resonates. 'Built on PostgreSQL, React, Node.js — no vendor lock-in' is music to an IT professional's ears." },
  { id: 98, category: "IT Professionals", text: "They respect GitHub profiles, code quality, and documentation. If they ask to see code or architecture docs, have them ready." },
  { id: 99, category: "IT Professionals", text: "Your 25-year advantage: 'I've shipped production systems for SEBI. I've seen what scales and what breaks. That's not something you get from tutorials.'" },
  { id: 100, category: "IT Professionals", text: "Many IT professionals want to build their own tools but don't have time. Position as: 'I build it, you focus on your business. We collaborate on the architecture.'" },

  // === LAWYERS (101-115) ===
  { id: 101, category: "Lawyers", text: "Lawyers think in terms of risk, liability, and precedent. Frame your pitch: 'This system reduces operational risk and creates an audit trail for every action.'" },
  { id: 102, category: "Lawyers", text: "Case management, document tracking, deadline management, billing (timesheet-based), and client communication — these are the pain points. Know them." },
  { id: 103, category: "Lawyers", text: "Confidentiality is non-negotiable. Lead with: 'All data is encrypted, access-controlled, and we sign NDAs as standard practice.' They need to hear this." },
  { id: 104, category: "Lawyers", text: "Senior lawyers are extremely busy. Junior associates or office managers are usually the first point of contact. Build the relationship there first." },
  { id: 105, category: "Lawyers", text: "They appreciate precise language. Don't say 'around Rs 2 lakhs.' Say 'Rs 2,00,000 including GST, payable in two milestones.' Precision signals professionalism." },
  { id: 106, category: "Lawyers", text: "Address as 'Advocate [Name]' or 'Sir/Madam' until they suggest otherwise. Legal professionals value their title." },
  { id: 107, category: "Lawyers", text: "High Court and Supreme Court lawyers earn in crores. Don't undercharge them. They associate price with quality." },

  // === SOLICITORS (108-115) ===
  { id: 108, category: "Solicitors", text: "Solicitors handle property, contracts, and corporate law. Their needs: document management, client record-keeping, deadline tracking, and template management." },
  { id: 109, category: "Solicitors", text: "They often work from older offices with paper-heavy processes. Digital transformation is a HUGE opportunity. 'Let's take your filing cabinet digital.'" },
  { id: 110, category: "Solicitors", text: "Property lawyers need: agreement templates, stamp duty calculators, registration tracking, and client document vaults. Build this and sell to every solicitor in your area." },

  // === BUSINESSMEN (GENERAL) (111-125) ===
  { id: 111, category: "Businessmen", text: "Every businessman thinks in profit and loss. Always frame your software as: 'This either makes you money or saves you money. Here's how much.'" },
  { id: 112, category: "Businessmen", text: "They respect other businessmen. The fact that YOU run a business (not a job) creates instant peer-level connection. Lead with 'I'm a founder too.'" },
  { id: 113, category: "Businessmen", text: "Show understanding of their specific industry BEFORE pitching. 5 minutes of research on their business before a meeting is worth 5 hours of generic pitching." },
  { id: 114, category: "Businessmen", text: "Cash flow is their daily worry. If your software helps them collect payments faster, track receivables, or reduce waste — that's the pitch." },
  { id: 115, category: "Businessmen", text: "Referrals are currency. 'I was referred by [name]' opens every door. Always ask happy clients for introductions." },

  // === ILLITERATE BUT WEALTHY (116-130) ===
  { id: 116, category: "Illiterate Wealthy", text: "Never assume they're unintelligent. They built empires without formal education. Their business instincts are razor-sharp. RESPECT that." },
  { id: 117, category: "Illiterate Wealthy", text: "They think in concrete terms, not abstractions. Don't say 'analytics dashboard.' Say 'You'll see exactly how much each shop sold today, in one screen.'" },
  { id: 118, category: "Illiterate Wealthy", text: "Visual demos work best. Show them the software running. Let them touch the phone/tablet. Hands-on experience beats any presentation." },
  { id: 119, category: "Illiterate Wealthy", text: "Their children or grandchildren often translate tech decisions. Build rapport with BOTH generations — the elder decides, the younger validates." },
  { id: 120, category: "Illiterate Wealthy", text: "Speak in their language — literally. Hindi, Gujarati, Kutchi — whatever they're comfortable with. They'll trust you more in their mother tongue." },
  { id: 121, category: "Illiterate Wealthy", text: "They value loyalty above all. Be available. Be responsive. Be consistent. They don't want the best technology — they want the most reliable PERSON." },
  { id: 122, category: "Illiterate Wealthy", text: "Price conversations: use round numbers. 'Rs 1 lakh' not 'Rs 97,500.' They think in lakhs and crores. Make it simple." },
  { id: 123, category: "Illiterate Wealthy", text: "They've been cheated before — by accountants, by partners, by technology vendors. Your biggest selling point is TRUST. Build it slowly, don't rush." },
  { id: 124, category: "Illiterate Wealthy", text: "Offer to train their staff personally. 'I'll come to your office and teach your people.' This hands-on commitment is what they value most." },
  { id: 125, category: "Illiterate Wealthy", text: "Never make them feel stupid. If they ask a basic question, answer with full respect: 'That's a great question. Here's how it works...' Dignity is everything." },

  // === EXTREMELY POLISHED PEOPLE (126-140) ===
  { id: 126, category: "Polished Elite", text: "Match their energy — refined, measured, articulate. No filler words. No slang. Speak like you belong in their circle, because you do." },
  { id: 127, category: "Polished Elite", text: "They notice everything: your shoes, your watch, your vocabulary, your posture. Every detail is being evaluated. Come prepared on all fronts." },
  { id: 128, category: "Polished Elite", text: "Don't try to impress — be impressive. There's a difference. Trying shows. Being natural commands." },
  { id: 129, category: "Polished Elite", text: "They value brevity and substance. If you can make your point in 3 sentences, don't use 10. Rambling is the fastest way to lose their respect." },
  { id: 130, category: "Polished Elite", text: "Name-drop strategically but sparingly. 'In our engagement with SEBI...' once is powerful. Twice is insecure." },
  { id: 131, category: "Polished Elite", text: "Send a handwritten thank-you note after an important meeting. In a world of WhatsApp messages, a handwritten note is extraordinarily memorable." },
  { id: 132, category: "Polished Elite", text: "Wine/whisky knowledge: you don't need to be an expert, but knowing the difference between a single malt and a blend helps at these tables." },
  { id: 133, category: "Polished Elite", text: "They respect people who can hold their own intellectually. Read one book per month. Have opinions on business, economics, and global affairs." },

  // === TRADERS (134-145) ===
  { id: 134, category: "Traders", text: "Traders live by the minute. Speed is EVERYTHING. Your system must be fast — real-time data, instant calculations, zero lag. Demonstrate speed." },
  { id: 135, category: "Traders", text: "They need: price tracking, profit/loss per trade, portfolio dashboards, alert systems, and reporting for tax purposes. Know these pain points." },
  { id: 136, category: "Traders", text: "Risk is their daily reality. Frame your software as a risk management tool: 'This gives you visibility into your exposure in real-time.'" },
  { id: 137, category: "Traders", text: "They'll want mobile access. 'Check your positions from your phone while at coffee' is a selling point that resonates immediately." },
  { id: 138, category: "Traders", text: "Confidentiality is critical. Their trading strategies are proprietary. Lead with data security and NDAs." },

  // === MANUFACTURERS (139-150) ===
  { id: 139, category: "Manufacturers", text: "Manufacturers think in terms of production, quality, and margins. Frame software as: 'This reduces waste by X% and improves production tracking.'" },
  { id: 140, category: "Manufacturers", text: "They need: production scheduling, inventory management, quality control tracking, dispatch/logistics, and vendor management." },
  { id: 141, category: "Manufacturers", text: "Factory visits are the best sales tool. Ask to see their operations. You'll spot 10 problems their ERP doesn't solve. Each problem is a project." },
  { id: 142, category: "Manufacturers", text: "They're used to dealing with large ERP vendors (SAP, Oracle). Position as: 'We build the custom modules your ERP can't — specific to YOUR process.'" },
  { id: 143, category: "Manufacturers", text: "Safety helmets and closed shoes when visiting a factory floor. This shows you respect their environment. They notice." },

  // === BUILDERS / CONSTRUCTION (144-155) ===
  { id: 144, category: "Builders", text: "Construction people are practical and visual. Show them a mobile dashboard: 'Every project site, every worker count, every material delivery — on your phone.'" },
  { id: 145, category: "Builders", text: "They need: project tracking (site-wise), material inventory, labor management, payment tracking to contractors, and compliance documentation." },
  { id: 146, category: "Builders", text: "Builders deal with multiple sites simultaneously. Real-time visibility across sites is the killer feature they'll pay premium for." },
  { id: 147, category: "Builders", text: "Cash flow tracking is critical in construction. 'Which site is profitable? Which is bleeding money?' If your software answers this, you have a client." },
  { id: 148, category: "Builders", text: "They're used to jugaad (makeshift solutions). Don't fight it — work with it. 'Let's digitize your existing process, not replace it.'" },
  { id: 149, category: "Builders", text: "Safety and compliance documentation is increasingly important. RERA compliance tracking software is a gap nobody has filled well." },

  // === GOVERNMENT OFFICIALS (150-165) ===
  { id: 150, category: "Government", text: "Government officials follow PROCESS. Everything needs documentation, approval chains, and proper proposals. There are no shortcuts. Accept this." },
  { id: 151, category: "Government", text: "Decision-making is committee-based. You'll present to one person but 5 people decide. Make sure your proposal works on paper even if you're not in the room." },
  { id: 152, category: "Government", text: "Budget cycles matter. Government budgets are allocated in April. Pitch in January-February for the next financial year's budget." },
  { id: 153, category: "Government", text: "Use their language: 'Tender', 'work order', 'compliance', 'audit trail', 'GeM portal.' Knowing government procurement terminology signals experience." },
  { id: 154, category: "Government", text: "Your SEBI credential is GOLDEN here. Government trusts government references. 'We've delivered for SEBI' opens every government door." },
  { id: 155, category: "Government", text: "Officers rotate every 2-3 years. Build relationships with the DEPARTMENT, not just the officer. The department stays, the person moves." },
  { id: 156, category: "Government", text: "Never discuss bribes or 'facilitation fees.' Walk away from any such request. One corruption scandal can destroy your entire business reputation." },
  { id: 157, category: "Government", text: "Patience is mandatory. Government projects take 6-12 months from first meeting to work order. Factor this into your pipeline planning." },
  { id: 158, category: "Government", text: "Dress formally for government meetings. Full shirt, trousers, leather shoes. They operate in a formal environment and expect vendors to match." },

  // === CHARTERED ACCOUNTANTS (159-170) ===
  { id: 159, category: "CAs", text: "CAs are the hidden influencers of Indian business. Every business owner trusts their CA more than anyone. Get CAs to recommend you and deals flow automatically." },
  { id: 160, category: "CAs", text: "They need: practice management, client deadline tracking (ITR, GST, audit schedules), document management, and billing/time tracking." },
  { id: 161, category: "CAs", text: "Don't compete with Tally — complement it. 'We build what Tally doesn't do — client portals, deadline tracking, and automated compliance reminders.'" },
  { id: 162, category: "CAs", text: "CAs talk to each other. CA associations (ICAI chapters) are tight networks. One happy CA client = 10 referrals minimum." },
  { id: 163, category: "CAs", text: "They appreciate precision in billing. Itemize everything in your invoices. CAs judge you by your invoices — messy invoice = messy work." },

  // === REAL ESTATE AGENTS / BROKERS (164-172) ===
  { id: 164, category: "Real Estate", text: "Brokers need: property listing management, client matching, site visit scheduling, brokerage tracking, and deal pipeline management." },
  { id: 165, category: "Real Estate", text: "They're always on the move. Mobile-first is mandatory. If it doesn't work perfectly on a phone, they won't use it." },
  { id: 166, category: "Real Estate", text: "Commission tracking is their #1 pain point. 'Which deals are closing? What's my commission pipeline?' Build this and they'll love you." },
  { id: 167, category: "Real Estate", text: "They know EVERYONE. A happy real estate broker refers you to all their developer clients, bank contacts, and buyer network. Treat them well." },

  // === WOMEN ENTREPRENEURS (168-178) ===
  { id: 168, category: "Women Entrepreneurs", text: "Professional courtesy first. Address by name and title, not gender. 'Ms. Mistry' or her preferred form. Never assume informality." },
  { id: 169, category: "Women Entrepreneurs", text: "Many women entrepreneurs have fought harder than their male counterparts to get where they are. Acknowledge their achievements genuinely — they're earned, not given." },
  { id: 170, category: "Women Entrepreneurs", text: "They often value attention to detail and thorough planning more than speed. Come extra prepared to meetings." },
  { id: 171, category: "Women Entrepreneurs", text: "Recommendations from other women entrepreneurs carry enormous weight. Build one strong relationship and the women's entrepreneur network opens up." },
  { id: 172, category: "Women Entrepreneurs", text: "Don't talk down or oversimplify. Many are highly educated (like Yasmin — BCom, MCom, Doctorate). Match their intellectual level." },

  // === RETIRED EXECUTIVES (173-182) ===
  { id: 173, category: "Retired Execs", text: "Your 60+ coffee group members are retired executives. They have connections, knowledge, and time. They may not need software — but they KNOW people who do." },
  { id: 174, category: "Retired Execs", text: "Ask for advice, not business. 'Uncle, you've seen many businesses. What do you think about this approach?' They love being consulted." },
  { id: 175, category: "Retired Execs", text: "Many retired executives sit on boards of trusts, societies, and family businesses. They influence tech decisions even if they don't use tech themselves." },
  { id: 176, category: "Retired Execs", text: "Respect their stories. When they share past experiences, listen fully. These stories contain business wisdom and hidden introductions." },

  // === YOUNG ENTREPRENEURS / STARTUP FOUNDERS (177-185) ===
  { id: 177, category: "Young Founders", text: "They speak startup language — MVP, pivot, runway, product-market fit. Use this vocabulary and you're on their wavelength instantly." },
  { id: 178, category: "Young Founders", text: "They'll challenge your tech choices. Be ready: 'Why not just use no-code?' Answer: 'No-code works for prototypes. We build for scale and customization.'" },
  { id: 179, category: "Young Founders", text: "Speed impresses them. 'I can have an MVP in 3 weeks.' They value velocity because they're burning cash and racing against time." },
  { id: 180, category: "Young Founders", text: "They may not have money yet. Offer equity + cash models or deferred payment for promising startups. If they succeed, you succeed." },
  { id: 181, category: "Young Founders", text: "Your age is your advantage here. 'I've seen 5 technology cycles. I know what survives and what doesn't. That experience protects your investment.'" },

  // === PARSIS (182-190) ===
  { id: 182, category: "Parsi", text: "Parsis are a small but incredibly accomplished community. They value integrity, education, and community contribution above wealth display." },
  { id: 183, category: "Parsi", text: "They appreciate quality over quantity. A well-crafted proposal beats a flashy presentation. Substance always wins with Parsis." },
  { id: 184, category: "Parsi", text: "Many Parsis are in manufacturing, hospitality (Taj Group heritage), and professional services. They operate at high standards — match them." },
  { id: 185, category: "Parsi", text: "Navroz (Parsi New Year) is important. A personalized greeting shows you see them as individuals, not just clients." },
  { id: 186, category: "Parsi", text: "They're direct communicators — more Western in business style than most Indian communities. Be clear, professional, and efficient with their time." },
  { id: 187, category: "Parsi", text: "Community is small and tight-knit. One referral from a respected Parsi opens multiple doors. Your relationship with Yasmin Mistry is exactly this kind of asset." },

  // === MARWARIS (188-198) ===
  { id: 188, category: "Marwari", text: "Marwaris are India's financial backbone — jewellery, textiles, finance, trading. They think in margins and have calculator-sharp minds." },
  { id: 189, category: "Marwari", text: "They WILL negotiate. It's in their DNA. Don't take it as disrespect. Quote 20% above your target and negotiate to where you want to be." },
  { id: 190, category: "Marwari", text: "Joint family businesses are common. The elder brother or father has final say. Even if the younger generation likes your pitch, the patriarch decides." },
  { id: 191, category: "Marwari", text: "Community connections are everything. Marwari business associations are powerful. Get in through one member and the network opens." },
  { id: 192, category: "Marwari", text: "They value long-term relationships. A Marwari who trusts you will give you business for decades. Invest in the relationship — the returns are generational." },
  { id: 193, category: "Marwari", text: "Accounting and finance software is their bread and butter. But they already have Tally. Sell what Tally can't do — custom reports, client portals, inventory beyond accounting." },

  // === SCHOOL/COLLEGE PRINCIPALS & EDUCATORS (194-200) ===
  { id: 194, category: "Educators", text: "Educators are mission-driven. Frame software as 'improving student outcomes' not 'saving time.' They care about impact more than efficiency." },
  { id: 195, category: "Educators", text: "Budget is always tight. Offer a pilot program: 'Let's run it for one department free for a month. You'll see the impact before investing.'" },
  { id: 196, category: "Educators", text: "School management software needs: admissions, attendance, fee collection, report cards, parent communication, and timetable management." },
  { id: 197, category: "Educators", text: "The principal decides but the school secretary/admin staff must approve the usability. Demo to BOTH audiences — technical and non-technical." },
  { id: 198, category: "Educators", text: "One school leads to the entire education trust. Trusts often run 5-10 schools. One deployment × 10 schools = massive recurring revenue." },

  // === NRIs (NON-RESIDENT INDIANS) (199-207) ===
  { id: 199, category: "NRIs", text: "NRIs often have Indian businesses managed by family. They need remote visibility: dashboards, reports, and alerts they can check from abroad." },
  { id: 200, category: "NRIs", text: "They compare your pricing to US/UK rates. Rs 2L sounds cheap to someone earning in dollars. Don't undersell — they expect international quality." },
  { id: 201, category: "NRIs", text: "Video calls are their primary meeting mode. Be sharp on Zoom/Meet — good camera, lighting, background. This IS their in-person meeting." },
  { id: 202, category: "NRIs", text: "Time zone awareness: schedule calls for their morning (your evening) or overlap hours. Being flexible signals professionalism." },
  { id: 203, category: "NRIs", text: "They value documentation and contracts more than Indian clients (Western business influence). Have proper SOWs and contracts ready." },

  // === ARMY / DEFENCE PERSONNEL (204-210) ===
  { id: 204, category: "Defence", text: "Military personnel respect: discipline, punctuality, precision, and hierarchy. Be on time. Be organized. Be direct. No fluff." },
  { id: 205, category: "Defence", text: "Address by rank: Colonel, Major, General. Never first name. The rank was earned through decades of service." },
  { id: 206, category: "Defence", text: "They think in terms of operations, logistics, and security. Frame software in military terms: 'operational readiness', 'threat monitoring', 'situational awareness.'" },
  { id: 207, category: "Defence", text: "Security clearance and data sovereignty matter. 'All data stored on Indian servers with military-grade encryption.' This is not optional — it's expected." },
  { id: 208, category: "Defence", text: "Your SEBI + Indian Army credential combination is UNIQUE. Very few vendors can claim both. Use it prominently when pitching to defence organizations." },
  { id: 209, category: "Defence", text: "Government procurement for defence is slow but large. Contracts can be Rs 10L-1Cr. Patience and persistence are required." },
  { id: 210, category: "Defence", text: "Col. Gopinath at SEBI is your door into defence-adjacent work. Even if that deal is slow, the credential you build there opens doors to other government defence work." },
];
