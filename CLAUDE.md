# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MMAM (Make Me A Millionaire) — a personal AI coach + business management app for Ashish Kamdar (51, software developer, 25+ years experience). Covers personality development, grooming, body language, business strategy, CRM pipeline, client management, proposals, and motivation. Targets the wealthy Kutchi business community at Matunga Gymkhana, Mumbai.

## Tech Stack

- **Framework:** Next.js 16 (App Router, TypeScript)
- **Styling:** Tailwind CSS — warm stone/amber palette, dark + light mode
- **AI Providers:** Google Gemini (free, primary) + Anthropic Claude (paid, secondary)
- **Database:** PostgreSQL 16 on server (`mmam_db` / `mmam_user` / `mmam_secure_2026`)
- **PWA:** Service worker for offline mode, IndexedDB sync queue
- **Auth:** 4-digit PIN lock, 30-day session persistence
- **Deployment:** Self-hosted on nginx + PM2 at https://mmam.areakpi.in (port 3200)
- **Report Generation:** `docx` + `file-saver` for Word document export with company letterhead

## Commands

```bash
npm run dev          # Start dev server
npx next build       # Build for production
npm start            # Start production server
```

## Deployment

```bash
# Sync and deploy
rsync -avz --exclude node_modules --exclude .git --exclude .next src/ nuremberg:/root/Projects/mmam/src/
ssh nuremberg "cd /root/Projects/mmam && npx next build && pm2 restart mmam"

# Bump service worker cache (forces mobile refresh) — increment the version number
ssh nuremberg "sed -i 's/mmam-vN/mmam-vN+1/g' /root/Projects/mmam/public/sw.js"
```

- Server: `ssh nuremberg` (root access)
- PM2 process name: `mmam` (port 3200)
- Nginx config: `/etc/nginx/sites-enabled/mmam`
- SSL: Let's Encrypt auto-renew
- Database: `sudo -u postgres psql -d mmam_db`
- Database tables: `projects`, `gymkhana_contacts`, `pipeline`, `proposals`, `products`, `follow_ups`, `coaching_entries`, `journal_entries`, `revenue_entries`, `weekly_reviews`, `whatsapp_templates`, `tech_reports`

## What's Built (27 pages)

### Personal Development
| Page | Route | Storage | Description |
|------|-------|---------|-------------|
| Motivation | `/motivation` | localStorage | 376 custom motivation cards across 29 categories with heart/favourite |
| Arvindbhai | `/arvindbhai` | localStorage | 318 quotes from father-in-law's WhatsApp export |
| Rebuild Me | `/personality` | localStorage | Daily grooming checklist (22 items), wardrobe guide, body language, speech guide |
| Polish You | `/polish-you` | Static | 880 tips across 9 sections: conversation, social intelligence, dining etiquette, language, digital presence, networking, personal brand, emotional intelligence, presence & aura |
| Event Prep | `/event-prep` | Gemini API | 35+ event types → AI generates complete grooming/outfit/behavior guide |
| Journal | `/journal` | PostgreSQL | Daily entries — mood, energy, grooming, people met, wins, challenges |
| Weekly Review | `/weekly-review` | PostgreSQL | End-of-week reflection and goal setting |

### Business Operations
| Page | Route | Storage | Description |
|------|-------|---------|-------------|
| Today | `/today` | PostgreSQL | Daily command center — follow-ups, money collection, blocked projects, habits, all in priority order |
| Pipeline | `/pipeline` | PostgreSQL | CRM pipeline: Aware → Interested → Meeting → Proposal → Negotiating → Won/Lost |
| Follow-ups | `/follow-ups` | PostgreSQL | Color-coded: overdue (red), due today (amber), upcoming, completed. "Done" opens in-app modal (not browser prompt — fixed for iOS Safari) to capture outcome. |
| Projects | `/projects` | PostgreSQL | Interactive cards — inline status change, editable blockers, next steps, collapsible conversation logs |
| Proposals | `/proposals` | PostgreSQL | Create proposals → "Copy for WhatsApp" generates formatted text. Track draft/sent/accepted/rejected |
| Products | `/products` | PostgreSQL | 3 productized offerings with pricing, features, target audience. Millionaire math calculator |
| Revenue | `/revenue` | PostgreSQL | Income/expense tracker with profit summary |
| Gymkhana | `/gymkhana` | PostgreSQL | Track contacts at Matunga Gymkhana — relationship, business, software needs, next move |
| Approach | `/approach` | Gemini API | Enter person → tailored approach strategy powered by community research for 8 Indian communities |

### Tools & Reference
| Page | Route | Storage | Description |
|------|-------|---------|-------------|
| Coach | `/coach` | PostgreSQL | Ask AI directly (Gemini) OR paste from claude.ai → saved to database permanently |
| Chat | `/chat` | localStorage | AI chat with streaming (Gemini/Claude), session history |
| WhatsApp | `/whatsapp` | PostgreSQL | 12+ message templates — tap to copy, paste into WhatsApp |
| Online Work | `/online-work` | Gemini API | Freelance platforms, quick money moves, rate calculator |
| Suggestions | `/suggestions` | localStorage | Saved AI advice with paste-from-clipboard, category filters |
| Portfolio | `/portfolio` | Static | Public-facing page showcasing projects and services |
| Dashboard | `/` | Mixed | Morning Launch (motivation card + 5 rotating power checks from 1,910-tip pool + due follow-up + "More Tips" button for unlimited sets) → then welcome, daily tips, project summary, focus areas. Recharge button to revisit power checks anytime. |
| Settings | `/settings` | localStorage | Gemini/Anthropic API keys, provider selection, system prompt |
| Executive MBA | `/executive` | localStorage | Executive tips browser with categories, search, favourites, shuffle. Standalone page — no sub-links. |
| Architecture Deep-Dive | `/executive/architecture` | Static | Own menu under "Knowledge Base". 12 tabbed sections: VISA (65K TPS), Netflix, UPI, Docker/K8s/Standard, High Traffic, System Design Patterns, Payment Gateways, Real-Time Chat (WhatsApp/Slack), Search Engines, Authentication (OAuth/JWT/SSO), Mobile Architecture, Microservices. All with ASCII diagrams, comparison tables, real-world examples. |
| Tech Stack Advisor | `/executive/tech-advisor` | PostgreSQL | Own menu under "Client Projects". 6-step wizard: App Type → Scale → Features → Compliance → Infrastructure → Budget (+ optional client/project name). Generates 35-section report: architecture diagram, tech stack, security, server specs, licensing, dev phases, milestones, human + AI resources, backup/DR, performance targets, scalability roadmap, tech alternatives, 3-year cost projection, compliance checklist, go-live checklist, maintenance plan, training plan, risk assessment, scope of work (in/out/assumptions/constraints), communication plan (meetings/escalation/tools), testing strategy & QA plan (types/quality gates), acceptance criteria (per-area + sign-off process), change request process (steps/pricing), stakeholder RACI matrix, environment strategy, notification providers, infrastructure cost breakdown, WhatsApp summary (mobile phone preview with client name). Download as 26-section Word document (AREA KPI letterhead, client name on title page, page numbering). Save to PostgreSQL + browse/load/delete saved reports. |

### API Routes (13)
| Route | Methods | Database Table |
|-------|---------|----------------|
| `/api/projects` | GET, POST, PUT, DELETE | `projects` |
| `/api/gymkhana` | GET, POST, PUT, DELETE | `gymkhana_contacts` |
| `/api/pipeline` | GET, POST, PUT, DELETE | `pipeline` |
| `/api/proposals` | GET, POST, PUT, DELETE | `proposals` |
| `/api/products` | GET, POST, PUT | `products` |
| `/api/follow-ups` | GET, POST, PUT, DELETE | `follow_ups` |
| `/api/coaching` | GET, POST, DELETE | `coaching_entries` |
| `/api/journal` | GET, POST, DELETE | `journal_entries` |
| `/api/revenue` | GET, POST, DELETE | `revenue_entries` |
| `/api/weekly-review` | GET, POST | `weekly_reviews` |
| `/api/whatsapp-templates` | GET, POST, DELETE | `whatsapp_templates` |
| `/api/chat` | POST | — (streaming, supports Gemini + Anthropic) |
| `/api/tech-reports` | GET (list + single by `?id=`), POST, DELETE | `tech_reports` |

### Components (6)
| Component | Description |
|-----------|-------------|
| `sidebar.tsx` | App shell, 28 nav items grouped into 6 sections (Personal Growth, Business, Knowledge Base, Client Projects, Tools, Reflect) with divider lines and labels. Dark/light toggle, user avatar. |
| `theme-provider.tsx` | Dark/light mode context |
| `auth-gate.tsx` | 4-digit PIN lock with numeric keypad, 30-day persistence. Stores PIN + auth token in both cookies AND localStorage for mobile reliability. |
| `pwa-provider.tsx` | Service worker registration, offline/online detection, sync |
| `daily-tips.tsx` | 35 rotating tips across grooming/posture/speech/aura/business |
| `projects-summary.tsx` | Dashboard widget pulling from PostgreSQL |

### Data Files (22)
| File | Description |
|------|-------------|
| `lib/db.ts` | PostgreSQL connection pool |
| `lib/ai-config.ts` | AI provider/key helper |
| `lib/motivation-cards.ts` | 694 motivation cards (376 custom + 318 Arvindbhai) |
| `lib/community-research.ts` | Deep research on 8 Indian business communities |
| `lib/conversation-tips.ts` | 94 conversation mastery tips for Polish You |
| `lib/social-intelligence-tips.ts` | 96 social intelligence tips for Polish You |
| `lib/dining-etiquette-tips.ts` | 103 dining & social etiquette tips for Polish You |
| `lib/language-tips.ts` | 100 language & communication tips for Polish You |
| `lib/digital-presence-tips.ts` | 97 digital presence & messaging tips for Polish You |
| `lib/networking-tips.ts` | 100 networking tips for Polish You |
| `lib/personal-brand-tips.ts` | 100 personal brand building tips for Polish You |
| `lib/emotional-intelligence-tips.ts` | 93 emotional intelligence tips for Polish You |
| `lib/presence-aura-tips.ts` | 97 presence & aura tips for Polish You |
| `lib/power-checks.ts` | Morning Power Check pool aggregator — imports all tip files, seeded daily rotation with theme diversity |
| `lib/executive-corporate-language.ts` | 200 corporate phrases & sentences with usage context |
| `lib/executive-strategic-thinking.ts` | 200 MBA frameworks, mental models, and strategic questions |
| `lib/executive-communication.ts` | 200 executive communication tips — speaking, pitching, closing |
| `lib/executive-financial-fluency.ts` | 200 financial terms, metrics, pricing strategy, wealth language |
| `lib/executive-ceo-speaks.ts` | 500 tips: CEO sentences (100), attitude modification (100), stress/composure (100), handling difficult people (100), body language (100) |
| `lib/executive-decoder.ts` | 200 "What they say → What they actually mean" decoder tips |
| `lib/executive-techie-talks.ts` | 221 technical jargon with plain English meanings — legacy to modern + real dev sentences decoded |
| `lib/executive-high-traffic.ts` | 150 high-traffic architecture tips — VISA, Netflix, Docker/K8s, hardware tuning |

### Morning Power Check System
Total pool: **1,910 tips** across 15 themes. Dashboard shows 5 per set with "More Tips" button for unlimited rounds. Seeded shuffle ensures same 5 for a given day (deterministic), theme-diversity algorithm picks from different categories each set. Themes: presence, social, mindset, business, grooming, relationships, discipline, corporate-language, strategic-thinking, exec-communication, financial-fluency, ceo-speaks, attitude, stress-calm, difficult-people, body-language, decoder, techie-talks, high-traffic.

### Architecture Deep-Dive Page (`/executive/architecture`)
12 tabbed sections split across 3 files for fast loading:
| File | Sections |
|------|----------|
| `page.tsx` | VISA, Netflix, UPI, Docker/K8s/Standard, High Traffic, System Design Patterns |
| `sections-extended.tsx` | Payment Gateways (Razorpay/Stripe), Real-Time Chat (WhatsApp/Slack), Search Engines (Google/Elasticsearch), Authentication (OAuth/JWT/SSO), Mobile Architecture (RN/Flutter/Native) |
| `sections-microservices.tsx` | Microservices: architecture patterns, API Gateway, Service Mesh, Saga pattern, licensing (12 technologies), hardware by scale, team sizing (Amazon two-pizza rule), decision framework, migration path (Strangler Fig), observability stack |

### Tech Stack Advisor (`/executive/tech-advisor`)
6-step wizard → 35-section recommendation + 26-section Word report. Split across 3 files:
| File | Purpose |
|------|---------|
| `page.tsx` | Wizard UI (+ client/project name fields), recommendation engine, results display, saved reports browser (load/delete) |
| `project-planner.ts` | 23 plan generators: licensing, hardware, phases, resources, risks, milestones, total cost, backup/DR, environments, notifications, maintenance, scalability, go-live checklist, performance targets, tech alternatives, 3-year projections, compliance, training, scope of work, communication plan, testing strategy, acceptance criteria, change request process, RACI matrix, WhatsApp summary |
| `report-generator.ts` | DOCX generation with AREA KPI letterhead, client/project name on title page, 26-section Word report, page numbering |

## Active Projects (in database)

| Client | Project | Status | Price |
|--------|---------|--------|-------|
| Sunil Saiya (JSG) | Event ticketing + scanner (1050 members) | Delivered (Free) | Free |
| Sunil's Daughter | Olistic Studios fitness software | In Progress | Rs 2,25,000 (Rs 1L advance expected by ~Apr 7) |
| Narayanji Shamji (Nirmal Bhai) | Members CRUD + insights | Blocked (Uttambhai) — Apr 15 final touchpoint, patience exhausted | ~Rs 20K |
| Jain Jagruti Sangh (Rohit Gangar) | Ticketing (like JSG) | Quoted | TBD |
| SEBI India — PNS Dept (Col. Gopinath) | Surveillance system | Blocked | Maintenance TBD (Rs 3L/yr target) |

## Sales Pipeline (in database)

| Lead | Company | Stage | Potential |
|------|---------|-------|-----------|
| Rupen Sheth (Gymkhana) | Networking & Security Co (VAPT, infra) | Interested — showed WhatsApp bot demo, called and explained capabilities, shared areakpi.in. Offered subcontract/commission/flexible models. Won't cold call for me — needs organic pull. | HIGH — 300 clients, channel partner potential |
| Yasmin Mistry | Durand Forms India + Mistry Logistics + YM Securities | Cold — went silent | Rs 10-30L (3 companies) |
| Rohit Gangar | Jain Jagruti Sangh | Aware | Rs 50K-1L |
| Niyam (Gymkhana) | Gold/crypto software | Cold — promised team meeting, never followed up | TBD |

## Also Managed

- **JSG landing page** at `jsg1.areakpi.in` — Flask app at `/var/www/jsg-seating/`, updated with Past Dramas, Upcoming Events, WhatsApp CTA
- **areakpi.in** — company website (staging at staging1.areakpi.in, managed separately)
- Company: **AREA KPI Technology** | WhatsApp: +919819800214

## Design Constraints

- **No blue-on-gray** — warm amber/gold accent on stone neutrals
- **Mobile-first** — primary use is on phone, large touch targets
- **Dark mode default** with light mode toggle
- **No login fatigue** — 4-digit PIN, 30-day session
- **Offline capable** — service worker caches all pages, syncs when online
- **Company image** — present as a company with employees, not solo freelancer
- **Letterhead:** `public/letterhead.jpg` — AREA KPI Technology branded header for Word reports
- UI reference: `~/Downloads/Catalyst-tailwind-css-UI-Blocks-634/`

## User Context (Ashish Kamdar)

- 51 years old, athletic (badminton, swimming daily)
- Father of 2 girls, husband, caretaker of 74-year-old mother
- 25+ years software development experience
- Company: AREA KPI Technology, Mumbai
- Daily at Matunga Gymkhana — part of "millionaires club" Kutchi coffee group (60+ yr olds)
- Credential: built surveillance system for SEBI India
- Working on personality rebuild — wife flagged negative energy
- Financially stressed (stock market losses) — needs income NOW
- Community: Kutchi/Jain business network in Matunga

## What's Left to Build

### High Priority
- [ ] Individual project detail pages (`/projects/[id]`) with full conversation timeline
- [ ] Revenue goals dashboard with monthly targets and progress bars
- [ ] Migrate suggestions + chat sessions from localStorage to PostgreSQL
- [ ] Push notifications for follow-up reminders

### Medium Priority
- [ ] Testimonial collector — draft, send to client for approval, publish
- [ ] Gymkhana department-wise analytics
- [ ] Revenue charts with monthly trends
- [ ] Export projects/contacts as PDF
- [ ] Daily journal streak tracker and mood graphs
- [ ] Pipeline conversion analytics (aware → won rate)

### Nice to Have
- [ ] Voice-to-text for quick journal entries on mobile
- [ ] Calendar integration for follow-up dates
- [ ] WhatsApp deep links from project cards
- [ ] QR code for portfolio page
- [ ] Multiple WhatsApp export imports
- [ ] AI-powered weekly summary
- [ ] Auto-suggest follow-ups based on project activity
