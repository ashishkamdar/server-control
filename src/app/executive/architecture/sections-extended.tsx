import React from "react";

// Re-export types and helpers for use in the main page
export type Section = {
  id: string;
  title: string;
  icon: string;
  content: React.ReactNode;
};

function Diagram({ title, children }: { title: string; children: string }) {
  return (
    <div className="my-4 overflow-x-auto rounded-xl border border-accent/20 bg-[#1a1a2e] p-4 sm:p-6">
      <p className="mb-3 text-xs font-bold uppercase tracking-wider text-accent">{title}</p>
      <pre className="whitespace-pre text-xs leading-relaxed text-emerald-400 sm:text-sm">{children}</pre>
    </div>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="my-4 overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-hover">
            {headers.map((h) => (
              <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-border/50 last:border-0">
              {row.map((cell, j) => (
                <td key={j} className={`px-4 py-3 ${j === 0 ? "font-medium" : "text-muted"}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <p className="text-xs font-medium text-muted">{label}</p>
      <p className="mt-1 font-mono text-2xl font-bold text-accent">{value}</p>
      {sub && <p className="mt-1 text-xs text-muted">{sub}</p>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SECTION: PAYMENT GATEWAYS
// ═══════════════════════════════════════════════════════════════
export const paymentGatewaySection: Section = {
  id: "payment-gateways",
  title: "Payment Gateway Internals — Razorpay, Stripe",
  icon: "💰",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Stripe Volume" value="$1T+" sub="Annual processing" />
        <Stat label="Razorpay TPS" value="5,000+" sub="Peak transactions/sec" />
        <Stat label="Auth Time" value="<2 sec" sub="End-to-end" />
        <Stat label="Uptime SLA" value="99.99%" sub="~52 min downtime/year" />
      </div>

      <h3 className="mb-2 text-lg font-bold">How a Payment Gateway Works (Razorpay/Stripe)</h3>
      <p className="mb-4 text-sm text-muted">When a customer pays Rs 5,000 on your website, here&apos;s the full journey:</p>

      <Diagram title="Payment Gateway Transaction Flow">{`
  ┌──────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
  │ Customer │────▶│  Your App    │────▶│  Payment     │────▶│  Card    │
  │ Browser  │     │  (Frontend)  │     │  Gateway     │     │ Network  │
  └──────────┘     └──────────────┘     │ (Razorpay/   │     │(VISA/MC) │
                                        │  Stripe)     │     └────┬─────┘
                                        └──────┬───────┘          │
                                               │                  ▼
                                               │           ┌──────────┐
                                               │           │ Issuing  │
                                               │           │ Bank     │
                                               │           │ (HDFC)   │
                                               │           └────┬─────┘
                                               │                │
                                               ◀────────────────┘

  STEP-BY-STEP:
  ═════════════
  1. CHECKOUT: Customer enters card on YOUR site
     → Card data goes to Razorpay (never touches your server — PCI compliance)

  2. TOKENIZATION: Razorpay replaces card number with a token
     → "4111-1111-1111-1111" becomes "tok_abc123xyz"
     → Your server only sees the token, never the real card number

  3. AUTHORIZATION: Razorpay → Card Network (VISA) → Issuing Bank
     → Bank checks: valid card? sufficient balance? fraud risk?
     → Returns: APPROVED or DECLINED with auth code

  4. 3D SECURE (if required): Customer enters OTP
     → Extra security layer mandated by RBI for Indian cards
     → Adds 5-10 seconds but reduces fraud dramatically

  5. CAPTURE: Money is "held" on the card (not yet transferred)
     → Merchant can capture immediately or later (hotel pre-auth)

  6. SETTLEMENT: Razorpay batches all captures → sends to banks
     → Money arrives in merchant account in T+2 days (India)
     → Stripe: T+2 to T+7 days depending on country`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Payment Gateway Internal Architecture</h3>

      <Diagram title="Razorpay/Stripe Internal Architecture">{`
  ┌─────────────────────────────────────────────────────────────┐
  │                    API GATEWAY LAYER                        │
  │  Rate Limiting │ Authentication │ Request Validation        │
  └────────────────────────┬────────────────────────────────────┘
                           │
  ┌────────────────────────▼────────────────────────────────────┐
  │                   CORE SERVICES                             │
  │                                                             │
  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
  │  │ Payment │  │  Fraud   │  │ Routing  │  │  Webhook   │  │
  │  │ Engine  │  │ Detection│  │ Engine   │  │  Delivery  │  │
  │  │         │  │ (ML/AI)  │  │          │  │            │  │
  │  │ Create  │  │          │  │ Chooses  │  │ Notifies   │  │
  │  │ Capture │  │ Score    │  │ best     │  │ merchant   │  │
  │  │ Refund  │  │ each txn │  │ bank/PSP │  │ of events  │  │
  │  └────┬────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘  │
  │       │            │             │               │          │
  └───────┼────────────┼─────────────┼───────────────┼──────────┘
          │            │             │               │
  ┌───────▼────────────▼─────────────▼───────────────▼──────────┐
  │                    DATA LAYER                               │
  │                                                             │
  │  PostgreSQL    │  Redis       │  Kafka        │  S3         │
  │  (Transactions)│  (Cache,     │  (Event       │  (Invoices, │
  │               │   Sessions)  │   Stream)     │   Reports)  │
  └─────────────────────────────────────────────────────────────┘
          │
  ┌───────▼─────────────────────────────────────────────────────┐
  │                 BANKING INTEGRATION LAYER                   │
  │                                                             │
  │  VISA/MC    │  RuPay/UPI  │  Net Banking  │  Wallets       │
  │  (ISO 8583) │  (NPCI API) │  (Bank APIs)  │  (PhonePe etc) │
  └─────────────────────────────────────────────────────────────┘

  KEY CHALLENGES:
  ═══════════════
  • IDEMPOTENCY: Same request must produce same result (no double charge)
  • PCI-DSS: Card data encrypted at rest + transit, strict access control
  • RECONCILIATION: Match every transaction with bank settlement daily
  • RETRY LOGIC: If bank times out, retry safely without double-charging
  • MULTI-CURRENCY: Convert INR ↔ USD ↔ EUR with live exchange rates`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Stripe vs Razorpay Comparison</h3>
      <Table
        headers={["Aspect", "Stripe", "Razorpay"]}
        rows={[
          ["Founded", "2010 (San Francisco)", "2014 (Mumbai)"],
          ["Processing", "$1T+ annually", "~$180B annually"],
          ["Primary market", "Global (46 countries)", "India-first"],
          ["Tech stack", "Ruby, Go, Scala", "Java, Go, Python"],
          ["Database", "Custom (DocDB)", "MySQL, PostgreSQL"],
          ["UPI support", "Limited", "Native, excellent"],
          ["Pricing (India)", "2% + foreign exchange", "2% per transaction"],
          ["Developer experience", "Gold standard — best docs in fintech", "Very good, Stripe-inspired"],
          ["Settlement", "T+2 to T+7", "T+2 (India)"],
          ["Key innovation", "Stripe Elements (embeddable UI)", "Razorpay Checkout (one-line integration)"],
        ]}
      />

      <h3 className="mt-8 mb-2 text-lg font-bold">Fraud Detection Architecture</h3>
      <Diagram title="Real-time Fraud Detection Pipeline">{`
  Transaction
  Received
      │
      ▼
  ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
  │  Rule Engine │────▶│  ML Scoring   │────▶│  Decision    │
  │              │     │  Engine       │     │  Engine      │
  │ • Velocity   │     │              │     │              │
  │   (5 txns in │     │ • Neural net │     │ Score < 30:  │
  │   1 minute?) │     │   trained on │     │  → APPROVE   │
  │ • Amount     │     │   billions   │     │              │
  │   (unusual?) │     │   of txns    │     │ Score 30-70: │
  │ • Geo        │     │ • Features:  │     │  → 3D Secure │
  │   (Mumbai →  │     │   device,    │     │   (OTP)      │
  │   Nigeria?)  │     │   location,  │     │              │
  │ • Device     │     │   behavior,  │     │ Score > 70:  │
  │   (new?)     │     │   history    │     │  → DECLINE   │
  └──────────────┘     └───────────────┘     └──────────────┘

  ALL OF THIS HAPPENS IN < 100 MILLISECONDS
  Stripe's Radar blocks $35B+ in fraud annually`}</Diagram>
    </div>
  ),
};

// ═══════════════════════════════════════════════════════════════
// SECTION: REAL-TIME CHAT SYSTEMS
// ═══════════════════════════════════════════════════════════════
export const chatSystemSection: Section = {
  id: "chat-systems",
  title: "Real-Time Chat — WhatsApp, Slack Architecture",
  icon: "💬",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="WhatsApp Users" value="2B+" sub="Monthly active" />
        <Stat label="Messages/Day" value="100B+" sub="Sent daily" />
        <Stat label="Conn/Server" value="2M+" sub="WhatsApp's Erlang magic" />
        <Stat label="Slack Orgs" value="750K+" sub="Paid organizations" />
      </div>

      <h3 className="mb-2 text-lg font-bold">How WhatsApp Handles 2 Billion Users</h3>

      <Diagram title="WhatsApp Architecture">{`
  ┌────────────┐                              ┌────────────┐
  │  Sender    │                              │  Receiver  │
  │  Phone     │                              │  Phone     │
  └─────┬──────┘                              └──────▲─────┘
        │ (Noise Protocol                            │
        │  E2E Encrypted)                            │
        ▼                                            │
  ┌──────────────────────────────────────────────────────────┐
  │                   WhatsApp Backend                       │
  │                                                          │
  │  ┌──────────────┐    ┌──────────────┐    ┌───────────┐  │
  │  │  Connection  │    │   Message    │    │  Offline  │  │
  │  │  Server      │    │   Routing    │    │  Storage  │  │
  │  │  (Erlang)    │    │   Service    │    │  Queue    │  │
  │  │              │    │              │    │           │  │
  │  │  2M+ conns   │    │  Route msg   │    │  If user  │  │
  │  │  per server  │    │  to correct  │    │  offline, │  │
  │  │              │    │  connection  │    │  store    │  │
  │  │  ~550 servers│    │  server      │    │  until    │  │
  │  │  for 2B users│    │              │    │  online   │  │
  │  └──────────────┘    └──────────────┘    └───────────┘  │
  │                                                          │
  │  ┌──────────────┐    ┌──────────────┐                   │
  │  │  Mnesia DB   │    │  Media       │                   │
  │  │  (Erlang     │    │  Storage     │                   │
  │  │   built-in)  │    │  (Photos,    │                   │
  │  │              │    │   Videos)    │                   │
  │  │  User state, │    │              │                   │
  │  │  presence,   │    │  Stored      │                   │
  │  │  contacts    │    │  temporarily │                   │
  │  └──────────────┘    │  then deleted│                   │
  │                      └──────────────┘                   │
  └──────────────────────────────────────────────────────────┘

  WHY ERLANG?
  ════════════
  • Built for telecom (Ericsson created it for phone switches)
  • Each connection = lightweight Erlang process (2KB RAM)
  • 2M connections × 2KB = 4GB RAM per server
  • Hot code swapping: update code WITHOUT dropping connections
  • Pattern matching makes message routing trivially fast
  • "Let it crash" philosophy: processes crash independently

  WHY ~550 SERVERS FOR 2 BILLION USERS?
  ══════════════════════════════════════
  • 2B users ÷ 2M connections/server ≈ 1,000 connection servers
  • But only ~30% are online at any time = ~550 servers needed
  • Compare: a typical Java server handles ~50K connections
  • WhatsApp would need 40x more Java servers`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Slack Architecture</h3>

      <Diagram title="Slack Real-Time Messaging">{`
  ┌────────────────────────────────────────────────────────────┐
  │                    SLACK ARCHITECTURE                      │
  │                                                            │
  │  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐ │
  │  │  Web     │    │   API        │    │   Real-Time      │ │
  │  │  Client  │───▶│   Gateway    │───▶│   Messaging      │ │
  │  │  (React) │    │   (PHP/Hack) │    │   Service (RTM)  │ │
  │  └──────────┘    └──────┬───────┘    │                  │ │
  │                         │            │  WebSocket conn  │ │
  │                         ▼            │  per user per    │ │
  │                  ┌──────────────┐    │  workspace       │ │
  │                  │   Channel    │    └──────────────────┘ │
  │                  │   Service    │                          │
  │                  │              │    ┌──────────────────┐ │
  │                  │  Permissions │    │  Search Service  │ │
  │                  │  Membership  │    │  (Elasticsearch) │ │
  │                  └──────┬───────┘    │                  │ │
  │                         │            │  Indexes every   │ │
  │                         ▼            │  message for     │ │
  │                  ┌──────────────┐    │  instant search  │ │
  │                  │  Message     │    └──────────────────┘ │
  │                  │  Store       │                          │
  │                  │  (MySQL +    │    ┌──────────────────┐ │
  │                  │   Vitess)    │    │  File Storage    │ │
  │                  └──────────────┘    │  (S3)            │ │
  │                                      └──────────────────┘ │
  └────────────────────────────────────────────────────────────┘

  SLACK'S KEY DECISIONS:
  ══════════════════════
  • MySQL + Vitess for sharding (not NoSQL — they wanted ACID)
  • One WebSocket per user per workspace (not per channel)
  • Fan-out on delivery: when you post in #general with 5000 members,
    the message is written ONCE but delivered to 5000 WebSockets
  • Elasticsearch indexes every message — search across years instantly
  • Moved from PHP to Hack (Facebook's typed PHP) for performance`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Building a Chat System — Key Decisions</h3>
      <Table
        headers={["Decision", "Option A", "Option B", "Recommendation"]}
        rows={[
          ["Protocol", "WebSocket (persistent connection)", "Server-Sent Events (one-way)", "WebSocket for chat (bidirectional needed)"],
          ["Message storage", "Store on server (Slack model)", "E2E encrypted, minimal storage (WhatsApp)", "Server storage for business apps, E2E for privacy apps"],
          ["Delivery", "Fan-out on write (pre-compute)", "Fan-out on read (compute at read time)", "Fan-out on write for small groups, on read for large channels"],
          ["Presence", "Heartbeat every 30 seconds", "Connection-based (online = connected)", "Heartbeat is more reliable but costs more"],
          ["Offline messages", "Store and forward (queue)", "Push notification only", "Store and forward — never lose messages"],
          ["Read receipts", "Per-message tracking", "Last-read pointer per user", "Last-read pointer (less storage, good enough)"],
          ["Search", "Elasticsearch", "PostgreSQL full-text", "Elasticsearch for scale, PG for small apps"],
          ["Scaling", "Shard by workspace/room", "Shard by user", "By workspace for isolation, by user for 1:1"],
        ]}
      />

      <Diagram title="End-to-End Encryption (Signal Protocol — used by WhatsApp)">{`
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │  SENDER (Alice)              RECEIVER (Bob)         │
  │                                                     │
  │  1. Alice has Bob's          1. Bob has Alice's     │
  │     PUBLIC key                  PUBLIC key          │
  │                                                     │
  │  2. Alice encrypts           4. Bob decrypts       │
  │     message with               message with        │
  │     Bob's PUBLIC key           his PRIVATE key     │
  │                                                     │
  │  3. Encrypted message                              │
  │     travels through ──────▶                        │
  │     WhatsApp servers                               │
  │     (they CAN'T read it)                           │
  │                                                     │
  │  KEY INSIGHT: WhatsApp servers are just             │
  │  mailboxes — they deliver sealed envelopes          │
  │  they cannot open.                                  │
  └─────────────────────────────────────────────────────┘

  Signal Protocol additionally uses:
  • Double Ratchet: new encryption key for EVERY message
  • Perfect Forward Secrecy: old messages can't be decrypted
    even if current key is compromised`}</Diagram>
    </div>
  ),
};

// ═══════════════════════════════════════════════════════════════
// SECTION: SEARCH ENGINE DESIGN
// ═══════════════════════════════════════════════════════════════
export const searchEngineSection: Section = {
  id: "search-engines",
  title: "Search Engine Design — Google, Elasticsearch",
  icon: "🔍",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Google Queries" value="100K/sec" sub="8.5 billion/day" />
        <Stat label="Index Size" value="100PB+" sub="Petabytes indexed" />
        <Stat label="Response Time" value="<200ms" sub="Average query" />
        <Stat label="Web Pages" value="130T+" sub="Trillion pages indexed" />
      </div>

      <h3 className="mb-2 text-lg font-bold">How Google Search Works in 200 Milliseconds</h3>

      <Diagram title="Google Search Architecture (Simplified)">{`
  User types "best restaurant Mumbai"
       │
       ▼
  ┌──────────────────────────────────────────────────────────┐
  │  STEP 1: QUERY PROCESSING                               │
  │                                                          │
  │  "best restaurant Mumbai"                                │
  │       ↓                                                  │
  │  Spell check → Tokenize → Understand intent              │
  │  "best" → ranking signal                                 │
  │  "restaurant" → entity type                              │
  │  "Mumbai" → location filter                              │
  │       ↓                                                  │
  │  Query rewriting: also search for                        │
  │  "top restaurants mumbai" "good food mumbai"             │
  └──────────────────────┬───────────────────────────────────┘
                         │
  ┌──────────────────────▼───────────────────────────────────┐
  │  STEP 2: INDEX LOOKUP (THE MAGIC)                       │
  │                                                          │
  │  ┌─────────────── Inverted Index ──────────────────┐    │
  │  │                                                  │    │
  │  │  "restaurant" → [doc_45, doc_892, doc_1203, ...] │    │
  │  │  "mumbai"     → [doc_12, doc_45, doc_67, ...]    │    │
  │  │  "best"       → [doc_45, doc_1500, doc_892, ...] │    │
  │  │                                                  │    │
  │  │  INTERSECTION: doc_45 appears in ALL three        │    │
  │  │  → This document is a strong match               │    │
  │  └──────────────────────────────────────────────────┘    │
  │                                                          │
  │  This runs across THOUSANDS of machines in parallel      │
  │  Each machine holds a shard of the index                 │
  └──────────────────────┬───────────────────────────────────┘
                         │
  ┌──────────────────────▼───────────────────────────────────┐
  │  STEP 3: RANKING (200+ signals)                         │
  │                                                          │
  │  PageRank (link authority) ────────── 15%                │
  │  Content relevance (TF-IDF) ───────── 25%                │
  │  User signals (CTR, dwell time) ───── 20%                │
  │  Freshness (how recent) ───────────── 10%                │
  │  Mobile-friendliness ─────────────── 5%                  │
  │  Page speed ───────────────────────── 5%                  │
  │  BERT/AI understanding ────────────── 15%                │
  │  200+ other signals ───────────────── 5%                  │
  │                                                          │
  │  Final score → Sort → Return top 10 results             │
  └──────────────────────────────────────────────────────────┘`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Elasticsearch — The Search Engine You Can Use</h3>

      <Diagram title="Elasticsearch Architecture">{`
  ┌────────────────── Elasticsearch Cluster ──────────────────┐
  │                                                           │
  │  ┌───────────────┐  ┌───────────────┐  ┌──────────────┐ │
  │  │   Node 1      │  │   Node 2      │  │   Node 3     │ │
  │  │   (Master)    │  │   (Data)      │  │   (Data)     │ │
  │  │               │  │               │  │              │ │
  │  │ Shard 0 (P)   │  │ Shard 0 (R)   │  │ Shard 1 (R) │ │
  │  │ Shard 1 (P)   │  │ Shard 2 (P)   │  │ Shard 2 (R) │ │
  │  └───────────────┘  └───────────────┘  └──────────────┘ │
  │                                                           │
  │  P = Primary shard (writes)                               │
  │  R = Replica shard (reads + backup)                       │
  │                                                           │
  │  HOW IT WORKS:                                            │
  │  ═══════════════                                          │
  │  1. INDEX: Document → Analyze → Tokenize → Inverted Index│
  │     "The quick brown fox" → [the, quick, brown, fox]     │
  │                                                           │
  │  2. SEARCH: Query → Match against inverted index          │
  │     "brown fox" → find docs containing both tokens        │
  │     → Score by relevance (BM25 algorithm)                 │
  │                                                           │
  │  3. AGGREGATE: Count, sum, average across millions        │
  │     "Average price by category" → real-time analytics     │
  └───────────────────────────────────────────────────────────┘

  ELASTICSEARCH USE CASES:
  ════════════════════════
  • Full-text search (like Swiggy searching restaurants)
  • Log analysis (ELK Stack: Elasticsearch + Logstash + Kibana)
  • Real-time analytics (dashboards, monitoring)
  • Autocomplete and suggestions
  • Geospatial search (find nearby restaurants)`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Key Concepts in Search</h3>
      <Table
        headers={["Concept", "What It Means", "Example"]}
        rows={[
          ["Inverted Index", "Map from words → documents (opposite of normal)", "'restaurant' → [doc_1, doc_5, doc_99]"],
          ["TF-IDF", "Term Frequency × Inverse Document Frequency — measures relevance", "Word appears 5x in doc but rare overall = high score"],
          ["BM25", "Modern ranking algorithm (used by Elasticsearch)", "Improved TF-IDF with document length normalization"],
          ["Tokenization", "Breaking text into searchable tokens", "'running quickly' → ['run', 'quick'] (stemmed)"],
          ["Stemming", "Reducing words to root form", "'running', 'runs', 'ran' → all match 'run'"],
          ["Fuzzy Search", "Match despite typos", "'restraunt' matches 'restaurant' (edit distance 2)"],
          ["PageRank", "Google's link authority algorithm", "A page linked by NYT.com has more authority than random blog"],
          ["Sharding", "Split index across multiple servers for parallelism", "Index of 1B docs split into 10 shards of 100M each"],
          ["Relevance Tuning", "Boosting certain fields or signals", "Title match worth 3x more than body match"],
        ]}
      />
    </div>
  ),
};

// ═══════════════════════════════════════════════════════════════
// SECTION: AUTHENTICATION SYSTEMS
// ═══════════════════════════════════════════════════════════════
export const authSection: Section = {
  id: "authentication",
  title: "Authentication — OAuth, SSO, JWT Deep-Dive",
  icon: "🔐",
  content: (
    <div>
      <h3 className="mb-2 text-lg font-bold">Authentication vs Authorization</h3>
      <p className="mb-4 text-sm text-muted">Authentication = &quot;Who are you?&quot; (login). Authorization = &quot;What can you do?&quot; (permissions). Different things.</p>

      <Diagram title="How OAuth 2.0 Works (Sign in with Google)">{`
  ┌──────────┐                                    ┌──────────┐
  │   User   │                                    │  Google  │
  │ (Browser)│                                    │  (Auth   │
  └────┬─────┘                                    │  Server) │
       │                                          └────┬─────┘
       │  1. Click "Sign in with Google"               │
       │  on your app (mmam.areakpi.in)                │
       │                                               │
       ▼                                               │
  ┌──────────┐                                         │
  │ Your App │                                         │
  │ Backend  │  2. Redirect user to Google ───────────▶│
  └──────────┘     with client_id + scopes             │
                                                       │
       ┌───────────────────────────────────────────────┘
       │  3. User logs in to Google
       │     sees "Allow mmam to access your name/email?"
       │     clicks "Allow"
       │
       │  4. Google redirects back to your app
       │     with an AUTHORIZATION CODE
       ▼
  ┌──────────┐                                    ┌──────────┐
  │ Your App │  5. Exchange code for tokens ─────▶│  Google  │
  │ Backend  │◀─── Access Token + ID Token ───────│  Token   │
  └──────────┘                                    │  Endpoint│
       │                                          └──────────┘
       │  6. Use Access Token to get user info
       │     from Google's API
       │
       │  7. Create session for user in YOUR app
       │     (JWT token or server session)
       ▼
  ┌──────────┐
  │   User   │  Now logged in to your app!
  │  Session │  Without ever sharing their
  └──────────┘  Google password with you.

  KEY INSIGHT: Your app NEVER sees the user's Google password.
  You only get a token that lets you read their name/email.`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">JWT (JSON Web Token) Deep-Dive</h3>

      <Diagram title="JWT Structure">{`
  A JWT looks like this:
  eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjM0fQ.HMAC_signature

  It has THREE parts separated by dots:

  ┌──────────────────────────────────────────────────────┐
  │  HEADER (Algorithm + Type)                           │
  │  {"alg": "HS256", "typ": "JWT"}                     │
  │  → Base64 encoded                                    │
  └──────────────────────────────────────────────────────┘
                         .
  ┌──────────────────────────────────────────────────────┐
  │  PAYLOAD (Claims — the actual data)                  │
  │  {                                                   │
  │    "user_id": 1234,                                  │
  │    "name": "Ashish Kamdar",                          │
  │    "role": "admin",                                  │
  │    "exp": 1735689600    ← expires at this timestamp  │
  │  }                                                   │
  │  → Base64 encoded (NOT encrypted — anyone can read!) │
  └──────────────────────────────────────────────────────┘
                         .
  ┌──────────────────────────────────────────────────────┐
  │  SIGNATURE (Proof it wasn't tampered with)           │
  │  HMAC-SHA256(                                        │
  │    base64(header) + "." + base64(payload),           │
  │    SECRET_KEY    ← only YOUR server knows this       │
  │  )                                                   │
  └──────────────────────────────────────────────────────┘

  WHY JWT IS POWERFUL:
  ════════════════════
  • STATELESS: Server doesn't need to store sessions
  • SELF-CONTAINED: Token carries all user info
  • VERIFIABLE: Signature proves it wasn't modified
  • SCALABLE: Any server can verify (no shared session store)

  JWT GOTCHAS:
  ═══════════
  • Payload is NOT encrypted — don't put passwords in it
  • Can't revoke a JWT before expiry (use short-lived + refresh)
  • Token theft = account access (store securely, use HTTPS)`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">SSO (Single Sign-On) Architecture</h3>

      <Diagram title="SSO Flow — One Login for Multiple Apps">{`
  ┌───────────┐  ┌───────────┐  ┌───────────┐
  │  Gmail    │  │  YouTube  │  │  Google   │
  │           │  │           │  │  Drive    │
  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │   Identity       │
              │   Provider (IdP) │
              │                  │
              │   Google         │
              │   Accounts       │
              │                  │
              │   ONE login      │
              │   = access to    │
              │   ALL apps       │
              └──────────────────┘

  SSO PROTOCOLS:
  ═══════════════
  • SAML 2.0 — Enterprise standard (XML-based, older)
    Used by: Salesforce, Workday, corporate apps
    Best for: B2B enterprise apps

  • OAuth 2.0 + OIDC — Modern standard (JSON-based)
    Used by: Google, Facebook, GitHub login
    Best for: Consumer and modern B2B apps

  • LDAP/Active Directory — On-premise corporate
    Used by: Windows networks, internal tools
    Best for: Legacy corporate environments`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Authentication Methods Compared</h3>
      <Table
        headers={["Method", "Security", "UX", "Best For"]}
        rows={[
          ["Password + Email", "Low (reuse, phishing)", "Familiar", "Simple apps, legacy"],
          ["Password + 2FA (OTP)", "Medium-High", "Slight friction", "Banking, finance apps"],
          ["OAuth (Sign in with Google)", "High", "Excellent (one tap)", "Consumer apps, SaaS"],
          ["Passkeys (FIDO2)", "Very High", "Excellent (biometric)", "Modern apps (Apple, Google pushing)"],
          ["Magic Link (email)", "Medium", "Good (no password)", "Slack, Notion use this"],
          ["PIN + Device", "Medium", "Good for mobile", "MMAM uses this! 4-digit PIN + cookie"],
          ["SSO (SAML/OIDC)", "High", "Seamless after setup", "Enterprise, B2B SaaS"],
          ["Biometric (Face/Fingerprint)", "Very High", "Excellent", "Mobile banking, UPI"],
          ["Certificate-based", "Very High", "Complex setup", "Government, military, SEBI"],
        ]}
      />
    </div>
  ),
};

// ═══════════════════════════════════════════════════════════════
// SECTION: MOBILE APP ARCHITECTURE
// ═══════════════════════════════════════════════════════════════
export const mobileArchSection: Section = {
  id: "mobile-architecture",
  title: "Mobile App Architecture — Native vs Cross-Platform",
  icon: "📱",
  content: (
    <div>
      <h3 className="mb-4 text-lg font-bold">The Big Decision: How to Build Your Mobile App</h3>

      <Diagram title="Mobile Architecture Decision Tree">{`
                    ┌───────────────────────────┐
                    │  What are you building?    │
                    └─────────────┬─────────────┘
                                  │
               ┌──────────────────┼──────────────────┐
               │                  │                  │
         Content/CRUD        Interactive         Heavy Graphics
         (List, Forms,       (Chat, Maps,        (Games, Camera,
          Dashboard)          Real-time)          AR/VR, Video)
               │                  │                  │
               ▼                  ▼                  ▼
        ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
        │     PWA      │  │ React Native │  │    Native    │
        │   (Web App)  │  │  or Flutter  │  │  (Swift /    │
        │              │  │              │  │   Kotlin)    │
        └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
               │                 │                  │
               ▼                 ▼                  ▼
          Rs 50K-2L         Rs 2L-8L           Rs 5L-20L+
          1-4 weeks         2-4 months         4-8 months
          1 developer       1-2 developers     2-4 developers
          ×1 codebase       ×1 codebase        ×2 codebases`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">Complete Comparison</h3>
      <Table
        headers={["Aspect", "PWA", "React Native", "Flutter", "Native (Swift/Kotlin)"]}
        rows={[
          ["Language", "JavaScript/TypeScript", "JavaScript/TypeScript", "Dart", "Swift (iOS) + Kotlin (Android)"],
          ["Performance", "Good (80%)", "Very Good (90%)", "Excellent (95%)", "Best (100%)"],
          ["UI fidelity", "Web-like", "Near-native", "Custom (pixel-perfect)", "True native"],
          ["Code sharing", "100% (one codebase)", "85-90% shared", "95-98% shared", "0% (separate codebases)"],
          ["App Store", "No (install from browser)", "Yes", "Yes", "Yes"],
          ["Offline", "Service Worker", "AsyncStorage + SQLite", "Hive/SQLite", "Core Data / Room"],
          ["Push notifications", "Limited on iOS", "Full support", "Full support", "Full support"],
          ["Camera/GPS/Sensors", "Basic", "Good (via bridges)", "Good (via plugins)", "Full native access"],
          ["Hot reload", "Yes (HMR)", "Yes", "Yes (best in class)", "Xcode Previews / Limited"],
          ["Cost (typical)", "Rs 50K-2L", "Rs 3L-8L", "Rs 3L-8L", "Rs 10L-20L (×2 platforms)"],
          ["Time to market", "1-4 weeks", "2-4 months", "2-4 months", "4-8 months"],
          ["When to choose", "Content apps, MVP", "Apps needing native feel + web skills", "Beautiful custom UI apps", "Performance-critical, hardware-heavy"],
          ["Famous apps", "Twitter Lite, Starbucks", "Facebook, Instagram, Shopify", "Google Pay, BMW, eBay", "All top-tier apps"],
        ]}
      />

      <h3 className="mt-8 mb-2 text-lg font-bold">React Native Architecture</h3>

      <Diagram title="React Native — How It Works">{`
  ┌───────────────────────────────────────────────────────┐
  │                   YOUR CODE (JavaScript)              │
  │                                                       │
  │  const App = () => (                                  │
  │    <View>                                             │
  │      <Text>Hello Mumbai</Text>                        │
  │      <Button onPress={handlePay} />                   │
  │    </View>                                            │
  │  );                                                   │
  └──────────────────────┬────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │  Bridge │  ← The key innovation
                    │  (JSON  │     JS ↔ Native communication
                    │  async) │     (New Architecture: JSI — no bridge!)
                    └────┬────┘
                         │
  ┌──────────────────────▼────────────────────────────────┐
  │               NATIVE MODULES                          │
  │                                                       │
  │  iOS (Objective-C/Swift)  │  Android (Java/Kotlin)    │
  │                           │                           │
  │  <View> → UIView          │  <View> → android.view    │
  │  <Text> → UILabel         │  <Text> → TextView        │
  │  <Image> → UIImageView    │  <Image> → ImageView      │
  │                           │                           │
  │  THESE ARE REAL NATIVE COMPONENTS                     │
  │  Not a WebView! Not HTML! Actual platform widgets.    │
  └───────────────────────────────────────────────────────┘

  NEW ARCHITECTURE (2024+):
  ═════════════════════════
  • JSI (JavaScript Interface): Direct C++ bindings, no JSON bridge
  • Fabric: New rendering system, synchronous layout
  • TurboModules: Lazy-loaded native modules
  • Result: 2-3x performance improvement over old bridge`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">Flutter Architecture</h3>

      <Diagram title="Flutter — How It Works (Completely Different Approach)">{`
  ┌───────────────────────────────────────────────────────┐
  │                   YOUR CODE (Dart)                    │
  │                                                       │
  │  Widget build(context) {                              │
  │    return Scaffold(                                   │
  │      body: Column(                                    │
  │        children: [                                    │
  │          Text('Hello Mumbai'),                        │
  │          ElevatedButton(onPressed: handlePay),        │
  │        ],                                             │
  │      ),                                               │
  │    );                                                 │
  │  }                                                    │
  └──────────────────────┬────────────────────────────────┘
                         │
                    ┌────▼──────────────┐
                    │   Skia Engine     │  ← Flutter DRAWS everything itself
                    │   (2D Graphics)   │     using its own rendering engine
                    │                   │     (now Impeller on iOS)
                    │   Renders at      │
                    │   60/120 fps      │
                    └────┬──────────────┘
                         │
  ┌──────────────────────▼────────────────────────────────┐
  │               PLATFORM LAYER                          │
  │                                                       │
  │  iOS: Metal (GPU)          │  Android: OpenGL/Vulkan  │
  │                            │                          │
  │  Flutter doesn't use       │  Every pixel is drawn    │
  │  native UI components!     │  by Flutter's engine     │
  │  It paints directly on     │                          │
  │  a canvas — like a game.   │  This is why Flutter     │
  │                            │  looks IDENTICAL on       │
  │  Platform channels for     │  both platforms.          │
  │  camera, GPS, etc.         │                          │
  └───────────────────────────────────────────────────────┘

  KEY DIFFERENCE FROM REACT NATIVE:
  ═════════════════════════════════
  React Native: Uses NATIVE widgets (UIButton, TextView)
  Flutter: DRAWS its own widgets (like a game engine)

  React Native: Platform differences possible
  Flutter: Pixel-perfect same on both platforms`}</Diagram>

      <h3 className="mt-8 mb-2 text-lg font-bold">For MMAM and Your Clients</h3>
      <Table
        headers={["Scenario", "Best Choice", "Why"]}
        rows={[
          ["MMAM app", "PWA (current)", "Content-first, offline needed, no app store friction, fast iteration"],
          ["Samaj member management", "PWA or React Native", "CRUD + notifications. PWA if web-first, RN if app store presence needed"],
          ["Gymkhana event ticketing", "PWA", "QR scanning works in browser, no install needed for one-time use"],
          ["Fitness studio app (Olistic)", "React Native or Flutter", "Needs push notifications, timer UI, possibly video. Cross-platform saves cost"],
          ["Gold/crypto tracking", "React Native", "Real-time data, charts, push alerts. JS ecosystem has excellent charting libs"],
          ["SEBI surveillance", "Native or PWA", "Depends: if camera/hardware heavy = Native. If dashboard = PWA"],
        ]}
      />
    </div>
  ),
};

// Export all extended sections
export const extendedSections: Section[] = [
  paymentGatewaySection,
  chatSystemSection,
  searchEngineSection,
  authSection,
  mobileArchSection,
];
