"use client";

import { useState } from "react";
import Link from "next/link";
import { extendedSections } from "./sections-extended";
import { microservicesSection } from "./sections-microservices";

type Section = {
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

// ─── SECTION: VISA ─────────────────────────────────────────
const visaSection: Section = {
  id: "visa",
  title: "VISA — 65,000 TPS Architecture",
  icon: "💳",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Peak TPS" value="65,000" sub="Transactions per second" />
        <Stat label="Uptime" value="99.999%" sub="~5 min downtime/year" />
        <Stat label="Auth Time" value="<1 sec" sub="End-to-end" />
        <Stat label="Data Centers" value="4" sub="Global mesh" />
      </div>

      <h3 className="mb-2 text-lg font-bold">How a VISA Transaction Works</h3>
      <p className="mb-4 text-sm text-muted">When you swipe your card at a shop in Mumbai, here&apos;s what happens in under 1 second:</p>

      <Diagram title="VISA Transaction Flow">{`
  ┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────┐    ┌──────────┐
  │  POS/ATM │───▶│ Acquirer │───▶│   VisaNet    │───▶│  Issuer  │───▶│ Customer │
  │ Terminal │    │   Bank   │    │  (Switch)    │    │   Bank   │    │ Account  │
  └──────────┘    └──────────┘    └──────────────┘    └──────────┘    └──────────┘
       │                │                │                  │               │
       │   1. Card      │  2. ISO 8583   │  3. Route to     │  4. Check     │
       │   Data Sent    │  Message       │  Issuer Bank     │  Balance &    │
       │                │  Formatted     │  via VisaNet     │  Approve/     │
       │                │                │                  │  Decline      │
       │                │                │                  │               │
       │◀───────────────│◀───────────────│◀─────────────────│◀──────────────│
       │   6. Display   │  5. Response   │  4. Response     │  Auth Code    │
       │   Approved/    │  Forwarded     │  Routed Back     │  Generated    │
       │   Declined     │                │                  │               │
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        ALL OF THIS HAPPENS IN < 1 SECOND`}</Diagram>

      <h3 className="mb-2 text-lg font-bold">VisaNet Infrastructure</h3>

      <Diagram title="VisaNet Global Architecture">{`
                          ┌─────────────────────┐
                          │   GLOBAL NETWORK     │
                          │  (Private Fiber)     │
                          └──────────┬──────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
     ┌────────▼────────┐   ┌────────▼────────┐   ┌────────▼────────┐
     │   US East DC    │   │   US West DC    │   │  Singapore DC   │
     │  (Primary)      │   │  (Primary)      │   │  (Asia-Pacific) │
     │                 │   │                 │   │                 │
     │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌─────────────┐ │
     │ │ Transaction │ │   │ │ Transaction │ │   │ │ Transaction │ │
     │ │ Processing  │ │   │ │ Processing  │ │   │ │ Processing  │ │
     │ │ Engine      │ │   │ │ Engine      │ │   │ │ Engine      │ │
     │ └─────────────┘ │   │ └─────────────┘ │   │ └─────────────┘ │
     │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌─────────────┐ │
     │ │ Fraud       │ │   │ │ Fraud       │ │   │ │ Fraud       │ │
     │ │ Detection   │ │   │ │ Detection   │ │   │ │ Detection   │ │
     │ │ (Real-time) │ │   │ │ (Real-time) │ │   │ │ (Real-time) │ │
     │ └─────────────┘ │   │ └─────────────┘ │   │ └─────────────┘ │
     │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌─────────────┐ │
     │ │ In-Memory   │ │   │ │ In-Memory   │ │   │ │ In-Memory   │ │
     │ │ Data Grid   │ │   │ │ Data Grid   │ │   │ │ Data Grid   │ │
     │ └─────────────┘ │   │ └─────────────┘ │   │ └─────────────┘ │
     └─────────────────┘   └─────────────────┘   └─────────────────┘

  KEY DESIGN PRINCIPLES:
  ═══════════════════════
  1. Triple Redundancy — every component has 3 backups
  2. In-Memory Processing — no disk I/O for authorization
  3. Private Network — dedicated fiber, not public internet
  4. ISO 8583 — standard message format for all banks
  5. Geo-routing — transactions processed at nearest DC`}</Diagram>

      <h3 className="mb-2 text-lg font-bold">Why VISA Can Do 65,000 TPS</h3>
      <Table
        headers={["Technique", "How It Works", "Impact"]}
        rows={[
          ["In-memory processing", "Transaction data lives in RAM, not disk. No I/O wait.", "Auth in <100ms"],
          ["Custom hardware", "Purpose-built transaction processing units, not generic servers", "10x throughput vs. commodity"],
          ["Private network", "Dedicated fiber optic lines between DCs, not shared internet", "Predictable 5ms latency"],
          ["Batch settlement", "Authorization is real-time, but money moves in nightly batches", "Decouples speed from settlement"],
          ["Geo-routing", "Mumbai transaction → Singapore DC (nearest), not US", "50ms vs 200ms round trip"],
          ["Triple redundancy", "Every component has 3 copies. Any 2 can fail.", "99.999% uptime"],
          ["ISO 8583 protocol", "Fixed-length binary messages. Tiny payload, fast parsing.", "Minimal network overhead"],
        ]}
      />
    </div>
  ),
};

// ─── SECTION: NETFLIX ─────────────────────────────────────────
const netflixSection: Section = {
  id: "netflix",
  title: "Netflix — Streaming at Planet Scale",
  icon: "🎬",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Monthly Hours" value="400M+" sub="Hours of video streamed" />
        <Stat label="Countries" value="190+" sub="Global availability" />
        <Stat label="Microservices" value="1,000+" sub="Independent services" />
        <Stat label="Engineers" value="~2,000" sub="For 250M subscribers" />
      </div>

      <Diagram title="Netflix Architecture Overview">{`
  USER (Mumbai)
       │
       ▼
  ┌──────────────────┐     ┌──────────────────────────────────────────┐
  │   Open Connect   │     │              AWS Cloud                   │
  │   CDN Server     │     │                                          │
  │   (ISP Mumbai)   │     │  ┌────────┐  ┌────────┐  ┌────────┐    │
  │                  │     │  │ Zuul   │  │Eureka  │  │Hystrix │    │
  │  Serves VIDEO    │     │  │API GW  │──│Service │──│Circuit │    │
  │  (95% traffic)   │     │  │        │  │Discvry │  │Breaker │    │
  └──────────────────┘     │  └───┬────┘  └────────┘  └────────┘    │
                           │      │                                  │
  The CONTROL PLANE        │  ┌───▼────────────────────────────┐     │
  runs on AWS ────────────▶│  │     1,000+ Microservices       │     │
                           │  │                                │     │
  The DATA PLANE           │  │  User   │ Content │ Recommend  │     │
  (video) runs on ────────▶│  │  Svc    │ Svc     │ Engine     │     │
  Open Connect CDN         │  │         │         │            │     │
                           │  │  Billing│ A/B Test│ Analytics  │     │
                           │  │  Svc    │ Svc     │ Pipeline   │     │
                           │  └────────────────────────────────┘     │
                           │                                          │
                           │  ┌────────────────────────────────┐     │
                           │  │    Data Layer                  │     │
                           │  │  Cassandra │ EVCache │ Kafka   │     │
                           │  │  (NoSQL)   │(Cache)  │(Stream) │     │
                           │  └────────────────────────────────┘     │
                           └──────────────────────────────────────────┘

  WHAT MAKES IT WORK:
  ════════════════════
  • Open Connect boxes sit INSIDE ISPs — video never crosses the internet
  • Each microservice is independently deployable (separate team owns it)
  • Chaos Monkey randomly kills servers to test resilience
  • Zuul API Gateway handles 50B+ API requests/day
  • EVCache (modified memcached) caches billions of items`}</Diagram>

      <h3 className="mb-2 text-lg font-bold">Netflix&apos;s Key Innovations</h3>
      <Table
        headers={["Innovation", "What It Does", "Why It Matters"]}
        rows={[
          ["Open Connect CDN", "Netflix hardware inside ISPs. Video is pre-cached locally.", "95% of traffic never leaves the ISP network"],
          ["Chaos Monkey", "Randomly kills production servers to test resilience", "Ensures system survives any single failure"],
          ["Zuul Gateway", "API gateway handling routing, auth, load shedding", "Single entry point for 50B+ daily requests"],
          ["Adaptive Streaming", "Adjusts video quality based on bandwidth in real-time", "No buffering even on slow connections"],
          ["A/B Testing", "Every UI change tested on millions of users before rollout", "Data-driven decisions, not opinions"],
          ["Microservice ownership", "Each team owns their service end-to-end (build, deploy, operate)", "1000+ services, each independently scalable"],
        ]}
      />
    </div>
  ),
};

// ─── SECTION: UPI ─────────────────────────────────────────
const upiSection: Section = {
  id: "upi",
  title: "UPI — India's 10 Billion TXN/Month System",
  icon: "🇮🇳",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Monthly TXN" value="10B+" sub="Transactions" />
        <Stat label="Peak TPS" value="~10,000" sub="Transactions/second" />
        <Stat label="Settlement" value="Real-time" sub="Instant money transfer" />
        <Stat label="Participants" value="350+" sub="Banks connected" />
      </div>

      <Diagram title="UPI Transaction Architecture">{`
  ┌────────────┐                                          ┌────────────┐
  │  Sender    │                                          │  Receiver  │
  │  (PhonePe) │                                          │  (GPay)    │
  └─────┬──────┘                                          └─────▲──────┘
        │                                                       │
        ▼                                                       │
  ┌────────────┐     ┌──────────────┐     ┌────────────┐       │
  │  Sender's  │────▶│    NPCI      │────▶│ Receiver's │───────┘
  │  PSP App   │     │  (Switch)    │     │  PSP App   │
  └─────┬──────┘     │              │     └─────▲──────┘
        │            │  ┌────────┐  │           │
        ▼            │  │ UPI    │  │           │
  ┌────────────┐     │  │ Switch │  │     ┌────────────┐
  │  Sender's  │────▶│  │ Engine │  │────▶│ Receiver's │
  │  Bank      │     │  └────────┘  │     │  Bank      │
  │  (HDFC)    │     │              │     │  (SBI)     │
  └────────────┘     └──────────────┘     └────────────┘

  THE FLOW (< 2 seconds):
  ═══════════════════════
  1. Sender enters UPI PIN on PhonePe
  2. PhonePe → NPCI Switch (encrypted)
  3. NPCI routes to Sender's bank (HDFC)
  4. HDFC debits account, sends confirmation
  5. NPCI routes to Receiver's bank (SBI)
  6. SBI credits account
  7. Both parties notified instantly

  WHY UPI IS AN ENGINEERING MARVEL:
  ══════════════════════════════════
  • Interoperable: ANY app → ANY bank → ANY app
  • Real-time: actual money moves, not IOUs
  • 350+ banks connected through ONE switch
  • Handles Diwali/salary day spikes gracefully
  • VPA (UPI ID) abstracts bank account details`}</Diagram>
    </div>
  ),
};

// ─── SECTION: DOCKER vs K8s vs STANDARD ─────────────────────
const dockerK8sSection: Section = {
  id: "docker-k8s",
  title: "Docker vs Kubernetes vs Standard Deployment",
  icon: "🐳",
  content: (
    <div>
      <h3 className="mb-4 text-lg font-bold">When to Use What — Decision Tree</h3>

      <Diagram title="Deployment Decision Tree">{`
                        ┌─────────────────────┐
                        │  How many services?  │
                        └──────────┬──────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                  1-3            3-10           10+
                    │              │              │
                    ▼              ▼              ▼
            ┌──────────────┐ ┌──────────┐ ┌──────────────┐
            │   STANDARD   │ │  DOCKER  │ │  KUBERNETES  │
            │   PM2+nginx  │ │  COMPOSE │ │              │
            └──────┬───────┘ │  /SWARM  │ └──────┬───────┘
                   │         └────┬─────┘        │
                   ▼              ▼              ▼
            ┌──────────────┐ ┌──────────┐ ┌──────────────┐
            │ < 5K req/s   │ │ 5-50K    │ │ 50K+ req/s   │
            │ 1-5 devs     │ │ req/s    │ │ 10+ devs     │
            │ Rs 500-5K/mo │ │ 3-10 devs│ │ Rs 30K+/mo   │
            │              │ │ Rs 5-30K │ │              │
            │ EXAMPLES:    │ │ /mo      │ │ EXAMPLES:    │
            │ • MMAM app   │ │          │ │ • Flipkart   │
            │ • JSG ticket │ │ EXAMPLES:│ │ • Ola/Uber   │
            │ • Samaj apps │ │ • Medium │ │ • PayTM      │
            │ • Small SaaS │ │   startup│ │ • Enterprise │
            └──────────────┘ │ • Growing│ │   SaaS       │
                             │   SaaS   │ └──────────────┘
                             └──────────┘`}</Diagram>

      <h3 className="mb-4 text-lg font-bold">Side-by-Side Comparison</h3>
      <Table
        headers={["Aspect", "Standard (PM2+nginx)", "Docker Compose", "Docker Swarm", "Kubernetes"]}
        rows={[
          ["Setup time", "30 minutes", "1-2 hours", "2-4 hours", "1-2 days"],
          ["Learning curve", "Low", "Medium", "Medium", "High (months)"],
          ["Best for", "1-3 services", "Dev environments", "3-10 services", "10+ services"],
          ["Auto-scaling", "No (manual)", "No", "Basic", "Advanced (HPA)"],
          ["Self-healing", "PM2 restarts", "Manual", "Yes", "Yes (advanced)"],
          ["Rolling updates", "Manual", "Manual", "Yes", "Yes (zero-downtime)"],
          ["Load balancing", "nginx", "nginx/traefik", "Built-in", "Built-in + Ingress"],
          ["Service discovery", "Manual config", "Docker DNS", "Built-in", "Built-in (CoreDNS)"],
          ["Cost (monthly)", "Rs 500-5,000", "Rs 2,000-10,000", "Rs 5,000-30,000", "Rs 30,000+"],
          ["Ops team needed", "No", "No", "Maybe", "Yes (DevOps)"],
          ["MMAM recommendation", "✅ Perfect fit", "Good for local dev", "Overkill", "Way overkill"],
        ]}
      />

      <h3 className="mt-8 mb-4 text-lg font-bold">Standard Deployment (What We Use)</h3>
      <Diagram title="MMAM Production Architecture">{`
  User (Mobile Browser)
       │
       │ HTTPS (TLS 1.3)
       ▼
  ┌──────────────────────┐
  │   Cloudflare CDN     │  ← DDoS protection, SSL, caching
  │   (Free tier works)  │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │   nginx              │  ← Reverse proxy, gzip, static files
  │   (Port 80/443)      │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │   PM2 Cluster Mode   │  ← 4 workers on 4 CPU cores
  │   (Next.js on 3200)  │
  │                      │
  │   Worker 1 ─┐        │
  │   Worker 2 ─┤        │
  │   Worker 3 ─┤        │
  │   Worker 4 ─┘        │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │   PostgreSQL 16      │  ← mmam_db with connection pooling
  │   (Local)            │
  └──────────────────────┘

  THIS HANDLES: ~5,000 req/s
  COST: ~Rs 2,000/month (VPS)
  PERFECT FOR: 1-10,000 daily users`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">When to Graduate to Docker</h3>
      <Diagram title="Docker Compose Architecture">{`
  ┌─────────────── docker-compose.yml ──────────────────┐
  │                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
  │  │  nginx   │  │  app     │  │  worker   │         │
  │  │  :80     │──│  :3200   │  │  (queue)  │         │
  │  └──────────┘  └────┬─────┘  └────┬──────┘         │
  │                     │              │                │
  │                ┌────▼──────────────▼────┐           │
  │                │    Internal Network    │           │
  │                └────┬──────────────┬───┘           │
  │                     │              │                │
  │               ┌─────▼────┐  ┌─────▼────┐          │
  │               │ postgres │  │  redis   │          │
  │               │  :5432   │  │  :6379   │          │
  │               │  (data)  │  │  (cache) │          │
  │               └──────────┘  └──────────┘          │
  └─────────────────────────────────────────────────────┘

  ONE COMMAND: docker-compose up -d
  EVERYTHING STARTS TOGETHER
  ISOLATED NETWORK - SECURE BY DEFAULT`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">When to Graduate to Kubernetes</h3>
      <Diagram title="Kubernetes Architecture">{`
  ┌────────────────────── K8s Cluster ──────────────────────┐
  │                                                         │
  │  ┌─────────── Control Plane ───────────┐               │
  │  │  API Server │ Scheduler │ etcd      │               │
  │  │  Controller Manager                 │               │
  │  └─────────────────────────────────────┘               │
  │                                                         │
  │  ┌──── Node 1 ────┐  ┌──── Node 2 ────┐  ┌── Node 3 ─┐│
  │  │ ┌────┐ ┌────┐  │  │ ┌────┐ ┌────┐  │  │ ┌────┐    ││
  │  │ │App │ │App │  │  │ │API │ │API │  │  │ │Pay │    ││
  │  │ │Pod1│ │Pod2│  │  │ │Pod1│ │Pod2│  │  │ │Pod │    ││
  │  │ └────┘ └────┘  │  │ └────┘ └────┘  │  │ └────┘    ││
  │  │ ┌────┐         │  │ ┌────┐         │  │ ┌────┐    ││
  │  │ │DB  │         │  │ │Redis│        │  │ │Queue│   ││
  │  │ │Pod │         │  │ │Pod │         │  │ │Pod  │   ││
  │  │ └────┘         │  │ └────┘         │  │ └────┘    ││
  │  └────────────────┘  └────────────────┘  └───────────┘│
  │                                                         │
  │  Features: Auto-scaling, Self-healing, Rolling updates  │
  │  Load balancing, Service discovery, Secret management   │
  └─────────────────────────────────────────────────────────┘

  USE K8s WHEN:
  • 10+ microservices
  • Multiple teams deploying independently
  • Need auto-scaling (Black Friday spikes)
  • Zero-downtime is mandatory
  • Budget > Rs 30,000/month for infrastructure`}</Diagram>
    </div>
  ),
};

// ─── SECTION: HIGH TRAFFIC TECHNIQUES ──────────────────────
const highTrafficSection: Section = {
  id: "high-traffic",
  title: "High Traffic — Handling 10,000+ Requests/Second",
  icon: "⚡",
  content: (
    <div>
      <h3 className="mb-4 text-lg font-bold">The Scaling Pyramid</h3>
      <Diagram title="Optimization Priority (Bottom = Do First)">{`
                    ╱╲
                   ╱  ╲
                  ╱ K8s╲         ← Last resort. Only if you NEED it.
                 ╱ Auto ╲
                ╱ Scale  ╲
               ╱──────────╲
              ╱ Microsvcs  ╲     ← Split only when monolith is the bottleneck
             ╱──────────────╲
            ╱  Message Queue ╲   ← Async processing for heavy tasks
           ╱──────────────────╲
          ╱   Read Replicas    ╲  ← Scale database reads
         ╱──────────────────────╲
        ╱   Connection Pooling   ╲ ← PgBouncer: 10x DB efficiency
       ╱──────────────────────────╲
      ╱     Caching (Redis)        ╲ ← Cache hot data: 100x faster
     ╱──────────────────────────────╲
    ╱    Database Indexing            ╲ ← Proper indexes: 10-1000x faster
   ╱────────────────────────────────────╲
  ╱      CDN for Static Assets          ╲ ← Offload 80% of requests
 ╱────────────────────────────────────────╲
╱         Code Optimization                ╲ ← Fix N+1 queries, reduce payload
╲━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╱

START FROM THE BOTTOM. Each layer gives 10x improvement.
Most apps never need the top layers.`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">Caching Architecture</h3>
      <Diagram title="Multi-Layer Caching">{`
  Request arrives
       │
       ▼
  ┌──────────────────┐  HIT (< 1ms)
  │  Browser Cache   │─────────────────▶ Return cached response
  │  (localStorage,  │
  │   Service Worker)│
  └────────┬─────────┘
           │ MISS
           ▼
  ┌──────────────────┐  HIT (5-20ms)
  │  CDN Edge Cache  │─────────────────▶ Return from nearest PoP
  │  (Cloudflare,    │
  │   CloudFront)    │
  └────────┬─────────┘
           │ MISS
           ▼
  ┌──────────────────┐  HIT (1-5ms)
  │  Application     │─────────────────▶ Return from Redis
  │  Cache (Redis)   │
  └────────┬─────────┘
           │ MISS
           ▼
  ┌──────────────────┐  HIT (5-50ms)
  │  Database Query  │─────────────────▶ Execute query
  │  Cache           │                   Store result in Redis
  └────────┬─────────┘                   Return to user
           │ MISS
           ▼
  ┌──────────────────┐  (50-500ms)
  │  Full DB Query   │─────────────────▶ Run query on disk
  │  (PostgreSQL)    │                   Cache result
  └──────────────────┘                   Return to user

  GOAL: 95%+ cache hit ratio
  = Only 5% of requests reach the database`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">Load Balancing Strategies</h3>
      <Table
        headers={["Strategy", "How It Works", "Best For"]}
        rows={[
          ["Round Robin", "Requests go to servers in order: 1, 2, 3, 1, 2, 3...", "Equal servers, stateless apps"],
          ["Least Connections", "Send to server with fewest active connections", "Variable request times"],
          ["Weighted", "Server A gets 70%, Server B gets 30% (based on capacity)", "Mixed hardware"],
          ["IP Hash", "Same client IP always goes to same server", "Session affinity needs"],
          ["Geo-based", "Route to nearest data center by geography", "Global applications"],
          ["Health-aware", "Skip servers that fail health checks", "All production systems"],
        ]}
      />

      <h3 className="mt-8 mb-4 text-lg font-bold">Database Scaling Path</h3>
      <Diagram title="Database Scaling Journey">{`
  Stage 1: SINGLE SERVER
  ┌─────────────────┐
  │  PostgreSQL      │  Handles: ~5,000 queries/sec
  │  (All reads +    │  Cost: Rs 2,000/mo
  │   all writes)    │  Good for: < 10K daily users
  └─────────────────┘

  Stage 2: READ REPLICAS
  ┌─────────────────┐     ┌─────────────────┐
  │  Master          │────▶│  Replica 1      │  Handles: ~20,000 q/s
  │  (Writes only)   │────▶│  Replica 2      │  Cost: Rs 8,000/mo
  │                  │────▶│  Replica 3      │  Good for: < 100K users
  └─────────────────┘     └─────────────────┘

  Stage 3: SHARDING
  ┌────────────┐  ┌────────────┐  ┌────────────┐
  │  Shard 1   │  │  Shard 2   │  │  Shard 3   │  Handles: ~100K+ q/s
  │  Users A-I │  │  Users J-R │  │  Users S-Z │  Cost: Rs 30K+/mo
  └────────────┘  └────────────┘  └────────────┘  Good for: Millions

  Stage 4: DISTRIBUTED DATABASE
  ┌─────────────────────────────────────────────┐
  │  CockroachDB / Google Spanner / Vitess      │  Handles: Unlimited
  │  (Auto-sharding, global replication,         │  Cost: Rs 1L+/mo
  │   strongly consistent)                       │  Good for: Google-scale
  └─────────────────────────────────────────────┘`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">Hardware Quick Reference</h3>
      <Table
        headers={["Component", "Budget", "Standard", "High Performance"]}
        rows={[
          ["CPU", "2 cores (shared)", "4-8 cores (dedicated)", "16-32 cores"],
          ["RAM", "4 GB", "16-32 GB", "64-256 GB"],
          ["Storage", "50 GB SSD", "200 GB NVMe SSD", "1+ TB NVMe RAID"],
          ["Network", "1 Gbps shared", "1 Gbps dedicated", "10 Gbps"],
          ["Handles", "~500 req/s", "~5,000 req/s", "~50,000 req/s"],
          ["Cost/month", "Rs 500-1,000", "Rs 3,000-10,000", "Rs 30,000+"],
          ["Users", "< 1,000/day", "< 50,000/day", "< 1,000,000/day"],
        ]}
      />
    </div>
  ),
};

// ─── SECTION: SYSTEM DESIGN PATTERNS ────────────────────────
const patternsSection: Section = {
  id: "patterns",
  title: "System Design Patterns That Power the Internet",
  icon: "🏗️",
  content: (
    <div>
      <Diagram title="Event-Driven Architecture (Used by Uber, LinkedIn, Netflix)">{`
  ┌──────────┐     ┌──────────────────────┐     ┌──────────┐
  │ Producer │────▶│    Message Broker     │────▶│ Consumer │
  │ (Order   │     │    (Kafka / SQS)      │     │ (Email   │
  │  Service)│     │                       │     │  Service)│
  └──────────┘     │  ┌─────────────────┐  │     └──────────┘
                   │  │  Topic: orders  │  │
  ┌──────────┐     │  │  ┌──┬──┬──┬──┐  │  │     ┌──────────┐
  │ Producer │────▶│  │  │e1│e2│e3│e4│  │  │────▶│ Consumer │
  │ (Payment │     │  │  └──┴──┴──┴──┘  │  │     │ (Invoice │
  │  Service)│     │  └─────────────────┘  │     │  Service)│
  └──────────┘     └──────────────────────┘     └──────────┘

  WHY: Services don't call each other directly.
  They publish events. Anyone interested subscribes.
  If email service is down, events wait in the queue.
  No data lost. No cascade failures.`}</Diagram>

      <Diagram title="CQRS Pattern (Separate Read & Write Paths)">{`
  ┌──────────┐                            ┌──────────────┐
  │  WRITE   │                            │    READ      │
  │ Commands │                            │   Queries    │
  └────┬─────┘                            └──────┬───────┘
       │                                         │
       ▼                                         ▼
  ┌────────────┐     Event Stream      ┌────────────────┐
  │ PostgreSQL │ ────────────────────▶ │ Elasticsearch  │
  │ (Source of │     (Kafka sync)      │ (Optimized for │
  │  truth)    │                       │  fast search)  │
  └────────────┘                       └────────────────┘

  Write DB: Optimized for consistency & transactions
  Read DB: Optimized for speed & complex queries
  Best of both worlds.`}</Diagram>

      <Diagram title="Circuit Breaker Pattern (Netflix Hystrix)">{`
  Normal State:
  Service A ──────▶ Service B ──────▶ Response ✓

  Service B is slow/failing:
  Service A ──────▶ Service B ──────▶ Timeout ✗ (3 failures)
                        │
                        ▼
              ┌─────────────────┐
              │ CIRCUIT OPEN    │  ← Stop calling Service B
              │ (30 sec timer)  │     Return fallback response
              └────────┬────────┘     instead. Protect the system.
                       │
              After 30 seconds:
                       │
              ┌────────▼────────┐
              │ HALF-OPEN       │  ← Try ONE request to Service B
              │ (Test request)  │
              └────────┬────────┘
                       │
               ┌───────┴───────┐
               │               │
            Success          Failure
               │               │
               ▼               ▼
          ┌─────────┐   ┌───────────┐
          │ CLOSED  │   │   OPEN    │
          │ (Normal)│   │(Wait more)│
          └─────────┘   └───────────┘`}</Diagram>

      <h3 className="mt-8 mb-4 text-lg font-bold">Quick Reference: Who Uses What</h3>
      <Table
        headers={["Company", "Language", "Database", "Message Queue", "Special Sauce"]}
        rows={[
          ["Google", "C++, Go, Java", "Bigtable, Spanner", "Pub/Sub", "Custom everything — TPUs, Borg, GFS"],
          ["Netflix", "Java, Node.js", "Cassandra, EVCache", "Kafka", "Open Connect CDN inside ISPs"],
          ["Amazon", "Java, Go", "DynamoDB, Aurora", "SQS, Kinesis", "Two-pizza teams, service ownership"],
          ["Uber", "Go, Java", "MySQL, Cassandra", "Kafka", "H3 geospatial grid, Ringpop"],
          ["WhatsApp", "Erlang", "Mnesia, PostgreSQL", "Custom", "2M connections/server, FreeBSD tuning"],
          ["Twitter/X", "Scala, Java", "Manhattan, MySQL", "Kafka", "Fan-out on write + read hybrid"],
          ["IRCTC", "Java", "Oracle, PostgreSQL", "RabbitMQ", "Queue-based ticket allocation"],
          ["Flipkart", "Java, Go", "MySQL, Cassandra", "Kafka", "Pods architecture for shop isolation"],
          ["PhonePe/UPI", "Java", "MariaDB, Cassandra", "Kafka", "ISO 8583, NPCI switch integration"],
        ]}
      />
    </div>
  ),
};

const SECTIONS: Section[] = [
  visaSection,
  netflixSection,
  upiSection,
  dockerK8sSection,
  highTrafficSection,
  patternsSection,
  ...extendedSections,
  microservicesSection,
];

export default function ArchitecturePage() {
  const [activeSection, setActiveSection] = useState(SECTIONS[0].id);
  const current = SECTIONS.find((s) => s.id === activeSection) || SECTIONS[0];

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-6">
        <Link href="/executive" className="text-sm text-accent hover:text-accent-hover">
          ← Executive MBA
        </Link>
        <h1 className="mt-2 text-3xl font-bold tracking-tight">System Architecture</h1>
        <p className="mt-2 text-muted">
          Deep-dive into how the world&apos;s biggest systems work. VISA, Netflix, UPI, and the architecture decisions behind them.
        </p>
      </div>

      {/* Section tabs */}
      <div className="mb-8 flex gap-2 overflow-x-auto pb-2">
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveSection(s.id)}
            className={`flex shrink-0 items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition-colors ${
              activeSection === s.id
                ? "bg-accent text-white"
                : "bg-surface text-muted hover:bg-surface-hover"
            }`}
          >
            <span>{s.icon}</span>
            <span className="hidden sm:inline">{s.title.split("—")[0].trim()}</span>
            <span className="sm:hidden">{s.title.split("—")[0].trim().split(" ")[0]}</span>
          </button>
        ))}
      </div>

      {/* Active section */}
      <div>
        <h2 className="mb-6 text-2xl font-bold">{current.icon} {current.title}</h2>
        {current.content}
      </div>

      <div className="mt-12 rounded-xl border border-accent/20 bg-accent/5 p-6 text-center">
        <p className="text-sm font-medium text-accent">
          Knowledge is power. Now go discuss architecture at Gymkhana like you run a tech empire.
        </p>
      </div>
    </div>
  );
}
