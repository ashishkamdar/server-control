import React from "react";
import type { Section } from "./sections-extended";

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

export const microservicesSection: Section = {
  id: "microservices",
  title: "Microservices — Architecture, Licensing, Hardware & Teams",
  icon: "🧩",
  content: (
    <div>
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Netflix" value="1,000+" sub="Microservices" />
        <Stat label="Amazon" value="2,000+" sub="Microservices" />
        <Stat label="Uber" value="4,000+" sub="Microservices" />
        <Stat label="Typical SME" value="5-15" sub="Microservices needed" />
      </div>

      {/* ── WHAT ARE MICROSERVICES ── */}
      <h3 className="mb-2 text-lg font-bold">Monolith vs Microservices — The Core Idea</h3>
      <p className="mb-4 text-sm text-muted">
        A monolith is one big application doing everything. Microservices break it into small, independent services — each doing one thing well.
      </p>

      <Diagram title="Monolith vs Microservices">{`
  ╔═══════════════════════════════════════════════════════════════╗
  ║                        MONOLITH                              ║
  ║                                                               ║
  ║  ┌──────────────────────────────────────────────────────┐    ║
  ║  │                  ONE APPLICATION                     │    ║
  ║  │                                                      │    ║
  ║  │  User Module  │  Payment  │  Inventory │  Email     │    ║
  ║  │  Notification │  Reports  │  Auth      │  Search    │    ║
  ║  │                                                      │    ║
  ║  │  ONE database │  ONE deployment │  ONE codebase      │    ║
  ║  └──────────────────────────────────────────────────────┘    ║
  ║                                                               ║
  ║  ✅ Simple to start    ✅ Easy debugging    ✅ Low cost       ║
  ║  ❌ Hard to scale parts independently                        ║
  ║  ❌ One bug can crash everything                              ║
  ║  ❌ 50+ developers stepping on each other                    ║
  ╠═══════════════════════════════════════════════════════════════╣
  ║                     MICROSERVICES                             ║
  ║                                                               ║
  ║  ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐  ║
  ║  │ User   │ │Payment │ │Inventory │ │ Email  │ │ Search │  ║
  ║  │Service │ │Service │ │ Service  │ │Service │ │Service │  ║
  ║  │        │ │        │ │          │ │        │ │        │  ║
  ║  │Own DB  │ │Own DB  │ │ Own DB   │ │Own DB  │ │Own DB  │  ║
  ║  │Own team│ │Own team│ │ Own team │ │Own team│ │Own team│  ║
  ║  └───┬────┘ └───┬────┘ └────┬─────┘ └───┬────┘ └───┬────┘  ║
  ║      └──────────┴───────────┴────────────┴──────────┘       ║
  ║                    Message Bus (Kafka/RabbitMQ)               ║
  ║                                                               ║
  ║  ✅ Scale each service independently                         ║
  ║  ✅ Each team deploys independently                          ║
  ║  ✅ Different tech stack per service (polyglot)              ║
  ║  ❌ Complex to operate     ❌ Network latency                ║
  ║  ❌ Distributed debugging  ❌ Need DevOps team               ║
  ╚═══════════════════════════════════════════════════════════════╝`}</Diagram>

      {/* ── ARCHITECTURE PATTERNS ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Microservice Communication Patterns</h3>

      <Diagram title="Synchronous vs Asynchronous Communication">{`
  ╔═══════════════════════════════════════════════════════════╗
  ║  SYNCHRONOUS (Request-Response)                          ║
  ║                                                           ║
  ║  Order Service ──── REST/gRPC ────▶ Payment Service      ║
  ║       │                                   │              ║
  ║       │◀────── Response (200 OK) ─────────┘              ║
  ║                                                           ║
  ║  ✅ Simple, familiar                                     ║
  ║  ❌ Caller waits (blocked). If Payment is slow, Order    ║
  ║     is slow too. Cascading latency.                      ║
  ╠═══════════════════════════════════════════════════════════╣
  ║  ASYNCHRONOUS (Event-Driven)                             ║
  ║                                                           ║
  ║  Order Service ──── Event ────▶ [Message Queue] ────▶    ║
  ║       │                              │                    ║
  ║       │ (doesn't wait)               ├──▶ Payment Svc    ║
  ║       │                              ├──▶ Email Svc      ║
  ║       ▼                              └──▶ Analytics Svc  ║
  ║  Returns "Order Placed"                                   ║
  ║  immediately                                              ║
  ║                                                           ║
  ║  ✅ Fast, resilient, loosely coupled                     ║
  ║  ✅ If Email Svc is down, events queue until it's back   ║
  ║  ❌ Harder to debug (eventual consistency)               ║
  ╚═══════════════════════════════════════════════════════════╝`}</Diagram>

      <Diagram title="API Gateway Pattern">{`
  Mobile App ──┐
               │
  Web App ─────┤                   ┌──▶ User Service
               │                   │
  3rd Party ───┼──▶ ┌──────────┐  ├──▶ Order Service
               │    │   API    │──┤
  Admin Panel ─┘    │ Gateway  │  ├──▶ Payment Service
                    │          │  │
                    │ • Auth   │  ├──▶ Inventory Service
                    │ • Rate   │  │
                    │   Limit  │  ├──▶ Search Service
                    │ • Route  │  │
                    │ • Cache  │  └──▶ Notification Svc
                    │ • Log    │
                    └──────────┘
                    Kong / AWS API GW / nginx

  WHY API GATEWAY:
  ════════════════
  • Clients talk to ONE endpoint, not 20 different services
  • Authentication handled ONCE at the gateway
  • Rate limiting protects all services uniformly
  • Request/response transformation (XML↔JSON)
  • Aggregation: combine responses from 3 services into 1`}</Diagram>

      <Diagram title="Service Mesh (Istio / Linkerd)">{`
  ┌─────────────────────────────────────────────────────────┐
  │                  SERVICE MESH                           │
  │                                                         │
  │  ┌─────────────────┐        ┌─────────────────┐        │
  │  │   Service A     │        │   Service B     │        │
  │  │  ┌───────────┐  │        │  ┌───────────┐  │        │
  │  │  │ Your Code │  │        │  │ Your Code │  │        │
  │  │  └─────┬─────┘  │        │  └─────▲─────┘  │        │
  │  │        │        │        │        │        │        │
  │  │  ┌─────▼─────┐  │        │  ┌─────┴─────┐  │        │
  │  │  │  Sidecar  │──┼────────┼──│  Sidecar  │  │        │
  │  │  │  Proxy    │  │  mTLS  │  │  Proxy    │  │        │
  │  │  │ (Envoy)   │  │encrypted│  │ (Envoy)   │  │        │
  │  │  └───────────┘  │        │  └───────────┘  │        │
  │  └─────────────────┘        └─────────────────┘        │
  │                                                         │
  │  WHAT THE SIDECAR PROXY DOES (without changing code):  │
  │  • Encrypts all service-to-service traffic (mTLS)      │
  │  • Retries failed requests automatically               │
  │  • Circuit breaking                                    │
  │  • Distributed tracing (Jaeger integration)            │
  │  • Traffic splitting (canary: 5% to v2, 95% to v1)    │
  │  • Metrics collection (latency, error rates)           │
  └─────────────────────────────────────────────────────────┘

  YOUR CODE DOESN'T CHANGE — the mesh handles all networking.
  Used by: Airbnb, eBay, T-Mobile, Salesforce`}</Diagram>

      {/* ── DATA MANAGEMENT ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Data Management in Microservices</h3>

      <Diagram title="Database Per Service Pattern">{`
  ╔═══════════════════════════════════════════════════════════╗
  ║  ANTI-PATTERN: Shared Database (DON'T DO THIS)           ║
  ║                                                           ║
  ║  Svc A ──┐                                               ║
  ║          ├──▶  ┌──────────────┐                          ║
  ║  Svc B ──┤     │  Shared DB   │  ← All services write    ║
  ║          ├──▶  │  (Coupled!)  │     to same tables.       ║
  ║  Svc C ──┘     └──────────────┘     Can't change schema   ║
  ║                                     without breaking all. ║
  ╠═══════════════════════════════════════════════════════════╣
  ║  CORRECT: Database Per Service                            ║
  ║                                                           ║
  ║  User Svc ──▶ ┌──────────┐                               ║
  ║               │ Users DB │  (PostgreSQL)                  ║
  ║               └──────────┘                                ║
  ║                                                           ║
  ║  Order Svc ──▶ ┌──────────┐                              ║
  ║               │ Orders DB│  (MySQL)                       ║
  ║               └──────────┘                                ║
  ║                                                           ║
  ║  Search Svc ──▶ ┌──────────┐                             ║
  ║                │Search DB │  (Elasticsearch)              ║
  ║                └──────────┘                               ║
  ║                                                           ║
  ║  Each service OWNS its data. Other services access it     ║
  ║  only through APIs, never directly.                       ║
  ║  Each service can use the BEST database for its needs.    ║
  ╚═══════════════════════════════════════════════════════════╝`}</Diagram>

      <Diagram title="Saga Pattern — Distributed Transactions">{`
  PROBLEM: Customer places order. Need to:
  1. Create order  2. Reserve inventory  3. Charge payment
  If payment fails, must undo steps 1 and 2.

  ┌──────────┐    ┌───────────┐    ┌──────────┐
  │  Order   │───▶│ Inventory │───▶│ Payment  │
  │  Created │    │ Reserved  │    │ Charged  │
  └──────────┘    └───────────┘    └──────────┘
       │               │               │
       │          If payment fails:    │
       │               │               │
       │    ┌──────────▼───────┐       │
       │    │ Compensating     │       │
       │    │ Transaction:     │       │
       │    │ Release inventory│       │
       │    └──────────┬───────┘       │
       │               │               │
  ┌────▼───────────────▼───────────────┘
  │ Compensating Transaction:
  │ Cancel order
  └────────────────────────────────

  TWO TYPES:
  ══════════
  Choreography: Each service publishes events, next listens
  → Simpler but harder to track the overall flow

  Orchestrator: Central coordinator tells each service what to do
  → More control but single point of coordination`}</Diagram>

      {/* ── LICENSING ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Technology Licensing — What You&apos;re Actually Paying For</h3>

      <Table
        headers={["Technology", "License", "Cost", "Notes"]}
        rows={[
          ["PostgreSQL", "Open Source (PostgreSQL License)", "FREE", "No limits on usage, commercial use, or modifications. The best deal in software."],
          ["MySQL", "Dual: GPL + Commercial (Oracle)", "FREE (GPL) or $2K-10K/yr", "GPL: free but must open-source if distributed. Commercial: proprietary use."],
          ["MongoDB", "SSPL (Server Side Public License)", "FREE (Community) or $57/mo+", "SSPL restricts SaaS usage. Atlas (cloud) starts at $57/month."],
          ["Redis", "Dual: RSALv2 + SSPLv1", "FREE (self-host) or $5/mo+", "License changed 2024. Cloud providers can't resell. Self-host is free."],
          ["Elasticsearch", "SSPL + Elastic License", "FREE (self-host) or $95/mo+", "Can't offer as a managed service. Use OpenSearch (AWS fork) if needed."],
          ["Kafka", "Apache 2.0 (Open Source)", "FREE", "Truly open source. Confluent offers managed service ($0.11/GB)."],
          ["Kubernetes", "Apache 2.0 (Open Source)", "FREE (self-host)", "Free to run. Managed: EKS $72/mo, GKE $72/mo per cluster."],
          ["Docker", "Apache 2.0 (Engine)", "FREE (Engine) or $5-24/user/mo", "Docker Engine is free. Docker Desktop requires license for companies >250 employees."],
          ["nginx", "BSD-2 (Open Source)", "FREE or $3,675/yr (Plus)", "Open source is free. nginx Plus adds enterprise features."],
          ["Oracle DB", "Proprietary", "Rs 30L-5Cr+/year", "Named User Plus or Processor-based. Extremely expensive. Avoid if possible."],
          ["SQL Server", "Proprietary (Microsoft)", "$930-15K+ per core", "Standard: $3,900/2-core. Enterprise: $15,100/2-core. Express: free (10GB limit)."],
          ["AWS/GCP/Azure", "Pay-as-you-go", "Variable", "No license fee — pay for compute/storage/transfer by the hour."],
        ]}
      />

      <div className="my-6 rounded-xl border border-amber-500/30 bg-amber-500/5 p-5">
        <p className="mb-2 text-sm font-bold text-amber-500">Licensing Advice for Your Clients</p>
        <p className="text-sm text-muted">
          For Indian SMEs and samaj organizations, recommend the <strong>fully open-source stack</strong>:
          PostgreSQL + Redis + nginx + Node.js + Next.js. Zero licensing costs, enterprise-grade quality.
          This is exactly what MMAM uses. When a client says &quot;Oracle charges us Rs 30L/year&quot;,
          you can say: &quot;I can build the same on PostgreSQL for Rs 0 in licensing.&quot; That&apos;s a powerful pitch.
        </p>
      </div>

      {/* ── HARDWARE REQUIREMENTS ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Hardware Requirements by Architecture Size</h3>

      <Table
        headers={["Scale", "Architecture", "Servers", "RAM Total", "CPU Cores", "Storage", "Monthly Cost"]}
        rows={[
          ["Tiny (1-5K users)", "Monolith on VPS", "1 server", "4-8 GB", "2-4", "50 GB SSD", "Rs 500-2K"],
          ["Small (5-50K users)", "Monolith + Cache", "2 servers (app + DB)", "16-32 GB", "8-16", "200 GB NVMe", "Rs 3K-10K"],
          ["Medium (50K-500K users)", "3-5 Microservices", "4-8 servers", "64-128 GB", "32-64", "1 TB NVMe", "Rs 15K-50K"],
          ["Large (500K-5M users)", "10-20 Microservices", "15-30 servers", "256-512 GB", "128-256", "5 TB NVMe", "Rs 1L-5L"],
          ["Enterprise (5M+ users)", "50+ Microservices", "100+ servers", "2+ TB", "500+", "50+ TB", "Rs 10L+"],
        ]}
      />

      <Diagram title="Hardware Architecture for Medium Scale (50K-500K Users)">{`
  ┌───────────────────── Infrastructure Map ─────────────────────┐
  │                                                              │
  │  LOAD BALANCER (nginx / HAProxy)                             │
  │  • 2 cores, 4 GB RAM, 50 GB SSD                             │
  │  • Cost: Rs 1,500/mo                                         │
  │                                                              │
  │  APPLICATION SERVERS (×3 for redundancy)                     │
  │  • 4 cores, 16 GB RAM, 100 GB NVMe each                     │
  │  • PM2 cluster mode (4 workers each = 12 total)              │
  │  • Cost: Rs 4,000/mo × 3 = Rs 12,000/mo                     │
  │                                                              │
  │  DATABASE SERVER (Primary)                                   │
  │  • 8 cores, 32 GB RAM, 500 GB NVMe                          │
  │  • PostgreSQL 16, tuned for performance                      │
  │  • shared_buffers = 8GB, effective_cache_size = 24GB         │
  │  • Cost: Rs 8,000/mo                                         │
  │                                                              │
  │  DATABASE REPLICA (Read-only, failover)                      │
  │  • 8 cores, 32 GB RAM, 500 GB NVMe                          │
  │  • Streaming replication from primary                        │
  │  • Cost: Rs 8,000/mo                                         │
  │                                                              │
  │  CACHE SERVER (Redis)                                        │
  │  • 4 cores, 16 GB RAM, 50 GB SSD                            │
  │  • Cost: Rs 4,000/mo                                         │
  │                                                              │
  │  MESSAGE QUEUE (RabbitMQ / Redis Streams)                    │
  │  • Can share with cache server for medium scale              │
  │  • Separate server at large scale                            │
  │                                                              │
  │  ═══════════════════════════════════════                     │
  │  TOTAL: ~Rs 33,500/mo for 50K-500K users                    │
  │  HANDLES: ~10,000 requests/second                            │
  │  UPTIME: 99.95% with failover                               │
  └──────────────────────────────────────────────────────────────┘`}</Diagram>

      {/* ── TEAM & MANPOWER ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Team Size & Manpower Requirements</h3>

      <Table
        headers={["Scale", "Architecture", "Dev Team", "DevOps", "Total", "Monthly Payroll (India)"]}
        rows={[
          ["Tiny (monolith)", "1-2 services", "1 full-stack dev", "0 (dev manages)", "1 person", "Rs 50K-1.5L"],
          ["Small (monolith+)", "2-3 services", "2-3 developers", "0-1 part-time", "2-3 people", "Rs 1.5L-5L"],
          ["Medium (microservices)", "5-10 services", "5-8 developers", "1-2 DevOps", "6-10 people", "Rs 5L-15L"],
          ["Large", "10-30 services", "15-30 developers", "3-5 DevOps + SRE", "20-35 people", "Rs 20L-60L"],
          ["Enterprise", "50+ services", "50-200+ developers", "10-20 DevOps/SRE", "60-220+ people", "Rs 1Cr+"],
        ]}
      />

      <Diagram title="Team Structure for Microservices (Medium Scale)">{`
  ┌─────────────────────────────────────────────────────────┐
  │              AMAZON'S TWO-PIZZA TEAM RULE               │
  │                                                         │
  │  "Every team should be small enough to be fed by        │
  │   two pizzas." — Jeff Bezos                             │
  │                                                         │
  │  Each microservice is owned by ONE team of 3-8 people.  │
  │  They build it, deploy it, and operate it (on-call).    │
  └─────────────────────────────────────────────────────────┘

  ┌──────────────────────── Medium Scale Example ────────────┐
  │                                                          │
  │  TEAM: User & Auth (4 people)                            │
  │  ├── 2 Backend developers                                │
  │  ├── 1 Frontend developer                                │
  │  └── 1 QA / Part-time DevOps                             │
  │  Owns: User Service, Auth Service, Profile Service       │
  │                                                          │
  │  TEAM: Orders & Payments (4 people)                      │
  │  ├── 2 Backend developers                                │
  │  ├── 1 Frontend developer                                │
  │  └── 1 QA                                                │
  │  Owns: Order Service, Payment Service, Invoice Service   │
  │                                                          │
  │  TEAM: Platform / DevOps (2 people)                      │
  │  ├── 1 DevOps / SRE engineer                             │
  │  └── 1 Database administrator (can be part-time)         │
  │  Owns: CI/CD, Monitoring, Infrastructure, Databases      │
  │                                                          │
  │  TOTAL: 10 people for 6-8 microservices                  │
  │                                                          │
  │  KEY ROLES:                                              │
  │  ══════════                                              │
  │  Backend Dev:    Rs 8L-25L/yr  (builds services)         │
  │  Frontend Dev:   Rs 6L-20L/yr  (builds UI)               │
  │  DevOps/SRE:     Rs 12L-35L/yr (keeps it all running)    │
  │  DBA:            Rs 10L-30L/yr (database performance)     │
  │  QA Engineer:    Rs 5L-15L/yr  (testing & quality)        │
  │  Tech Lead:      Rs 20L-50L/yr (architecture decisions)   │
  │  Engineering Mgr: Rs 25L-60L/yr (team management)         │
  └──────────────────────────────────────────────────────────┘`}</Diagram>

      {/* ── WHEN TO USE WHAT ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">The Golden Rule: When to Use Microservices</h3>

      <Diagram title="Decision Framework">{`
  ╔═══════════════════════════════════════════════════════════╗
  ║              SHOULD YOU USE MICROSERVICES?                ║
  ╠═══════════════════════════════════════════════════════════╣
  ║                                                           ║
  ║  ❓ Do you have > 10 developers?                         ║
  ║     NO → Stay monolith. Microservices need teams.        ║
  ║                                                           ║
  ║  ❓ Do different parts need to scale independently?      ║
  ║     NO → Stay monolith. Scaling the whole thing works.   ║
  ║                                                           ║
  ║  ❓ Do teams step on each other during deployment?       ║
  ║     NO → Stay monolith. One pipeline is simpler.         ║
  ║                                                           ║
  ║  ❓ Do you have DevOps expertise?                        ║
  ║     NO → Stay monolith. Microservices need ops skills.   ║
  ║                                                           ║
  ║  ❓ Is your traffic > 10,000 requests/second?            ║
  ║     NO → Stay monolith. A single server handles a lot.   ║
  ║                                                           ║
  ║  IF YOU ANSWERED "YES" TO 3+ QUESTIONS:                  ║
  ║  → Consider microservices                                ║
  ║  → Start by extracting ONE service (the most painful)    ║
  ║  → Use the Strangler Fig pattern (gradual migration)     ║
  ║                                                           ║
  ║  ┌─────────────────────────────────────────────────────┐ ║
  ║  │  "If you can't build a well-structured monolith,    │ ║
  ║  │   what makes you think microservices are the         │ ║
  ║  │   answer?" — Simon Brown                            │ ║
  ║  └─────────────────────────────────────────────────────┘ ║
  ╚═══════════════════════════════════════════════════════════╝`}</Diagram>

      {/* ── MIGRATION PATH ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Migration: Monolith → Microservices (Strangler Fig)</h3>

      <Diagram title="Strangler Fig Pattern — Gradual Migration">{`
  PHASE 1: Monolith handles everything
  ┌────────────────────────────────────────┐
  │              MONOLITH                  │
  │  User │ Order │ Payment │ Email │ Auth │
  └────────────────────────────────────────┘

  PHASE 2: Extract the most painful service
  ┌───────────────────────────────┐  ┌──────────┐
  │          MONOLITH             │  │ Payment  │ ← Extracted!
  │  User │ Order │ Email │ Auth  │──│ Service  │    Own DB,
  └───────────────────────────────┘  └──────────┘    Own deploy

  PHASE 3: Continue extracting
  ┌──────────────────┐  ┌──────────┐  ┌────────┐
  │    MONOLITH      │  │ Payment  │  │  Auth  │
  │  User │ Order    │──│ Service  │  │Service │
  │  Email           │  └──────────┘  └────────┘
  └──────────────────┘

  PHASE 4: Monolith becomes just another service
  ┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐
  │ User   │ │ Order  │ │ Payment  │ │ Email  │ │  Auth  │
  │Service │ │Service │ │ Service  │ │Service │ │Service │
  └────────┘ └────────┘ └──────────┘ └────────┘ └────────┘

  TIMELINE: 6-18 months for medium complexity
  RULE: Never do a "big bang" rewrite. Gradual = safe.`}</Diagram>

      {/* ── OBSERVABILITY ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Observability Stack for Microservices</h3>

      <Table
        headers={["Tool", "Purpose", "License", "Cost"]}
        rows={[
          ["Prometheus", "Metrics collection (CPU, RAM, request rates)", "Apache 2.0 (Free)", "Free self-host, or $8/mo Grafana Cloud"],
          ["Grafana", "Dashboards & visualization", "AGPL (Free)", "Free self-host, or $8/mo cloud"],
          ["Jaeger / Zipkin", "Distributed tracing", "Apache 2.0 (Free)", "Free self-host"],
          ["ELK Stack", "Log aggregation (Elasticsearch + Logstash + Kibana)", "SSPL", "Free self-host, $95/mo+ Elastic Cloud"],
          ["Loki", "Log aggregation (lightweight, Grafana ecosystem)", "AGPL (Free)", "Free self-host"],
          ["PagerDuty", "Alerting & on-call management", "Proprietary", "$21/user/mo"],
          ["Sentry", "Error tracking & crash reporting", "BSL", "Free tier, $26/mo+ paid"],
          ["Datadog", "All-in-one (metrics, logs, traces, APM)", "Proprietary", "$15-31/host/mo"],
          ["New Relic", "All-in-one APM", "Proprietary", "Free tier (100GB/mo), then $0.30/GB"],
        ]}
      />

      <Diagram title="Observability Architecture">{`
  ┌───────────────────── Your Microservices ─────────────────┐
  │                                                          │
  │  Svc A    Svc B    Svc C    Svc D    Svc E              │
  │   │        │        │        │        │                  │
  │   └────────┴────────┴────────┴────────┘                  │
  │                     │                                    │
  └─────────────────────┼────────────────────────────────────┘
                        │
           ┌────────────┼────────────┐
           │            │            │
           ▼            ▼            ▼
    ┌────────────┐ ┌─────────┐ ┌──────────┐
    │ Prometheus │ │  Loki   │ │  Jaeger  │
    │ (Metrics)  │ │ (Logs)  │ │ (Traces) │
    └─────┬──────┘ └────┬────┘ └────┬─────┘
          │             │           │
          └─────────────┼───────────┘
                        │
                  ┌─────▼─────┐
                  │  Grafana  │  ← Single pane of glass
                  │ Dashboard │     for everything
                  └─────┬─────┘
                        │
                  ┌─────▼─────┐
                  │ Alerting  │  → PagerDuty / Slack / Email
                  └───────────┘

  COST FOR SELF-HOSTED: Rs 3,000-5,000/mo (one monitoring server)
  WHAT YOU GET: Enterprise-grade observability for free`}</Diagram>

      {/* ── REAL-WORLD EXAMPLES ── */}
      <h3 className="mt-8 mb-2 text-lg font-bold">Real-World Microservice Examples</h3>

      <Table
        headers={["Company", "# Services", "Team Size", "Key Lesson"]}
        rows={[
          ["Netflix", "1,000+", "~2,000 engineers", "Each team owns 2-3 services end-to-end. 'You build it, you run it.'"],
          ["Amazon", "2,000+", "~30,000 engineers", "Two-pizza teams. Mandate: all communication via APIs. Led to AWS."],
          ["Uber", "4,000+", "~6,000 engineers", "Started monolith, hit scaling wall at 1,000 engineers. Microservices saved them."],
          ["Spotify", "~800", "~2,000 engineers", "Squads (teams) own features. Guilds share knowledge across squads."],
          ["Shopify", "1 monolith", "~3,000 engineers", "Chose to KEEP the monolith and optimize it. Proof that microservices aren't always the answer."],
          ["Stack Overflow", "1 monolith", "~50 engineers", "Serves 1.3B page views/month on a monolith. Scale without complexity."],
          ["Basecamp", "1 monolith", "~20 engineers", "Ruby on Rails monolith. Profitable, millions of users. Deliberately simple."],
        ]}
      />

      <div className="my-6 rounded-xl border border-accent/20 bg-accent/5 p-5">
        <p className="mb-2 text-sm font-bold text-accent">For Your Client Conversations</p>
        <p className="text-sm text-muted">
          When a client or Gymkhana uncle asks about microservices, here&apos;s your line:
          &quot;Microservices make sense when you have 10+ developers and need to deploy independently.
          For most Indian businesses, a well-built monolith with good caching handles millions of users.
          Stack Overflow serves 1.3 billion page views on just 9 servers — no microservices.
          I&apos;ll recommend the right architecture for your scale, not the trendy one.&quot;
        </p>
      </div>
    </div>
  ),
};
