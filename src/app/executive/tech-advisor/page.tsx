"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { generateProjectPlan, type ProjectPlan } from "./project-planner";

// ─── SAVED REPORT TYPE ─────────────────────────────────
interface SavedReport {
  id: number;
  title: string;
  whatsapp_summary: string;
  created_at: string;
  requirements?: Requirements;
  recommendation?: Recommendation;
  project_plan?: ProjectPlan;
}

// ─── TYPES ─────────────────────────────────────────────────
interface Requirements {
  // Step 1: Application Type
  appType: "web" | "mobile" | "both" | "api-only" | "desktop" | "desktop-web" | "";
  platform: "any" | "windows-only" | "mac-only" | "linux-only" | "cross-platform" | "ios-only" | "android-only" | "ios-android" | "";
  pwaNeeded: boolean;
  offlineNeeded: boolean;

  // Step 2: Scale
  totalUsers: "under100" | "100-1K" | "1K-10K" | "10K-100K" | "100K-1M" | "1M+" | "";
  concurrentUsers: "under10" | "10-50" | "50-200" | "200-1K" | "1K-5K" | "5K-50K" | "50K+" | "";
  transactionsPerDay: "under100" | "100-1K" | "1K-10K" | "10K-100K" | "100K+" | "";
  peakHoursPattern: "steady" | "business-hours" | "spiky" | "24x7" | "";
  dataVolume: "under1GB" | "1-10GB" | "10-100GB" | "100GB-1TB" | "1TB+" | "";

  // Step 3: Features
  realTimeNeeded: boolean;
  fileUploads: boolean;
  paymentProcessing: boolean;
  searchHeavy: boolean;
  reportingDashboards: boolean;
  multiLanguage: boolean;
  multiTenant: boolean;
  aiFeatures: boolean;
  contentType: "text" | "media" | "data" | "mixed" | "";
  notificationChannels: { email: boolean; sms: boolean; push: boolean; whatsapp: boolean };
  publicAPI: boolean;
  userRoles: "simple" | "moderate" | "complex" | "";

  // Step 4: Data & Security
  dataType: "public" | "internal" | "sensitive" | "financial" | "government" | "";
  complianceNeeds: string[];
  dataRetentionYears: "1" | "3" | "7" | "10+" | "";
  industry: "general" | "healthcare" | "education" | "fintech" | "ecommerce" | "community" | "logistics" | "manufacturing" | "";
  uptimeRequirement: "99" | "99.9" | "99.95" | "99.99" | "";

  // Step 5: Infrastructure
  deployment: "cloud" | "self-hosted" | "on-premise" | "hybrid" | "";
  geoReach: "single-city" | "india" | "asia" | "global" | "";

  // Step 6: Constraints & Migration
  clientName: string;
  projectName: string;
  budget: "under1L" | "1-5L" | "5-15L" | "15-50L" | "50L+" | "";
  timeline: "1month" | "2-3months" | "3-6months" | "6-12months" | "12months+" | "";
  teamSize: "solo" | "2-3" | "4-8" | "8-15" | "15+" | "";
  existingSystems: string;
  replacingExisting: boolean;
  trainingNeeded: boolean;
  maintenanceContract: boolean;
}

const INITIAL: Requirements = {
  appType: "", platform: "", pwaNeeded: false, offlineNeeded: false,
  totalUsers: "", concurrentUsers: "", transactionsPerDay: "", peakHoursPattern: "", dataVolume: "",
  realTimeNeeded: false, fileUploads: false, paymentProcessing: false, searchHeavy: false,
  reportingDashboards: false, multiLanguage: false, multiTenant: false, aiFeatures: false,
  contentType: "", notificationChannels: { email: false, sms: false, push: false, whatsapp: false },
  publicAPI: false, userRoles: "",
  dataType: "", complianceNeeds: [], dataRetentionYears: "", industry: "", uptimeRequirement: "",
  deployment: "", geoReach: "",
  clientName: "", projectName: "",
  budget: "", timeline: "", teamSize: "", existingSystems: "",
  replacingExisting: false, trainingNeeded: false, maintenanceContract: false,
};

// ─── RECOMMENDATION ENGINE ─────────────────────────────────
export interface Recommendation {
  frontend: { tech: string; why: string };
  backend: { tech: string; why: string };
  database: { primary: string; cache: string; search?: string; why: string };
  messaging?: { tech: string; why: string };
  hosting: { type: string; specs: ServerSpec[]; why: string };
  loadBalancer: { tech: string; why: string };
  security: { firewall: string; waf: string; ssl: string; auth: string; why: string };
  monitoring: { tech: string; why: string };
  cicd: { tech: string; why: string };
  cdn?: { tech: string; why: string };
  costs: { monthly: string; yearly: string; breakdown: { item: string; cost: string }[] };
  team: { roles: { role: string; count: string; salary: string }[]; total: string };
  timeline: string;
  architectureDiagram: string;
}

interface ServerSpec {
  role: string;
  count: number;
  cpu: string;
  ram: string;
  storage: string;
  os: string;
}

function generateRecommendation(req: Requirements): Recommendation {
  // Determine scale tier
  const scale = getScaleTier(req);
  const isFinancial = req.dataType === "financial" || req.paymentProcessing;
  const isGovernment = req.dataType === "government";
  const needsRealTime = req.realTimeNeeded;
  const isMobile = req.appType === "mobile" || req.appType === "both";
  const isWeb = req.appType === "web" || req.appType === "both";

  // ── FRONTEND ──
  const isDesktop = req.appType === "desktop" || req.appType === "desktop-web";
  const isWindowsOnly = req.platform === "windows-only";
  const isCrossPlatformDesktop = req.platform === "cross-platform" && isDesktop;

  const frontend = (() => {
    // Desktop applications
    if (req.appType === "desktop" && isWindowsOnly) return {
      tech: "Electron (TypeScript + React) or .NET WPF/WinUI 3",
      why: "Electron: web skills → desktop app (VS Code, Slack use it). .NET WPF/WinUI: native Windows performance, deep OS integration. Choose .NET if you need hardware access or Windows-specific features.",
    };
    if (req.appType === "desktop" && req.platform === "mac-only") return {
      tech: "Swift + SwiftUI (native macOS) or Electron",
      why: "SwiftUI for native Mac feel and App Store distribution. Electron if you want to reuse web skills. Tauri is a lighter alternative to Electron.",
    };
    if (req.appType === "desktop" && req.platform === "linux-only") return {
      tech: "Electron or GTK (Python/C) or Tauri (Rust + Web)",
      why: "Electron works everywhere including Linux. GTK for native Linux look. Tauri is lighter (Rust backend, web frontend).",
    };
    if (isDesktop && (isCrossPlatformDesktop || req.platform === "any")) return {
      tech: "Electron (TypeScript + React) or Tauri (Rust + React)",
      why: "Electron: proven, VS Code/Slack/Discord use it. 200MB+ app size. Tauri: newer, Rust backend, 10MB app size, better performance. Both run on Windows + Mac + Linux.",
    };
    if (req.appType === "desktop-web") return {
      tech: "Next.js 16 (Web) + Electron or Tauri (Desktop)",
      why: "Share 90%+ code between web and desktop versions. Next.js for the web app, wrap with Electron/Tauri for desktop distribution.",
    };

    // API only
    if (req.appType === "api-only") return { tech: "No frontend (API only)", why: "Headless API — consumers build their own UI" };

    // Mobile — platform-specific
    if (isMobile && req.platform === "ios-only") return {
      tech: "Swift + SwiftUI (native iOS)",
      why: "Native iOS gives best performance, full hardware access, and App Store optimization. SwiftUI is Apple's modern declarative UI framework.",
    };
    if (isMobile && req.platform === "android-only") return {
      tech: "Kotlin + Jetpack Compose (native Android)",
      why: "Kotlin is Google's preferred Android language. Jetpack Compose is the modern declarative UI toolkit. Best performance and Play Store integration.",
    };

    // Mobile + Web
    if (isMobile && isWeb) return {
      tech: "Next.js 16 (Web) + React Native (iOS + Android)",
      why: "Next.js for SEO + SSR on web. React Native shares JS/TS skills for iOS/Android. Code sharing via shared libs. One team, three platforms.",
    };

    // Mobile cross-platform
    if (isMobile) return {
      tech: req.offlineNeeded
        ? "React Native + SQLite + WatermelonDB (offline-first)"
        : (req.platform === "ios-android" ? "React Native or Flutter" : "React Native"),
      why: req.platform === "ios-android"
        ? "React Native: JS ecosystem, hot reload, huge community. Flutter: better UI consistency, Dart language, Google-backed. Both produce native apps from one codebase."
        : "Cross-platform mobile with one codebase. React ecosystem gives access to 1M+ packages.",
    };

    // Web
    if (req.pwaNeeded || req.offlineNeeded) return {
      tech: "Next.js 16 (PWA) + Service Worker + IndexedDB",
      why: "PWA gives app-like experience without app store. Offline via Service Worker. IndexedDB for local data sync. Installable on phones and desktops.",
    };
    return {
      tech: "Next.js 16 (App Router, TypeScript, Tailwind CSS)",
      why: "Server-side rendering for SEO, TypeScript for reliability, Tailwind for rapid UI development. Industry standard for modern web apps.",
    };
  })();

  // ── BACKEND ──
  const backend = (() => {
    if (scale === "enterprise") return {
      tech: "Go (high-perf services) + Node.js (API layer) + gRPC (inter-service)",
      why: "Go for compute-heavy services (10x throughput vs Node). Node.js for API gateway. gRPC for fast inter-service communication.",
    };
    if (scale === "large") return {
      tech: "Node.js (Express/Fastify) + Redis + Message Queue",
      why: "Node.js handles I/O-bound workloads efficiently. Fastify is 2x faster than Express. Redis for caching, queue for async tasks.",
    };
    if (isFinancial) return {
      tech: "Node.js (Fastify) + TypeScript + strict validation (Zod)",
      why: "TypeScript catches bugs at compile time — critical for financial systems. Zod validates every input. Fastify for speed.",
    };
    return {
      tech: "Next.js API Routes (Node.js, TypeScript)",
      why: "API routes built into Next.js — no separate backend needed. TypeScript for type safety. Simplest architecture.",
    };
  })();

  // ── DATABASE ──
  const database = (() => {
    const cache = scale === "tiny" ? "In-memory (Node.js)" : "Redis 7";
    const search = req.searchHeavy ? "Elasticsearch 8" : undefined;

    if (isFinancial || isGovernment) return {
      primary: "PostgreSQL 16 (ACID, row-level security)",
      cache, search,
      why: "PostgreSQL is ACID-compliant — every transaction is atomic. Row-level security for multi-tenant data isolation. Free, enterprise-grade.",
    };
    if (scale === "enterprise") return {
      primary: "PostgreSQL 16 (Primary + Read Replicas + PgBouncer)",
      cache: "Redis Cluster (3+ nodes)", search: search || "Elasticsearch 8",
      why: "Replicas handle read load. PgBouncer pools connections (50 real connections serve 1000 app connections). Redis Cluster for HA caching.",
    };
    if (req.multiTenant) return {
      primary: "PostgreSQL 16 (schema-per-tenant or RLS)",
      cache, search,
      why: "Schema-per-tenant gives true isolation. Row-Level Security (RLS) is lighter. Both are PostgreSQL native — no extra cost.",
    };
    return {
      primary: "PostgreSQL 16",
      cache, search,
      why: "Powers Instagram, Spotify, NASA. Free, reliable, scales to millions of rows. The only database most apps ever need.",
    };
  })();

  // ── MESSAGING ──
  const messaging = (() => {
    if (scale === "enterprise") return { tech: "Apache Kafka (event streaming)", why: "Kafka handles trillions of events/day. Perfect for event sourcing, audit trails, and real-time analytics." };
    if (scale === "large" || needsRealTime) return { tech: "Redis Streams or RabbitMQ", why: "Redis Streams for lightweight queuing. RabbitMQ for complex routing. Both handle 10K+ messages/second." };
    if (isFinancial) return { tech: "RabbitMQ (durable queues)", why: "RabbitMQ guarantees message delivery — critical for financial transactions. Dead letter queues catch failures." };
    if (req.transactionsPerDay === "10K-100K" || req.transactionsPerDay === "100K+") return { tech: "Redis Streams", why: "Lightweight, built into Redis. Handles async jobs, email sending, report generation without a separate service." };
    return undefined;
  })();

  // ── HOSTING ──
  const hosting = (() => {
    const specs = getServerSpecs(req, scale);
    if (scale === "enterprise") return { type: "AWS / GCP (Multi-region, Kubernetes)", specs, why: "Multi-region for disaster recovery. Kubernetes for auto-scaling. Managed services reduce ops burden." };
    if (scale === "large") return { type: "AWS EC2 / Hetzner Dedicated + Docker Swarm", specs, why: "Dedicated servers for cost efficiency at scale. Docker Swarm for orchestration without K8s complexity." };
    if (scale === "medium") return { type: "Hetzner Cloud / DigitalOcean / AWS Lightsail", specs, why: "European VPS providers offer 3x more compute per dollar vs. AWS. Perfect for Indian businesses serving Indian users." };
    return { type: "Single VPS (Hetzner / DigitalOcean)", specs, why: "One server handles everything. PM2 + nginx. Simplest, cheapest, most reliable for this scale. This is what MMAM uses." };
  })();

  // ── LOAD BALANCER ──
  const loadBalancer = (() => {
    if (scale === "enterprise") return { tech: "AWS ALB (Application Load Balancer) + Cloudflare", why: "ALB handles L7 routing with auto-scaling. Cloudflare for DDoS protection and global CDN." };
    if (scale === "large") return { tech: "nginx (load balancing) + Cloudflare (CDN + DDoS)", why: "nginx round-robin across app servers. Cloudflare free tier provides CDN + DDoS protection." };
    if (scale === "medium") return { tech: "nginx (reverse proxy) + Cloudflare (free)", why: "nginx as reverse proxy with health checks. Cloudflare free tier for SSL + basic DDoS protection." };
    return { tech: "nginx (reverse proxy) + Let's Encrypt SSL", why: "nginx handles SSL termination, gzip, static files. Let's Encrypt for free auto-renewing certificates." };
  })();

  // ── SECURITY ──
  const security = (() => {
    const base = {
      ssl: "TLS 1.3 (Let's Encrypt or Cloudflare)",
      auth: req.paymentProcessing ? "OAuth 2.0 + 2FA (OTP via SMS/email)" :
        isGovernment ? "Certificate-based + MFA" :
          scale === "tiny" ? "PIN/Password + JWT" : "JWT + refresh tokens + rate limiting",
    };
    if (isGovernment || isFinancial) return {
      ...base,
      firewall: "UFW (host) + VPC (network) + IP whitelisting for admin",
      waf: "Cloudflare WAF Pro ($20/mo) or AWS WAF",
      why: "Multi-layer security: network firewall (UFW), application firewall (WAF), encryption (TLS 1.3), and strict authentication.",
    };
    if (scale === "large" || scale === "enterprise") return {
      ...base,
      firewall: "VPC + Security Groups + UFW",
      waf: "Cloudflare WAF or AWS WAF",
      why: "VPC isolates your network. Security Groups control traffic between services. WAF blocks common web attacks.",
    };
    return {
      ...base,
      firewall: "UFW (Ubuntu Firewall) — allow only 80, 443, 22",
      waf: "Cloudflare free (basic protection)",
      why: "UFW blocks all ports except web + SSH. Cloudflare proxies traffic for basic DDoS protection. Sufficient for this scale.",
    };
  })();

  // ── MONITORING ──
  const monitoring = (() => {
    if (scale === "enterprise") return { tech: "Prometheus + Grafana + Jaeger + Loki + PagerDuty", why: "Full observability: metrics (Prometheus), dashboards (Grafana), traces (Jaeger), logs (Loki), alerting (PagerDuty)." };
    if (scale === "large") return { tech: "Prometheus + Grafana + Sentry + UptimeRobot", why: "Prometheus for metrics, Grafana for dashboards, Sentry for error tracking, UptimeRobot for uptime alerts." };
    if (scale === "medium") return { tech: "PM2 Monitoring + Sentry (free) + UptimeRobot (free)", why: "PM2 shows process health. Sentry catches errors with stack traces. UptimeRobot pings every 5 minutes." };
    return { tech: "PM2 logs + UptimeRobot (free)", why: "PM2 shows CPU/RAM and auto-restarts crashes. UptimeRobot alerts you if the site goes down. Free and sufficient." };
  })();

  // ── CI/CD ──
  const cicd = (() => {
    if (scale === "enterprise") return { tech: "GitHub Actions + ArgoCD (GitOps) + Docker Registry", why: "GitHub Actions for CI, ArgoCD for GitOps deployment to Kubernetes. Every change is a PR, reviewed, and auto-deployed." };
    if (scale === "large") return { tech: "GitHub Actions + Docker + rsync deploy", why: "GitHub Actions runs tests on every push. Docker builds for consistency. rsync for fast deployment to servers." };
    return { tech: "rsync + SSH deploy (or GitHub Actions)", why: "Simple rsync command deploys in seconds. Add GitHub Actions later for automated testing. Don't over-engineer CI/CD early." };
  })();

  // ── CDN ──
  const cdn = (isWeb || req.pwaNeeded) ? {
    tech: scale === "enterprise" ? "AWS CloudFront (multi-region)" : "Cloudflare (free tier)",
    why: "CDN caches static assets (JS, CSS, images) at edge locations worldwide. Reduces server load by 80%+. Free with Cloudflare.",
  } : undefined;

  // ── COSTS ──
  const costs = calculateCosts(req, scale, hosting.specs);

  // ── TEAM ──
  const team = calculateTeam(req, scale);

  // ── TIMELINE ──
  const timeline = estimateTimeline(req, scale);

  // ── ARCHITECTURE DIAGRAM ──
  const architectureDiagram = generateDiagram(req, scale, hosting.specs);

  return {
    frontend, backend, database, messaging, hosting, loadBalancer,
    security, monitoring, cicd, cdn, costs, team, timeline, architectureDiagram,
  };
}

function getScaleTier(req: Requirements): "tiny" | "small" | "medium" | "large" | "enterprise" {
  const c = req.concurrentUsers;
  if (c === "50K+" || req.totalUsers === "1M+") return "enterprise";
  if (c === "5K-50K" || req.totalUsers === "100K-1M") return "large";
  if (c === "1K-5K" || c === "200-1K" || req.totalUsers === "10K-100K") return "medium";
  if (c === "50-200" || c === "10-50" || req.totalUsers === "1K-10K") return "small";
  return "tiny";
}

function getServerSpecs(req: Requirements, scale: string): ServerSpec[] {
  if (scale === "enterprise") return [
    { role: "Load Balancer", count: 2, cpu: "4 cores", ram: "8 GB", storage: "50 GB SSD", os: "Ubuntu 24 LTS" },
    { role: "API Gateway", count: 2, cpu: "4 cores", ram: "8 GB", storage: "50 GB SSD", os: "Ubuntu 24 LTS" },
    { role: "App Server", count: 6, cpu: "8 cores", ram: "32 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "DB Primary", count: 1, cpu: "16 cores", ram: "64 GB", storage: "1 TB NVMe", os: "Ubuntu 24 LTS" },
    { role: "DB Replica", count: 2, cpu: "16 cores", ram: "64 GB", storage: "1 TB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Redis Cluster", count: 3, cpu: "4 cores", ram: "32 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Kafka / Queue", count: 3, cpu: "8 cores", ram: "16 GB", storage: "500 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Monitoring", count: 1, cpu: "4 cores", ram: "16 GB", storage: "500 GB SSD", os: "Ubuntu 24 LTS" },
  ];
  if (scale === "large") return [
    { role: "Load Balancer + nginx", count: 1, cpu: "4 cores", ram: "8 GB", storage: "50 GB SSD", os: "Ubuntu 24 LTS" },
    { role: "App Server", count: 3, cpu: "8 cores", ram: "16 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "DB Primary", count: 1, cpu: "8 cores", ram: "32 GB", storage: "500 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "DB Replica", count: 1, cpu: "8 cores", ram: "32 GB", storage: "500 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Redis + Queue", count: 1, cpu: "4 cores", ram: "16 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Monitoring", count: 1, cpu: "2 cores", ram: "8 GB", storage: "200 GB SSD", os: "Ubuntu 24 LTS" },
  ];
  if (scale === "medium") return [
    { role: "App Server + nginx", count: 2, cpu: "4 cores", ram: "16 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "DB Server (PostgreSQL)", count: 1, cpu: "4 cores", ram: "16 GB", storage: "200 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Cache (Redis)", count: 1, cpu: "2 cores", ram: "8 GB", storage: "50 GB SSD", os: "Ubuntu 24 LTS" },
  ];
  if (scale === "small") return [
    { role: "App + DB Server", count: 1, cpu: "4 cores", ram: "8 GB", storage: "100 GB NVMe", os: "Ubuntu 24 LTS" },
    { role: "Backup Server (optional)", count: 1, cpu: "2 cores", ram: "4 GB", storage: "100 GB SSD", os: "Ubuntu 24 LTS" },
  ];
  return [
    { role: "All-in-one Server", count: 1, cpu: "2 cores", ram: "4 GB", storage: "50 GB SSD", os: "Ubuntu 24 LTS" },
  ];
}

function calculateCosts(req: Requirements, scale: string, servers: ServerSpec[]): Recommendation["costs"] {
  const serverCosts: Record<string, number> = {
    "2 cores/4 GB": 500, "4 cores/8 GB": 1500, "4 cores/16 GB": 3000,
    "8 cores/16 GB": 5000, "8 cores/32 GB": 8000, "16 cores/64 GB": 18000,
    "2 cores/8 GB": 1000,
  };
  const breakdown: { item: string; cost: string }[] = [];
  let total = 0;

  servers.forEach((s) => {
    const key = `${s.cpu}/${s.ram}`;
    const perServer = serverCosts[key] || 3000;
    const cost = perServer * s.count;
    total += cost;
    breakdown.push({ item: `${s.role} (×${s.count})`, cost: `Rs ${cost.toLocaleString()}/mo` });
  });

  // Add service costs
  if (scale !== "tiny") { breakdown.push({ item: "Domain + SSL", cost: "Rs 500/mo" }); total += 500; }
  if (req.paymentProcessing) { breakdown.push({ item: "Payment Gateway (2% per txn)", cost: "Variable" }); }
  breakdown.push({ item: "Backups (automated)", cost: `Rs ${scale === "tiny" ? 200 : 1000}/mo` }); total += scale === "tiny" ? 200 : 1000;
  if (req.aiFeatures) { breakdown.push({ item: "AI API costs (Gemini/Claude)", cost: "Rs 1,000-10,000/mo" }); total += 3000; }

  return { monthly: `Rs ${total.toLocaleString()}`, yearly: `Rs ${(total * 12).toLocaleString()}`, breakdown };
}

function calculateTeam(req: Requirements, scale: string): Recommendation["team"] {
  if (scale === "enterprise") return {
    roles: [
      { role: "Tech Lead / Architect", count: "1", salary: "Rs 25-50L/yr" },
      { role: "Backend Developer", count: "4-6", salary: "Rs 10-25L/yr each" },
      { role: "Frontend Developer", count: "2-3", salary: "Rs 8-20L/yr each" },
      { role: "DevOps / SRE", count: "2-3", salary: "Rs 15-35L/yr each" },
      { role: "QA Engineer", count: "2", salary: "Rs 6-15L/yr each" },
      { role: "DBA", count: "1", salary: "Rs 12-30L/yr" },
      { role: "Project Manager", count: "1", salary: "Rs 15-30L/yr" },
    ],
    total: "13-17 people",
  };
  if (scale === "large") return {
    roles: [
      { role: "Tech Lead", count: "1", salary: "Rs 20-40L/yr" },
      { role: "Full-stack Developer", count: "3-5", salary: "Rs 8-20L/yr each" },
      { role: "DevOps (part-time)", count: "1", salary: "Rs 12-25L/yr" },
      { role: "QA", count: "1", salary: "Rs 6-12L/yr" },
    ],
    total: "6-8 people",
  };
  if (scale === "medium") return {
    roles: [
      { role: "Senior Developer (lead)", count: "1", salary: "Rs 15-30L/yr" },
      { role: "Full-stack Developer", count: "2-3", salary: "Rs 8-18L/yr each" },
      { role: "QA (part-time)", count: "1", salary: "Rs 5-10L/yr" },
    ],
    total: "4-5 people",
  };
  if (scale === "small") return {
    roles: [
      { role: "Full-stack Developer", count: "1-2", salary: "Rs 8-18L/yr each" },
      { role: "Designer (part-time/freelance)", count: "1", salary: "Rs 30K-1L/project" },
    ],
    total: "2-3 people",
  };
  return {
    roles: [
      { role: "Solo Developer (you!)", count: "1", salary: "Your time" },
    ],
    total: "1 person (you)",
  };
}

function estimateTimeline(req: Requirements, scale: string): string {
  if (scale === "enterprise") return "9-18 months (Phase 1 MVP in 3-4 months)";
  if (scale === "large") return "4-8 months (MVP in 2-3 months)";
  if (scale === "medium") return "3-5 months (MVP in 6-8 weeks)";
  if (scale === "small") return "4-8 weeks (MVP in 2-3 weeks)";
  return "2-4 weeks";
}

function generateDiagram(req: Requirements, scale: string, servers: ServerSpec[]): string {
  const isFinancial = req.dataType === "financial" || req.paymentProcessing;
  const hasQueue = scale === "large" || scale === "enterprise" || isFinancial;
  const hasReplica = scale === "medium" || scale === "large" || scale === "enterprise";
  const hasCache = scale !== "tiny";
  const hasCDN = req.appType !== "api-only";

  if (scale === "tiny" || scale === "small") {
    return `
  Users (Browser/Mobile)
       │
       │ HTTPS
       ▼
  ${hasCDN ? `┌──────────────────┐
  │  Cloudflare CDN  │  ← SSL + caching + DDoS protection
  └────────┬─────────┘
           │
           ▼` : ''}
  ┌──────────────────────┐
  │   nginx              │  ← Reverse proxy, gzip, static files
  │   (Port 80/443)      │
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │   ${req.appType === "api-only" ? "Node.js (Fastify)" : "Next.js (PM2)"}     │  ← Application
  │   PM2 Cluster Mode   │     ${servers[0]?.cpu || "2 cores"}, ${servers[0]?.ram || "4 GB RAM"}
  └────────┬─────────────┘
           │
           ▼
  ┌──────────────────────┐
  │   PostgreSQL 16      │  ← Database
  │   (on same server)   │
  └──────────────────────┘

  TOTAL: 1 server | Cost: ${scale === "tiny" ? "~Rs 500-1,500/mo" : "~Rs 2,000-5,000/mo"}`;
  }

  if (scale === "medium") {
    return `
  Users (Browser/Mobile)
       │
       │ HTTPS
       ▼
  ┌──────────────────┐
  │  Cloudflare CDN  │  ← SSL + CDN + DDoS
  └────────┬─────────┘
           │
           ▼
  ┌────────────────────────────┐
  │  App Server 1 (nginx+PM2) │──┐
  │  4 cores, 16 GB RAM       │  │
  └────────────────────────────┘  │
  ┌────────────────────────────┐  │
  │  App Server 2 (nginx+PM2) │──┤
  │  4 cores, 16 GB RAM       │  │
  └────────────────────────────┘  │
                                  │
                      ┌───────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
  ┌───────────┐ ┌───────────┐ ┌──────────┐
  │PostgreSQL │ │  Redis    │ │ File     │
  │16 Primary │ │  Cache    │ │ Storage  │
  │4c, 16GB   │ │  2c, 8GB  │ │ (S3/     │
  └───────────┘ └───────────┘ │  local)  │
                              └──────────┘

  TOTAL: 4 servers | Cost: ~Rs 10,000-20,000/mo`;
  }

  return `
  Users (Browser/Mobile/API)
       │
       │ HTTPS
       ▼
  ┌──────────────────┐
  │  Cloudflare CDN  │  ← Global CDN + WAF + DDoS
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────────┐
  │  Load Balancer       │  ← nginx / HAProxy
  │  (Health checks,     │     Distributes to app servers
  │   SSL termination)   │
  └────────┬─────────────┘
           │
     ┌─────┼─────┬─────────┐
     │     │     │         │
     ▼     ▼     ▼         ▼
  ┌─────┐┌─────┐┌─────┐ ┌─────┐
  │App 1││App 2││App 3│ │App N│  ← ${scale === "enterprise" ? "6+" : "3"} app servers
  │     ││     ││     │ │     │     PM2 cluster mode
  └──┬──┘└──┬──┘└──┬──┘ └──┬──┘
     └──────┼──────┼───────┘
            │      │
    ┌───────┘      └───────┐
    │                      │
    ▼                      ▼
  ┌──────────────┐   ┌──────────────┐
  │ PostgreSQL   │   │ Redis        │
  │ Primary      │   │ ${scale === "enterprise" ? "Cluster (3)" : "Cache"}      │
  │ (Writes)     │   │              │
  └──────┬───────┘   └──────────────┘
         │
  ${hasReplica ? `┌──────┴───────┐
  │ PostgreSQL   │
  │ Replica(s)   │   ← Read queries + failover
  │ (Reads)      │
  └──────────────┘` : ''}
  ${hasQueue ? `
         │
  ┌──────▼───────┐
  │ Message Queue│   ← ${scale === "enterprise" ? "Kafka" : "RabbitMQ/Redis Streams"}
  │ (Async jobs) │      Email, reports, heavy processing
  └──────────────┘` : ''}

  ┌──────────────┐
  │ Monitoring   │   ← Prometheus + Grafana + Sentry
  │ Server       │
  └──────────────┘

  TOTAL: ${servers.reduce((sum, s) => sum + s.count, 0)} servers | ${scale === "enterprise" ? "Multi-region recommended" : "Single region"}`;
}

// ─── WIZARD UI ─────────────────────────────────────────────
const STEPS = [
  { title: "Application Type", subtitle: "What are you building?" },
  { title: "Scale & Traffic", subtitle: "How many users, transactions, and data?" },
  { title: "Features & Capabilities", subtitle: "What does it need to do?" },
  { title: "Data & Compliance", subtitle: "Sensitivity, industry, and uptime" },
  { title: "Infrastructure", subtitle: "Deployment, geography, and hosting" },
  { title: "Budget & Team", subtitle: "Constraints, migration, and maintenance" },
];

function RadioGroup({ label, options, value, onChange }: {
  label: string; options: { value: string; label: string; desc?: string }[];
  value: string; onChange: (v: string) => void;
}) {
  return (
    <div className="mb-6">
      <p className="mb-3 text-sm font-semibold">{label}</p>
      <div className="grid gap-2 sm:grid-cols-2">
        {options.map((opt) => (
          <button
            key={opt.value}
            onClick={() => onChange(opt.value)}
            className={`rounded-xl border p-4 text-left transition-all ${
              value === opt.value
                ? "border-accent bg-accent/10"
                : "border-border bg-surface hover:border-accent/30"
            }`}
          >
            <p className="text-sm font-medium">{opt.label}</p>
            {opt.desc && <p className="mt-1 text-xs text-muted">{opt.desc}</p>}
          </button>
        ))}
      </div>
    </div>
  );
}

function Toggle({ label, desc, checked, onChange }: {
  label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void;
}) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`flex w-full items-center gap-3 rounded-xl border p-4 text-left transition-all ${
        checked ? "border-accent bg-accent/10" : "border-border bg-surface hover:border-accent/30"
      }`}
    >
      <div className={`flex size-6 shrink-0 items-center justify-center rounded-md border-2 transition-colors ${
        checked ? "border-accent bg-accent" : "border-border"
      }`}>
        {checked && (
          <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" className="size-4">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
        )}
      </div>
      <div>
        <p className="text-sm font-medium">{label}</p>
        {desc && <p className="mt-0.5 text-xs text-muted">{desc}</p>}
      </div>
    </button>
  );
}

// ─── MAIN COMPONENT ────────────────────────────────────────
export default function TechAdvisorPage() {
  const [step, setStep] = useState(0);
  const [req, setReq] = useState<Requirements>(INITIAL);
  const [showResult, setShowResult] = useState(false);

  // ── SAVED REPORTS STATE ──
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  const [savedReportsOpen, setSavedReportsOpen] = useState(false);
  const [loadingReports, setLoadingReports] = useState(false);
  const [loadedRecommendation, setLoadedRecommendation] = useState<Recommendation | null>(null);
  const [loadedProjectPlan, setLoadedProjectPlan] = useState<ProjectPlan | null>(null);

  const fetchSavedReports = useCallback(async () => {
    try {
      const res = await fetch("/api/tech-reports");
      if (res.ok) {
        const data = await res.json();
        setSavedReports(data);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchSavedReports(); }, [fetchSavedReports]);

  const handleLoadReport = async (id: number) => {
    setLoadingReports(true);
    try {
      const res = await fetch(`/api/tech-reports?id=${id}`);
      if (res.ok) {
        const report = await res.json();
        if (report.recommendation && report.project_plan) {
          setLoadedRecommendation(report.recommendation);
          setLoadedProjectPlan(report.project_plan);
          if (report.requirements) setReq(report.requirements);
          setShowResult(true);
          setSavedReportsOpen(false);
        }
      }
    } catch { /* ignore */ }
    setLoadingReports(false);
  };

  const handleDeleteReport = async (id: number) => {
    if (!confirm("Delete this saved report?")) return;
    try {
      await fetch(`/api/tech-reports?id=${id}`, { method: "DELETE" });
      setSavedReports((prev) => prev.filter((r) => r.id !== id));
    } catch { /* ignore */ }
  };

  const update = <K extends keyof Requirements>(key: K, value: Requirements[K]) => {
    setReq((prev) => ({ ...prev, [key]: value }));
  };

  const canProceed = (): boolean => {
    if (step === 0) {
      if (!req.appType) return false;
      if ((req.appType === "desktop" || req.appType === "desktop-web" || req.appType === "mobile" || req.appType === "both") && !req.platform) return false;
      return true;
    }
    if (step === 1) return !!req.totalUsers && !!req.concurrentUsers;
    if (step === 3) return !!req.dataType;
    if (step === 4) return !!req.deployment;
    if (step === 5) return !!req.budget && !!req.timeline && !!req.teamSize;
    return true;
  };

  const handleNext = () => {
    if (step < STEPS.length - 1) setStep(step + 1);
    else setShowResult(true);
  };

  const recommendation = loadedRecommendation || (showResult ? generateRecommendation(req) : null);
  const projectPlan: ProjectPlan | null = loadedProjectPlan || ((showResult && recommendation) ? generateProjectPlan({
    scale: getScaleTier(req),
    appType: req.appType,
    platform: req.platform,
    isFinancial: req.dataType === "financial" || req.paymentProcessing,
    isGovernment: req.dataType === "government",
    hasRealTime: req.realTimeNeeded,
    hasPayments: req.paymentProcessing,
    hasSearch: req.searchHeavy,
    hasAI: req.aiFeatures,
    hasFileUploads: req.fileUploads,
    hasMultiTenant: req.multiTenant,
    teamSize: req.teamSize,
    timeline: req.timeline,
    budget: req.budget,
    frontendTech: recommendation.frontend.tech,
    backendTech: recommendation.backend.tech,
    dbTech: recommendation.database.primary,
    cacheTech: recommendation.database.cache,
    queueTech: recommendation.messaging?.tech,
    deployment: req.deployment,
    geoReach: req.geoReach,
    industry: req.industry,
    uptimeRequirement: req.uptimeRequirement,
    dataVolume: req.dataVolume,
    contentType: req.contentType,
    notificationChannels: req.notificationChannels,
    publicAPI: req.publicAPI,
    userRoles: req.userRoles,
    replacingExisting: req.replacingExisting,
    trainingNeeded: req.trainingNeeded,
    maintenanceContract: req.maintenanceContract,
    dataType: req.dataType,
    clientName: req.clientName,
    projectName: req.projectName,
  }) : null);

  // ── ACTIONS ──
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [whatsappCopied, setWhatsappCopied] = useState(false);

  const handleDownloadReport = async () => {
    if (!recommendation || !projectPlan) return;
    setDownloading(true);
    try {
      const { generateWordReport } = await import("./report-generator");
      const blob = await generateWordReport({ recommendation, projectPlan, requirements: req as unknown as Record<string, unknown>, clientName: req.clientName, projectName: req.projectName });
      const { saveAs } = await import("file-saver");
      const date = new Date().toISOString().split("T")[0];
      saveAs(blob, `Tech-Stack-Report-${date}.docx`);
    } catch (e) { console.error("Report generation failed:", e); }
    setDownloading(false);
  };

  const handleSaveReport = async () => {
    if (!recommendation || !projectPlan) return;
    setSaving(true);
    try {
      const title = req.clientName
        ? `${req.clientName}${req.projectName ? ` — ${req.projectName}` : ""} — ${new Date().toLocaleDateString("en-IN")}`
        : `${req.appType} App — ${req.totalUsers} users — ${new Date().toLocaleDateString("en-IN")}`;
      await fetch("/api/tech-reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          requirements: req,
          recommendation,
          project_plan: projectPlan,
          whatsapp_summary: projectPlan.whatsappSummary.text,
        }),
      });
      setSaved(true);
      fetchSavedReports();
    } catch { /* ignore */ }
    setSaving(false);
  };

  const handleCopyWhatsApp = () => {
    if (!projectPlan) return;
    navigator.clipboard.writeText(projectPlan.whatsappSummary.text);
    setWhatsappCopied(true);
    setTimeout(() => setWhatsappCopied(false), 2000);
  };

  // ── RESULT VIEW ──
  if (showResult && recommendation) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Your Tech Stack Recommendation</h1>
            <p className="mt-1 text-sm text-muted">Complete A-Z technology setup based on your requirements</p>
          </div>
          <button onClick={() => { setShowResult(false); setStep(0); setReq(INITIAL); setSaved(false); setLoadedRecommendation(null); setLoadedProjectPlan(null); }}
            className="rounded-lg border border-border px-3 py-1.5 text-xs font-medium text-muted hover:bg-surface-hover">
            Start Over
          </button>
        </div>

        {/* Action buttons */}
        <div className="mb-8 flex flex-wrap gap-2">
          <button onClick={handleDownloadReport} disabled={downloading}
            className="flex items-center gap-2 rounded-xl bg-accent px-4 py-2.5 text-sm font-bold text-white transition-all hover:bg-accent-hover disabled:opacity-50">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="size-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
            </svg>
            {downloading ? "Generating..." : "Download Word Report"}
          </button>
          <button onClick={handleSaveReport} disabled={saving || saved}
            className={`flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-bold transition-all ${saved ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-500" : "border-accent/30 text-accent hover:bg-accent/10"}`}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="size-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0 1 11.186 0Z" />
            </svg>
            {saved ? "Saved!" : saving ? "Saving..." : "Save for Later"}
          </button>
          <button onClick={handleCopyWhatsApp}
            className={`flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-bold transition-all ${whatsappCopied ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-500" : "border-emerald-500/30 text-emerald-500 hover:bg-emerald-500/10"}`}>
            <svg viewBox="0 0 24 24" fill="currentColor" className="size-4">
              <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z" />
              <path d="M12 0C5.373 0 0 5.373 0 12c0 2.11.546 4.093 1.504 5.818L0 24l6.335-1.652A11.943 11.943 0 0 0 12 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 22c-1.82 0-3.543-.473-5.042-1.303l-.361-.214-3.742.977.998-3.648-.235-.374A9.935 9.935 0 0 1 2 12C2 6.477 6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z" />
            </svg>
            {whatsappCopied ? "Copied!" : "Copy WhatsApp Summary"}
          </button>
        </div>

        {/* Architecture Diagram */}
        <div className="mb-8 overflow-x-auto rounded-xl border border-accent/20 bg-[#1a1a2e] p-4 sm:p-6">
          <p className="mb-3 text-xs font-bold uppercase tracking-wider text-accent">Recommended Architecture</p>
          <pre className="whitespace-pre text-xs leading-relaxed text-emerald-400 sm:text-sm">{recommendation.architectureDiagram}</pre>
        </div>

        {/* Stack Cards */}
        <div className="mb-8 grid gap-4 sm:grid-cols-2">
          {[
            { title: "Frontend", icon: "🖥️", tech: recommendation.frontend.tech, why: recommendation.frontend.why },
            { title: "Backend / Middleware", icon: "⚙️", tech: recommendation.backend.tech, why: recommendation.backend.why },
            { title: "Database", icon: "🗄️", tech: `${recommendation.database.primary}${recommendation.database.search ? ` + ${recommendation.database.search}` : ""}`, why: recommendation.database.why },
            { title: "Cache", icon: "⚡", tech: recommendation.database.cache, why: "Caching hot data reduces database load by 90%+" },
            ...(recommendation.messaging ? [{ title: "Message Queue", icon: "📨", tech: recommendation.messaging.tech, why: recommendation.messaging.why }] : []),
            ...(recommendation.cdn ? [{ title: "CDN", icon: "🌐", tech: recommendation.cdn.tech, why: recommendation.cdn.why }] : []),
            { title: "Load Balancer", icon: "⚖️", tech: recommendation.loadBalancer.tech, why: recommendation.loadBalancer.why },
            { title: "CI/CD Pipeline", icon: "🔄", tech: recommendation.cicd.tech, why: recommendation.cicd.why },
            { title: "Monitoring", icon: "📊", tech: recommendation.monitoring.tech, why: recommendation.monitoring.why },
          ].map((card) => (
            <div key={card.title} className="rounded-xl border border-border bg-surface p-5">
              <div className="mb-2 flex items-center gap-2">
                <span className="text-lg">{card.icon}</span>
                <h3 className="font-bold">{card.title}</h3>
              </div>
              <p className="mb-2 text-sm font-medium text-accent">{card.tech}</p>
              <p className="text-xs text-muted">{card.why}</p>
            </div>
          ))}
        </div>

        {/* Security */}
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <h3 className="mb-3 flex items-center gap-2 font-bold"><span>🔐</span> Security Stack</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <div><p className="text-xs font-semibold text-muted">Firewall</p><p className="text-sm">{recommendation.security.firewall}</p></div>
            <div><p className="text-xs font-semibold text-muted">WAF</p><p className="text-sm">{recommendation.security.waf}</p></div>
            <div><p className="text-xs font-semibold text-muted">SSL/TLS</p><p className="text-sm">{recommendation.security.ssl}</p></div>
            <div><p className="text-xs font-semibold text-muted">Authentication</p><p className="text-sm">{recommendation.security.auth}</p></div>
          </div>
          <p className="mt-3 text-xs text-muted">{recommendation.security.why}</p>
        </div>

        {/* Server Specs */}
        <div className="mb-8">
          <h3 className="mb-3 font-bold">🖥️ Server Specifications</h3>
          <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-surface-hover">
                  {["Role", "Count", "CPU", "RAM", "Storage", "OS"].map((h) => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recommendation.hosting.specs.map((s, i) => (
                  <tr key={i} className="border-b border-border/50 last:border-0">
                    <td className="px-4 py-3 font-medium">{s.role}</td>
                    <td className="px-4 py-3 text-muted">{s.count}</td>
                    <td className="px-4 py-3 text-muted">{s.cpu}</td>
                    <td className="px-4 py-3 text-muted">{s.ram}</td>
                    <td className="px-4 py-3 text-muted">{s.storage}</td>
                    <td className="px-4 py-3 text-muted">{s.os}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-muted">Hosting: {recommendation.hosting.type} — {recommendation.hosting.why}</p>
        </div>

        {/* Costs */}
        <div className="mb-8 grid gap-4 sm:grid-cols-2">
          <div className="rounded-xl border border-border bg-surface p-5">
            <h3 className="mb-3 font-bold">💰 Cost Estimate</h3>
            <div className="mb-4 flex gap-4">
              <div>
                <p className="text-xs font-medium text-muted">Monthly</p>
                <p className="font-mono text-xl font-bold text-accent">{recommendation.costs.monthly}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-muted">Yearly</p>
                <p className="font-mono text-xl font-bold text-accent">{recommendation.costs.yearly}</p>
              </div>
            </div>
            <div className="space-y-2">
              {recommendation.costs.breakdown.map((b, i) => (
                <div key={i} className="flex justify-between text-xs">
                  <span className="text-muted">{b.item}</span>
                  <span className="font-medium">{b.cost}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-border bg-surface p-5">
            <h3 className="mb-3 font-bold">👥 Team Requirements</h3>
            <p className="mb-3 font-mono text-xl font-bold text-accent">{recommendation.team.total}</p>
            <div className="space-y-2">
              {recommendation.team.roles.map((r, i) => (
                <div key={i} className="flex justify-between text-xs">
                  <span>{r.role} (×{r.count})</span>
                  <span className="text-muted">{r.salary}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div className="mb-8 rounded-xl border border-accent/20 bg-accent/5 p-5 text-center">
          <p className="text-xs font-semibold uppercase tracking-wider text-accent">Estimated Timeline</p>
          <p className="mt-1 text-xl font-bold">{recommendation.timeline}</p>
        </div>

        {/* ══════════ PROJECT PLAN SECTIONS ══════════ */}
        {projectPlan && (
          <>
            <div className="mb-8 border-t border-border pt-8">
              <h2 className="mb-1 text-2xl font-bold">Project Plan</h2>
              <p className="text-sm text-muted">Detailed licensing, hardware, phases, resources, and risk assessment</p>
            </div>

            {/* LICENSING */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📜 Technology Licensing & Costs</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-surface-hover">
                      {["Technology", "License", "Cost", "Notes"].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {projectPlan.licenses.map((lic, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-4 py-3 font-medium">{lic.technology}</td>
                        <td className="px-4 py-3 text-muted">{lic.license}</td>
                        <td className={`px-4 py-3 font-medium ${lic.cost === "FREE" ? "text-emerald-500" : "text-amber-500"}`}>{lic.cost}</td>
                        <td className="px-4 py-3 text-xs text-muted">{lic.notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* HARDWARE DETAIL */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🖥️ Detailed Hardware Specifications</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-surface-hover">
                      {["Role", "Qty", "CPU", "RAM", "Disk", "Swap/Page", "Network", "OS", "Cost/mo"].map((h) => (
                        <th key={h} className="px-3 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {projectPlan.hardware.map((hw, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-3 py-3 font-medium">{hw.role}</td>
                        <td className="px-3 py-3 text-muted">{hw.count}</td>
                        <td className="px-3 py-3 text-muted">{hw.cpu}</td>
                        <td className="px-3 py-3 text-muted">{hw.ram}</td>
                        <td className="px-3 py-3 text-muted">{hw.disk}</td>
                        <td className="px-3 py-3 text-muted">{hw.swap}</td>
                        <td className="px-3 py-3 text-muted">{hw.network}</td>
                        <td className="px-3 py-3 text-muted">{hw.os}</td>
                        <td className="px-3 py-3 font-medium text-accent">{hw.monthlyCost}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* PROJECT PHASES */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📋 Development Phases & Timeline</h3>
              <div className="space-y-4">
                {projectPlan.phases.map((phase) => (
                  <div key={phase.phase} className="rounded-xl border border-border bg-surface p-5">
                    <div className="mb-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="flex size-8 items-center justify-center rounded-full bg-accent/15 font-mono text-sm font-bold text-accent">{phase.phase}</span>
                        <div>
                          <h4 className="font-bold">{phase.name}</h4>
                          <p className="text-xs text-muted">{phase.duration}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xs font-medium text-muted">Testing</p>
                        <p className="text-xs text-accent">{phase.testingTime}</p>
                      </div>
                    </div>

                    <div className="grid gap-4 sm:grid-cols-3">
                      <div>
                        <p className="mb-1 text-xs font-bold uppercase tracking-wider text-muted">Tasks</p>
                        <ul className="space-y-1">
                          {phase.tasks.map((t, i) => (
                            <li key={i} className="text-xs text-muted">• {t}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <p className="mb-1 text-xs font-bold uppercase tracking-wider text-muted">Deliverables</p>
                        <ul className="space-y-1">
                          {phase.deliverables.map((d, i) => (
                            <li key={i} className="text-xs text-emerald-500">✓ {d}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <p className="mb-1 text-xs font-bold uppercase tracking-wider text-muted">Resources</p>
                        <p className="text-xs">{phase.resources}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* MILESTONES */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🏁 Key Milestones</h3>
              <div className="relative ml-4 border-l-2 border-accent/30 pl-6">
                {projectPlan.milestones.map((m, i) => (
                  <div key={i} className="relative mb-4 last:mb-0">
                    <div className="absolute -left-[31px] flex size-4 items-center justify-center rounded-full border-2 border-accent bg-background" />
                    <p className="text-xs font-bold text-accent">{m.date}</p>
                    <p className="text-sm">{m.milestone}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* RESOURCES — Human + AI */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">👥 Resource Plan — Human + AI</h3>

              <div className="mb-4 rounded-xl border border-border bg-surface p-5">
                <h4 className="mb-3 text-sm font-bold">Human Resources</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border">
                        {["Role", "Count", "Monthly Rate", "Duration", "Total Cost"].map((h) => (
                          <th key={h} className="px-3 py-2 text-left text-xs font-bold uppercase text-muted">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {projectPlan.resources.humans.map((h, i) => (
                        <tr key={i} className="border-b border-border/30 last:border-0">
                          <td className="px-3 py-2 font-medium">{h.role}</td>
                          <td className="px-3 py-2 text-muted">{h.count}</td>
                          <td className="px-3 py-2 text-muted">{h.monthlyRate}</td>
                          <td className="px-3 py-2 text-muted">{h.duration}</td>
                          <td className="px-3 py-2 font-medium">{h.totalCost}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-3 text-right text-sm font-bold">Total Human Cost: <span className="text-accent">{projectPlan.resources.totalHumanCost}</span></p>
              </div>

              <div className="mb-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5">
                <h4 className="mb-3 text-sm font-bold text-emerald-500">Claude Code / AI Resources</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-emerald-500/20">
                        {["Task", "Est. Hours", "Cost/Hour", "Total"].map((h) => (
                          <th key={h} className="px-3 py-2 text-left text-xs font-bold uppercase text-emerald-500/70">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {projectPlan.resources.claudeCode.map((c, i) => (
                        <tr key={i} className="border-b border-emerald-500/10 last:border-0">
                          <td className="px-3 py-2 font-medium">{c.task}</td>
                          <td className="px-3 py-2 text-muted">{c.estimatedHours}</td>
                          <td className="px-3 py-2 text-muted">{c.costPerHour}</td>
                          <td className="px-3 py-2 font-medium text-emerald-500">{c.totalCost}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-3 text-right text-sm font-bold">Total AI Cost: <span className="text-emerald-500">{projectPlan.resources.totalAICost}</span></p>
                <p className="mt-1 text-right text-xs text-emerald-500">{projectPlan.resources.savingsWithAI}</p>
              </div>
            </div>

            {/* RISK ASSESSMENT */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">⚠️ Risk Assessment</h3>
              <div className="space-y-3">
                {projectPlan.risks.map((risk, i) => (
                  <div key={i} className="rounded-xl border border-border bg-surface p-4">
                    <div className="mb-2 flex items-start justify-between gap-3">
                      <p className="text-sm font-medium">{risk.risk}</p>
                      <div className="flex shrink-0 gap-2">
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          risk.probability === "High" ? "bg-red-500/15 text-red-500" :
                          risk.probability === "Medium" ? "bg-amber-500/15 text-amber-500" :
                          "bg-emerald-500/15 text-emerald-500"
                        }`}>{risk.probability}</span>
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          risk.impact === "High" ? "bg-red-500/15 text-red-500" :
                          risk.impact === "Medium" ? "bg-amber-500/15 text-amber-500" :
                          "bg-emerald-500/15 text-emerald-500"
                        }`}>{risk.impact} impact</span>
                      </div>
                    </div>
                    <p className="text-xs text-muted"><span className="font-semibold">Mitigation:</span> {risk.mitigation}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* TOTAL PROJECT COST */}
            <div className="mb-8 rounded-xl border-2 border-accent/30 bg-accent/5 p-6">
              <h3 className="mb-4 text-center font-bold">💰 Total Project Cost Summary (First 12 Months)</h3>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="text-center">
                  <p className="text-xs font-medium text-muted">Development</p>
                  <p className="mt-1 font-mono text-lg font-bold">{projectPlan.totalProjectCost.development}</p>
                </div>
                <div className="text-center">
                  <p className="text-xs font-medium text-muted">Infrastructure (12 mo)</p>
                  <p className="mt-1 font-mono text-lg font-bold">{projectPlan.totalProjectCost.infrastructure12mo}</p>
                </div>
                <div className="text-center">
                  <p className="text-xs font-medium text-muted">Licensing (12 mo)</p>
                  <p className="mt-1 font-mono text-lg font-bold">{projectPlan.totalProjectCost.licensing12mo}</p>
                </div>
                <div className="text-center rounded-lg bg-accent/10 p-3">
                  <p className="text-xs font-bold text-accent">GRAND TOTAL (12 mo)</p>
                  <p className="mt-1 font-mono text-xl font-bold text-accent">{projectPlan.totalProjectCost.grand12mo}</p>
                </div>
              </div>
            </div>

            {/* BACKUP & DISASTER RECOVERY */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">💾 Backup & Disaster Recovery</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                {[
                  { label: "Backup Frequency", value: projectPlan.backupDR.backupFrequency },
                  { label: "Retention Policy", value: projectPlan.backupDR.backupRetention },
                  { label: "Backup Storage", value: projectPlan.backupDR.backupStorage },
                  { label: "RTO (Recovery Time)", value: projectPlan.backupDR.rto },
                  { label: "RPO (Max Data Loss)", value: projectPlan.backupDR.rpo },
                  { label: "DR Strategy", value: projectPlan.backupDR.drStrategy },
                ].map((item, i) => (
                  <div key={i} className="rounded-xl border border-border bg-surface p-4">
                    <p className="text-xs font-bold uppercase tracking-wider text-accent">{item.label}</p>
                    <p className="mt-1 text-sm">{item.value}</p>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-right text-xs text-muted">Backup cost: {projectPlan.backupDR.backupCost}</p>
            </div>

            {/* ENVIRONMENTS */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🌐 Environment Strategy</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Environment", "Purpose", "Specs", "Cost"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.environments.environments.map((e, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{e.name}</td>
                      <td className="px-4 py-3 text-muted">{e.purpose}</td>
                      <td className="px-4 py-3 text-muted">{e.specs}</td>
                      <td className="px-4 py-3 text-accent">{e.cost}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* NOTIFICATION PROVIDERS */}
            {projectPlan.notifications.providers.length > 0 && (
              <div className="mb-8">
                <h3 className="mb-3 font-bold">🔔 Notification Providers</h3>
                <div className="overflow-x-auto rounded-xl border border-border">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b border-border bg-surface-hover">
                      {["Channel", "Provider", "Cost", "Notes"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                    </tr></thead>
                    <tbody>{projectPlan.notifications.providers.map((p, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-4 py-3 font-medium">{p.channel}</td>
                        <td className="px-4 py-3">{p.provider}</td>
                        <td className="px-4 py-3 text-muted">{p.cost}</td>
                        <td className="px-4 py-3 text-xs text-muted">{p.notes}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
            )}

            {/* PERFORMANCE TARGETS */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🎯 Performance Targets / SLA</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Metric", "Target", "How to Achieve"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.performanceTargets.targets.map((t, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{t.metric}</td>
                      <td className="px-4 py-3 font-mono text-sm text-accent">{t.target}</td>
                      <td className="px-4 py-3 text-xs text-muted">{t.how}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* SCALABILITY ROADMAP */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📈 Scalability Roadmap</h3>
              <div className="space-y-2">
                {projectPlan.scalabilityRoadmap.triggers.map((t, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-xl border border-border bg-surface p-4">
                    <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-accent/15 font-mono text-xs font-bold text-accent">{i + 1}</span>
                    <div className="flex-1">
                      <p className="text-sm font-medium">{t.when}</p>
                      <p className="mt-1 text-xs text-muted">→ {t.action}</p>
                    </div>
                    <span className="shrink-0 text-xs font-medium text-accent">{t.cost}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* TECH ALTERNATIVES */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🔄 Technology Alternatives</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Layer", "Primary Choice", "Alternative A", "Alternative B", "When to Switch"].map(h => <th key={h} className="px-3 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.techAlternatives.alternatives.map((a, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-3 py-3 font-medium">{a.layer}</td>
                      <td className="px-3 py-3 text-accent">{a.primary}</td>
                      <td className="px-3 py-3 text-muted">{a.alternativeA}</td>
                      <td className="px-3 py-3 text-muted">{a.alternativeB}</td>
                      <td className="px-3 py-3 text-xs text-muted">{a.when}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* YEAR PROJECTION */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📅 3-Year Cost Projection</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Year", "Infrastructure", "Maintenance", "Licensing", "Total"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.yearProjection.years.map((y, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{y.year}</td>
                      <td className="px-4 py-3 text-muted">{y.infrastructure}</td>
                      <td className="px-4 py-3 text-muted">{y.maintenance}</td>
                      <td className="px-4 py-3 text-muted">{y.licensing}</td>
                      <td className="px-4 py-3 font-bold text-accent">{y.total}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* COMPLIANCE CHECKLIST */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">✅ Compliance Checklist</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Requirement", "Status", "Action Needed"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.complianceChecklist.items.map((c, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{c.requirement}</td>
                      <td className={`px-4 py-3 text-xs font-medium ${c.status === "Mandatory" ? "text-red-500" : c.status === "Required" ? "text-amber-500" : "text-emerald-500"}`}>{c.status}</td>
                      <td className="px-4 py-3 text-xs text-muted">{c.action}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* GO-LIVE CHECKLIST */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🚀 Go-Live Checklist</h3>
              {(() => {
                const categories = [...new Set(projectPlan.goLiveChecklist.items.map(i => i.category))];
                return categories.map(cat => (
                  <div key={cat} className="mb-3">
                    <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">{cat}</p>
                    <div className="space-y-1">
                      {projectPlan.goLiveChecklist.items.filter(i => i.category === cat).map((item, i) => (
                        <div key={i} className="flex items-center gap-2 rounded-lg border border-border/50 bg-surface px-3 py-2">
                          <div className="flex size-5 shrink-0 items-center justify-center rounded border-2 border-border" />
                          <span className="text-xs">{item.item}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ));
              })()}
            </div>

            {/* MAINTENANCE PLAN */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🔧 Maintenance Plan</h3>
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Monthly</p>
                  <ul className="space-y-1">{projectPlan.maintenance.monthlyTasks.map((t, i) => <li key={i} className="text-xs text-muted">• {t}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Quarterly</p>
                  <ul className="space-y-1">{projectPlan.maintenance.quarterlyTasks.map((t, i) => <li key={i} className="text-xs text-muted">• {t}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Annual</p>
                  <ul className="space-y-1">{projectPlan.maintenance.annualTasks.map((t, i) => <li key={i} className="text-xs text-muted">• {t}</li>)}</ul>
                </div>
              </div>
              <p className="mt-2 text-right text-sm font-medium">Maintenance cost: <span className="text-accent">{projectPlan.maintenance.annualCost}</span></p>
            </div>

            {/* TRAINING PLAN */}
            {projectPlan.trainingPlan.sessions.length > 0 && (
              <div className="mb-8">
                <h3 className="mb-3 font-bold">🎓 Training Plan</h3>
                <div className="overflow-x-auto rounded-xl border border-border">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b border-border bg-surface-hover">
                      {["Audience", "Topic", "Duration", "Format"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                    </tr></thead>
                    <tbody>{projectPlan.trainingPlan.sessions.map((s, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-4 py-3 font-medium">{s.audience}</td>
                        <td className="px-4 py-3 text-muted">{s.topic}</td>
                        <td className="px-4 py-3 text-muted">{s.duration}</td>
                        <td className="px-4 py-3 text-xs text-muted">{s.format}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              </div>
            )}

            {/* SCOPE OF WORK */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📝 Scope of Work</h3>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-emerald-500">In Scope</p>
                  <ul className="space-y-1">{projectPlan.scopeOfWork.inScope.map((s, i) => <li key={i} className="text-xs text-muted">✓ {s}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-red-500">Out of Scope</p>
                  <ul className="space-y-1">{projectPlan.scopeOfWork.outOfScope.map((s, i) => <li key={i} className="text-xs text-muted">✗ {s}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Assumptions</p>
                  <ul className="space-y-1">{projectPlan.scopeOfWork.assumptions.map((s, i) => <li key={i} className="text-xs text-muted">• {s}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Constraints</p>
                  <ul className="space-y-1">{projectPlan.scopeOfWork.constraints.map((s, i) => <li key={i} className="text-xs text-muted">• {s}</li>)}</ul>
                </div>
              </div>
            </div>

            {/* COMMUNICATION PLAN */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📞 Communication Plan</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Meeting", "Frequency", "Attendees", "Purpose"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.communicationPlan.meetings.map((m, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{m.type}</td>
                      <td className="px-4 py-3 text-muted">{m.frequency}</td>
                      <td className="px-4 py-3 text-xs text-muted">{m.attendees}</td>
                      <td className="px-4 py-3 text-xs text-muted">{m.purpose}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Escalation Path</p>
                  <ul className="space-y-1">{projectPlan.communicationPlan.escalationPath.map((s, i) => <li key={i} className="text-xs text-muted">→ {s}</li>)}</ul>
                </div>
                <div className="rounded-xl border border-border bg-surface p-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Communication Tools</p>
                  <ul className="space-y-1">{projectPlan.communicationPlan.tools.map((s, i) => <li key={i} className="text-xs text-muted">• {s}</li>)}</ul>
                </div>
              </div>
            </div>

            {/* TESTING STRATEGY */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🧪 Testing Strategy & QA Plan</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Test Type", "Tool", "Coverage", "When"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.testingStrategy.types.map((t, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{t.type}</td>
                      <td className="px-4 py-3 text-accent">{t.tool}</td>
                      <td className="px-4 py-3 text-xs text-muted">{t.coverage}</td>
                      <td className="px-4 py-3 text-xs text-muted">{t.when}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              <div className="mt-4 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                <p className="mb-2 text-xs font-bold uppercase tracking-wider text-amber-500">Quality Gates (must pass before release)</p>
                <ul className="space-y-1">{projectPlan.testingStrategy.qualityGates.map((g, i) => <li key={i} className="text-xs text-muted">⚑ {g}</li>)}</ul>
              </div>
            </div>

            {/* ACCEPTANCE CRITERIA */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">✅ Acceptance Criteria</h3>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Area", "Criterion", "Verified By"].map(h => <th key={h} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.acceptanceCriteria.criteria.map((c, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-3 font-medium">{c.area}</td>
                      <td className="px-4 py-3 text-xs text-muted">{c.criterion}</td>
                      <td className="px-4 py-3 text-xs text-muted">{c.verifiedBy}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
              <div className="mt-4 rounded-xl border border-accent/20 bg-accent/5 p-4">
                <p className="mb-2 text-xs font-bold uppercase tracking-wider text-accent">Sign-off Process</p>
                <p className="text-xs text-muted">{projectPlan.acceptanceCriteria.signoffProcess}</p>
              </div>
            </div>

            {/* CHANGE REQUEST PROCESS */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">🔄 Change Request Process</h3>
              <div className="space-y-2">
                {projectPlan.changeRequestProcess.steps.map((s, i) => (
                  <div key={i} className="flex items-start gap-3 rounded-xl border border-border bg-surface p-4">
                    <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-accent/15 font-mono text-xs font-bold text-accent">{i + 1}</span>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">{s.step}</p>
                      <p className="mt-0.5 text-xs text-muted">Owner: {s.owner} · SLA: {s.sla}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
                <p className="mb-1 text-xs font-bold uppercase tracking-wider text-amber-500">Pricing for Changes</p>
                <p className="text-xs text-muted">{projectPlan.changeRequestProcess.pricingNote}</p>
              </div>
            </div>

            {/* RACI MATRIX */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">👥 RACI Matrix — Who Does What</h3>
              <p className="mb-3 text-xs text-muted">R = Responsible (does the work) · A = Accountable (owns the outcome) · C = Consulted · I = Informed</p>
              <div className="overflow-x-auto rounded-xl border border-border">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-border bg-surface-hover">
                    {["Activity", "R (Does)", "A (Owns)", "C (Consulted)", "I (Informed)"].map(h => <th key={h} className="px-3 py-3 text-left text-xs font-bold uppercase tracking-wider text-accent">{h}</th>)}
                  </tr></thead>
                  <tbody>{projectPlan.raciMatrix.rows.map((r, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-3 py-3 font-medium">{r.activity}</td>
                      <td className="px-3 py-3 text-xs text-accent">{r.responsible}</td>
                      <td className="px-3 py-3 text-xs font-medium">{r.accountable}</td>
                      <td className="px-3 py-3 text-xs text-muted">{r.consulted}</td>
                      <td className="px-3 py-3 text-xs text-muted">{r.informed}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            </div>

            {/* WHATSAPP SUMMARY — Mobile Phone Preview */}
            <div className="mb-8">
              <h3 className="mb-3 font-bold">📱 WhatsApp-Ready Summary</h3>
              <p className="mb-3 text-xs text-muted">Preview of how it looks on WhatsApp — tap Copy to paste directly</p>

              <div className="mx-auto max-w-sm">
                {/* Phone frame */}
                <div className="overflow-hidden rounded-[2rem] border-4 border-stone-700 bg-stone-800 shadow-2xl">
                  {/* Status bar */}
                  <div className="flex items-center justify-between bg-stone-800 px-5 py-2">
                    <span className="text-xs font-medium text-white">9:41</span>
                    <div className="flex items-center gap-1">
                      <div className="h-2.5 w-4 rounded-sm border border-white/50">
                        <div className="h-full w-3/4 rounded-sm bg-emerald-500" />
                      </div>
                    </div>
                  </div>
                  {/* WhatsApp header */}
                  <div className="flex items-center gap-3 bg-emerald-700 px-4 py-2.5">
                    <div className="flex size-8 items-center justify-center rounded-full bg-white/20 text-xs font-bold text-white">C</div>
                    <div>
                      <p className="text-sm font-semibold text-white">Client</p>
                      <p className="text-xs text-emerald-200">online</p>
                    </div>
                  </div>
                  {/* Chat area */}
                  <div className="bg-[#0b141a] p-3" style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E\")" }}>
                    {/* Message bubble */}
                    <div className="relative ml-auto max-w-[85%] rounded-xl rounded-tr-sm bg-emerald-800 p-3 shadow">
                      <pre className="whitespace-pre-wrap text-xs leading-relaxed text-emerald-50">{projectPlan.whatsappSummary.text}</pre>
                      <p className="mt-1 text-right text-[10px] text-emerald-400">
                        {new Date().toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" })} ✓✓
                      </p>
                    </div>
                  </div>
                  {/* Input bar */}
                  <div className="flex items-center gap-2 bg-[#1f2c34] px-3 py-2">
                    <div className="flex-1 rounded-full bg-[#2a3942] px-4 py-2">
                      <p className="text-xs text-white/30">Type a message</p>
                    </div>
                    <div className="flex size-9 items-center justify-center rounded-full bg-emerald-600">
                      <svg viewBox="0 0 24 24" fill="white" className="size-4"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" /></svg>
                    </div>
                  </div>
                </div>

                {/* Copy button below phone */}
                <button
                  onClick={handleCopyWhatsApp}
                  className={`mt-4 w-full rounded-xl py-3 text-center text-sm font-bold transition-all ${
                    whatsappCopied
                      ? "bg-emerald-500 text-white"
                      : "border-2 border-emerald-500/30 text-emerald-500 hover:bg-emerald-500/10"
                  }`}
                >
                  {whatsappCopied ? "Copied to Clipboard!" : "Copy WhatsApp Message"}
                </button>
              </div>
            </div>
          </>
        )}

        <div className="text-center text-xs text-muted">
          Generated by MMAM Tech Advisor · Based on your requirements · For discussion purposes
        </div>
      </div>
    );
  }

  // ── WIZARD VIEW ──
  return (
    <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-6">
        <Link href="/executive" className="text-sm text-accent hover:text-accent-hover">
          ← Executive MBA
        </Link>
        <div className="mt-2 flex items-center justify-between">
          <h1 className="text-2xl font-bold tracking-tight">Tech Stack Advisor</h1>
          {savedReports.length > 0 && (
            <button
              onClick={() => setSavedReportsOpen(!savedReportsOpen)}
              className="flex items-center gap-2 rounded-lg border border-accent/30 px-3 py-1.5 text-xs font-bold text-accent transition-all hover:bg-accent/10"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="size-3.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0 1 11.186 0Z" />
              </svg>
              {savedReports.length} Saved Report{savedReports.length !== 1 ? "s" : ""}
            </button>
          )}
        </div>
        <p className="mt-1 text-sm text-muted">
          Answer a few questions about your project. Get a complete A-Z technology recommendation.
        </p>
      </div>

      {/* Saved Reports List */}
      {savedReportsOpen && savedReports.length > 0 && (
        <div className="mb-8 rounded-xl border border-accent/20 bg-accent/5 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-bold">Saved Reports</h3>
            <button onClick={() => setSavedReportsOpen(false)} className="text-xs text-muted hover:text-foreground">Close</button>
          </div>
          <div className="space-y-2">
            {savedReports.map((report) => (
              <div key={report.id} className="flex items-center gap-3 rounded-lg border border-border bg-surface p-3">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{report.title}</p>
                  <p className="mt-0.5 text-xs text-muted">
                    {new Date(report.created_at).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}
                    {report.whatsapp_summary && ` · ${report.whatsapp_summary.slice(0, 60)}...`}
                  </p>
                </div>
                <button
                  onClick={() => handleLoadReport(report.id)}
                  disabled={loadingReports}
                  className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white transition-all hover:bg-accent-hover disabled:opacity-50"
                >
                  {loadingReports ? "..." : "Load"}
                </button>
                <button
                  onClick={() => handleDeleteReport(report.id)}
                  className="shrink-0 rounded-lg border border-red-500/30 px-2.5 py-1.5 text-xs font-medium text-red-500 transition-all hover:bg-red-500/10"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Progress bar */}
      <div className="mb-8">
        <div className="mb-2 flex justify-between text-xs text-muted">
          <span>Step {step + 1} of {STEPS.length}</span>
          <span>{STEPS[step].title}</span>
        </div>
        <div className="h-2 rounded-full bg-surface">
          <div className="h-2 rounded-full bg-accent transition-all" style={{ width: `${((step + 1) / STEPS.length) * 100}%` }} />
        </div>
        <p className="mt-2 text-sm text-muted">{STEPS[step].subtitle}</p>
      </div>

      {/* Step content */}
      <div className="mb-8">
        {step === 0 && (
          <>
            <RadioGroup label="What type of application?" options={[
              { value: "web", label: "Web Application", desc: "Browser-based, accessible from any device" },
              { value: "mobile", label: "Mobile App", desc: "iOS and/or Android native app" },
              { value: "both", label: "Web + Mobile", desc: "Full presence — browser + app stores" },
              { value: "desktop", label: "Desktop Application", desc: "Windows / Mac / Linux installable software" },
              { value: "desktop-web", label: "Desktop + Web", desc: "Installable desktop app with a web version too" },
              { value: "api-only", label: "API / Backend Only", desc: "Headless service, no user-facing UI" },
            ]} value={req.appType} onChange={(v) => { update("appType", v as Requirements["appType"]); update("platform", ""); }} />

            {/* Platform targeting — shown based on app type */}
            {req.appType === "desktop" || req.appType === "desktop-web" ? (
              <RadioGroup label="Target platform?" options={[
                { value: "windows-only", label: "Windows Only", desc: "Most Indian businesses use Windows" },
                { value: "mac-only", label: "Mac Only", desc: "Creative/design industry" },
                { value: "linux-only", label: "Linux Only", desc: "Servers, embedded, developer tools" },
                { value: "cross-platform", label: "Cross-Platform (Win + Mac + Linux)", desc: "Maximum reach — like VS Code, Slack" },
              ]} value={req.platform} onChange={(v) => update("platform", v as Requirements["platform"])} />
            ) : req.appType === "mobile" ? (
              <RadioGroup label="Target platform?" options={[
                { value: "ios-only", label: "iOS Only (iPhone/iPad)", desc: "Apple ecosystem, premium audience" },
                { value: "android-only", label: "Android Only", desc: "80%+ of Indian smartphones" },
                { value: "ios-android", label: "Both iOS + Android", desc: "Maximum reach — recommended for India" },
              ]} value={req.platform} onChange={(v) => update("platform", v as Requirements["platform"])} />
            ) : req.appType === "both" ? (
              <RadioGroup label="Mobile platform preference?" options={[
                { value: "ios-android", label: "Both iOS + Android", desc: "Full coverage — recommended" },
                { value: "android-only", label: "Android first (add iOS later)", desc: "Start with 80% of Indian market" },
                { value: "ios-only", label: "iOS first (add Android later)", desc: "Premium audience first" },
              ]} value={req.platform} onChange={(v) => update("platform", v as Requirements["platform"])} />
            ) : null}

            {/* PWA and offline — for web/desktop-web */}
            {(req.appType === "web" || req.appType === "both" || req.appType === "desktop-web") && (
              <div className="mt-4 space-y-2">
                <Toggle label="PWA (installable from browser)" desc="Works like a native app without app store — add to home screen" checked={req.pwaNeeded} onChange={(v) => update("pwaNeeded", v)} />
                <Toggle label="Offline capability needed" desc="Must work without internet connection" checked={req.offlineNeeded} onChange={(v) => update("offlineNeeded", v)} />
              </div>
            )}
            {(req.appType === "desktop" || req.appType === "mobile") && (
              <div className="mt-4 space-y-2">
                <Toggle label="Offline capability needed" desc="Must work without internet connection" checked={req.offlineNeeded} onChange={(v) => update("offlineNeeded", v)} />
              </div>
            )}
          </>
        )}

        {/* Step 1: Scale & Traffic */}
        {step === 1 && (
          <>
            <RadioGroup label="Total registered users expected?" options={[
              { value: "under100", label: "Under 100", desc: "Small internal tool or pilot" },
              { value: "100-1K", label: "100 — 1,000", desc: "Small business or community" },
              { value: "1K-10K", label: "1,000 — 10,000", desc: "Growing SaaS or organization" },
              { value: "10K-100K", label: "10,000 — 100,000", desc: "Established product" },
              { value: "100K-1M", label: "100K — 1 Million", desc: "Large-scale platform" },
              { value: "1M+", label: "1 Million+", desc: "Enterprise / consumer platform" },
            ]} value={req.totalUsers} onChange={(v) => update("totalUsers", v as Requirements["totalUsers"])} />
            <RadioGroup label="Peak concurrent users (at the same time)?" options={[
              { value: "under10", label: "Under 10", desc: "Very light usage" },
              { value: "10-50", label: "10 — 50", desc: "Small team simultaneous" },
              { value: "50-200", label: "50 — 200", desc: "Medium activity" },
              { value: "200-1K", label: "200 — 1,000", desc: "Active platform" },
              { value: "1K-5K", label: "1,000 — 5,000", desc: "High traffic" },
              { value: "5K-50K", label: "5,000 — 50,000", desc: "Very high traffic" },
              { value: "50K+", label: "50,000+", desc: "Massive scale" },
            ]} value={req.concurrentUsers} onChange={(v) => update("concurrentUsers", v as Requirements["concurrentUsers"])} />
            <RadioGroup label="Transactions per day?" options={[
              { value: "under100", label: "Under 100", desc: "~4/hour — low-volume internal tool" },
              { value: "100-1K", label: "100 — 1,000", desc: "~1/minute — typical business app" },
              { value: "1K-10K", label: "1,000 — 10,000", desc: "~7/minute — active platform" },
              { value: "10K-100K", label: "10,000 — 100,000", desc: "~1-2/second — high-volume commerce" },
              { value: "100K+", label: "100,000+", desc: "~1-100+/second — trading, fintech, large marketplace" },
            ]} value={req.transactionsPerDay} onChange={(v) => update("transactionsPerDay", v as Requirements["transactionsPerDay"])} />
            <RadioGroup label="Traffic pattern?" options={[
              { value: "steady", label: "Steady throughout the day" },
              { value: "business-hours", label: "Business hours (9 AM — 6 PM)", desc: "Low at night" },
              { value: "spiky", label: "Spiky (events, sales, deadlines)", desc: "Sudden bursts" },
              { value: "24x7", label: "24/7 non-stop", desc: "Continuous processing" },
            ]} value={req.peakHoursPattern} onChange={(v) => update("peakHoursPattern", v as Requirements["peakHoursPattern"])} />
            <RadioGroup label="Expected data volume (total storage needed)?" options={[
              { value: "under1GB", label: "Under 1 GB", desc: "Text-only app, small database" },
              { value: "1-10GB", label: "1 — 10 GB", desc: "Typical business app with some files" },
              { value: "10-100GB", label: "10 — 100 GB", desc: "Media uploads, large member databases" },
              { value: "100GB-1TB", label: "100 GB — 1 TB", desc: "Heavy media, analytics, logs" },
              { value: "1TB+", label: "1 TB+", desc: "Big data, video, large-scale analytics" },
            ]} value={req.dataVolume} onChange={(v) => update("dataVolume", v as Requirements["dataVolume"])} />
          </>
        )}

        {/* Step 2: Features & Capabilities */}
        {step === 2 && (
          <>
            <p className="mb-3 text-sm font-semibold">Core features needed</p>
            <div className="mb-6 grid gap-2 sm:grid-cols-2">
              <Toggle label="Real-time updates" desc="Live data, chat, notifications" checked={req.realTimeNeeded} onChange={(v) => update("realTimeNeeded", v)} />
              <Toggle label="File uploads" desc="Documents, images, videos" checked={req.fileUploads} onChange={(v) => update("fileUploads", v)} />
              <Toggle label="Payment processing" desc="Online payments, billing, invoicing" checked={req.paymentProcessing} onChange={(v) => update("paymentProcessing", v)} />
              <Toggle label="Heavy search" desc="Full-text search, filters, autocomplete" checked={req.searchHeavy} onChange={(v) => update("searchHeavy", v)} />
              <Toggle label="Reports & dashboards" desc="Charts, analytics, PDF/Excel exports" checked={req.reportingDashboards} onChange={(v) => update("reportingDashboards", v)} />
              <Toggle label="Multi-language" desc="Hindi, English, Gujarati, etc." checked={req.multiLanguage} onChange={(v) => update("multiLanguage", v)} />
              <Toggle label="Multi-tenant" desc="Multiple organizations on one system" checked={req.multiTenant} onChange={(v) => update("multiTenant", v)} />
              <Toggle label="AI features" desc="Chatbot, recommendations, analysis" checked={req.aiFeatures} onChange={(v) => update("aiFeatures", v)} />
              <Toggle label="Public API" desc="Third parties will integrate with this system" checked={req.publicAPI} onChange={(v) => update("publicAPI", v)} />
            </div>

            <p className="mb-3 text-sm font-semibold">Notification channels needed</p>
            <div className="mb-6 grid gap-2 sm:grid-cols-2">
              <Toggle label="Email notifications" desc="Transactional emails, reports" checked={req.notificationChannels.email} onChange={(v) => update("notificationChannels", { ...req.notificationChannels, email: v })} />
              <Toggle label="SMS notifications" desc="OTP, alerts, reminders" checked={req.notificationChannels.sms} onChange={(v) => update("notificationChannels", { ...req.notificationChannels, sms: v })} />
              <Toggle label="Push notifications" desc="Mobile/browser push alerts" checked={req.notificationChannels.push} onChange={(v) => update("notificationChannels", { ...req.notificationChannels, push: v })} />
              <Toggle label="WhatsApp messages" desc="WhatsApp Business API integration" checked={req.notificationChannels.whatsapp} onChange={(v) => update("notificationChannels", { ...req.notificationChannels, whatsapp: v })} />
            </div>

            <RadioGroup label="Primary content type?" options={[
              { value: "text", label: "Text-heavy", desc: "Forms, lists, data tables, documents" },
              { value: "media", label: "Media-heavy", desc: "Images, videos, audio, galleries" },
              { value: "data", label: "Data & analytics", desc: "Dashboards, charts, reports, numbers" },
              { value: "mixed", label: "Mixed content", desc: "Combination of text, media, and data" },
            ]} value={req.contentType} onChange={(v) => update("contentType", v as Requirements["contentType"])} />

            <RadioGroup label="User roles & permissions complexity?" options={[
              { value: "simple", label: "Simple (Admin / User)", desc: "Two roles, basic access control" },
              { value: "moderate", label: "Moderate (3-5 roles)", desc: "Admin, Manager, Staff, Viewer" },
              { value: "complex", label: "Complex RBAC", desc: "Custom roles, granular permissions, department-based access" },
            ]} value={req.userRoles} onChange={(v) => update("userRoles", v as Requirements["userRoles"])} />
          </>
        )}

        {/* Step 3: Data & Compliance */}
        {step === 3 && (
          <>
            <RadioGroup label="Data sensitivity level?" options={[
              { value: "public", label: "Public", desc: "Blog, portfolio, marketing site" },
              { value: "internal", label: "Internal / Business", desc: "CRM, project management, member data" },
              { value: "sensitive", label: "Sensitive / PII", desc: "Personal data, health records, Aadhaar" },
              { value: "financial", label: "Financial", desc: "Payments, banking, trading, invoices" },
              { value: "government", label: "Government / Regulated", desc: "SEBI, RBI, defense, compliance-heavy" },
            ]} value={req.dataType} onChange={(v) => update("dataType", v as Requirements["dataType"])} />

            <RadioGroup label="Industry / domain?" options={[
              { value: "general", label: "General business", desc: "No industry-specific regulations" },
              { value: "community", label: "Community / Samaj / NGO", desc: "Member management, events, donations" },
              { value: "fintech", label: "Fintech / Banking / Trading", desc: "RBI compliance, PCI-DSS, audit trails" },
              { value: "healthcare", label: "Healthcare", desc: "Patient data, HIPAA-like compliance" },
              { value: "education", label: "Education / EdTech", desc: "Student data, exam systems" },
              { value: "ecommerce", label: "E-commerce / Retail", desc: "Product catalog, orders, payments" },
              { value: "logistics", label: "Logistics / Supply chain", desc: "Tracking, fleet, warehouse management" },
              { value: "manufacturing", label: "Manufacturing / Industrial", desc: "ERP, inventory, production" },
            ]} value={req.industry} onChange={(v) => update("industry", v as Requirements["industry"])} />

            <RadioGroup label="Required uptime / availability?" options={[
              { value: "99", label: "99% (3.6 days downtime/year)", desc: "Acceptable for internal tools" },
              { value: "99.9", label: "99.9% (8.7 hours downtime/year)", desc: "Standard for business apps" },
              { value: "99.95", label: "99.95% (4.4 hours downtime/year)", desc: "High availability — mission-critical" },
              { value: "99.99", label: "99.99% (52 minutes downtime/year)", desc: "Enterprise-grade — requires redundancy everywhere" },
            ]} value={req.uptimeRequirement} onChange={(v) => update("uptimeRequirement", v as Requirements["uptimeRequirement"])} />

            <RadioGroup label="Data retention requirement?" options={[
              { value: "1", label: "1 year" },
              { value: "3", label: "3 years" },
              { value: "7", label: "7 years", desc: "Standard for financial records (Indian IT Act)" },
              { value: "10+", label: "10+ years", desc: "Government, legal compliance, audit" },
            ]} value={req.dataRetentionYears} onChange={(v) => update("dataRetentionYears", v as Requirements["dataRetentionYears"])} />
          </>
        )}

        {/* Step 4: Infrastructure */}
        {step === 4 && (
          <>
            <RadioGroup label="Where should the application be hosted?" options={[
              { value: "cloud", label: "Cloud (AWS / GCP / DigitalOcean)", desc: "Most flexible, pay-as-you-go, easy to scale" },
              { value: "self-hosted", label: "Self-hosted VPS", desc: "Your own virtual server (Hetzner, Linode). Best cost:performance" },
              { value: "on-premise", label: "On-premise (client's own servers)", desc: "Data stays on client's hardware. Banks, government often require this" },
              { value: "hybrid", label: "Hybrid (on-premise + cloud)", desc: "Sensitive data on-premise, everything else in cloud" },
            ]} value={req.deployment} onChange={(v) => update("deployment", v as Requirements["deployment"])} />

            <RadioGroup label="Geographic reach?" options={[
              { value: "single-city", label: "Single city / office", desc: "Users in one location. Simplest setup" },
              { value: "india", label: "Pan-India", desc: "Users across India. Single region hosting is fine" },
              { value: "asia", label: "Asia-Pacific", desc: "India + Southeast Asia + Middle East" },
              { value: "global", label: "Global", desc: "Users worldwide. Needs CDN + multi-region consideration" },
            ]} value={req.geoReach} onChange={(v) => update("geoReach", v as Requirements["geoReach"])} />
          </>
        )}

        {/* Step 5: Budget, Team & Migration */}
        {step === 5 && (
          <>
            <p className="mb-3 text-sm font-semibold">Client & Project Details (optional — appears on report)</p>
            <div className="mb-6 grid gap-3 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs font-medium text-muted">Client / Company Name</label>
                <input
                  type="text"
                  value={req.clientName}
                  onChange={(e) => update("clientName", e.target.value)}
                  placeholder="e.g., Sunil Saiya, JSG, Nirmal Industries"
                  className="w-full rounded-xl border border-border bg-surface p-4 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted">Project Name</label>
                <input
                  type="text"
                  value={req.projectName}
                  onChange={(e) => update("projectName", e.target.value)}
                  placeholder="e.g., Event Ticketing System, Fitness App"
                  className="w-full rounded-xl border border-border bg-surface p-4 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                />
              </div>
            </div>

            <RadioGroup label="Total budget (infrastructure + development)?" options={[
              { value: "under1L", label: "Under Rs 1 Lakh", desc: "MVP / proof of concept" },
              { value: "1-5L", label: "Rs 1 — 5 Lakh", desc: "Small business application" },
              { value: "5-15L", label: "Rs 5 — 15 Lakh", desc: "Medium business solution" },
              { value: "15-50L", label: "Rs 15 — 50 Lakh", desc: "Enterprise solution" },
              { value: "50L+", label: "Rs 50 Lakh+", desc: "Large-scale platform" },
            ]} value={req.budget} onChange={(v) => update("budget", v as Requirements["budget"])} />
            <RadioGroup label="Timeline to first release?" options={[
              { value: "1month", label: "1 month", desc: "Very tight — MVP only" },
              { value: "2-3months", label: "2 — 3 months", desc: "Standard for small-medium" },
              { value: "3-6months", label: "3 — 6 months", desc: "Standard for medium-large" },
              { value: "6-12months", label: "6 — 12 months", desc: "Complex enterprise" },
              { value: "12months+", label: "12+ months", desc: "Large-scale platform build" },
            ]} value={req.timeline} onChange={(v) => update("timeline", v as Requirements["timeline"])} />
            <RadioGroup label="Available team size?" options={[
              { value: "solo", label: "Solo developer (me)", desc: "One person builds everything" },
              { value: "2-3", label: "2 — 3 people", desc: "Small team" },
              { value: "4-8", label: "4 — 8 people", desc: "Medium team" },
              { value: "8-15", label: "8 — 15 people", desc: "Large team" },
              { value: "15+", label: "15+ people", desc: "Enterprise team" },
            ]} value={req.teamSize} onChange={(v) => update("teamSize", v as Requirements["teamSize"])} />

            <p className="mb-3 mt-6 text-sm font-semibold">Project context</p>
            <div className="mb-4 grid gap-2 sm:grid-cols-2">
              <Toggle label="Replacing an existing system" desc="Migrating from old software/spreadsheets" checked={req.replacingExisting} onChange={(v) => update("replacingExisting", v)} />
              <Toggle label="Training required" desc="Client team needs to be trained on the new system" checked={req.trainingNeeded} onChange={(v) => update("trainingNeeded", v)} />
              <Toggle label="Ongoing maintenance contract" desc="Post-launch support, updates, SLA" checked={req.maintenanceContract} onChange={(v) => update("maintenanceContract", v)} />
            </div>

            <div className="mt-4">
              <p className="mb-2 text-sm font-semibold">Existing systems to integrate with? (optional)</p>
              <textarea
                value={req.existingSystems}
                onChange={(e) => update("existingSystems", e.target.value)}
                placeholder="e.g., Tally for accounting, existing MySQL database, WhatsApp API, Razorpay, SAP, Zoho CRM..."
                className="w-full rounded-xl border border-border bg-surface p-4 text-sm placeholder:text-muted focus:border-accent focus:outline-none"
                rows={3}
              />
            </div>
          </>
        )}
      </div>

      {/* Navigation */}
      <div className="flex gap-3">
        {step > 0 && (
          <button onClick={() => setStep(step - 1)}
            className="flex-1 rounded-xl border border-border py-4 text-center text-sm font-bold text-muted transition-all hover:bg-surface-hover">
            Back
          </button>
        )}
        <button
          onClick={handleNext}
          disabled={!canProceed()}
          className={`flex-1 rounded-xl py-4 text-center text-sm font-bold transition-all ${
            canProceed()
              ? "bg-accent text-white hover:bg-accent-hover"
              : "bg-accent/30 text-white/50 cursor-not-allowed"
          }`}
        >
          {step === STEPS.length - 1 ? "Generate Recommendation" : "Next"}
        </button>
      </div>
    </div>
  );
}
