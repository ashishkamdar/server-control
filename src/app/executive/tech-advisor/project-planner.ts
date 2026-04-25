// Project planning engine — licensing, hardware detail, phases, resources, costs

export interface LicenseItem {
  technology: string;
  license: string;
  cost: string;
  notes: string;
}

export interface HardwareDetail {
  role: string;
  count: number;
  cpu: string;
  ram: string;
  disk: string;
  swap: string;
  network: string;
  os: string;
  monthlyCost: string;
}

export interface ProjectPhase {
  phase: string;
  name: string;
  duration: string;
  tasks: string[];
  deliverables: string[];
  resources: string;
  testingTime: string;
}

export interface ResourcePlan {
  humans: { role: string; count: number; monthlyRate: string; duration: string; totalCost: string }[];
  claudeCode: { task: string; estimatedHours: string; costPerHour: string; totalCost: string }[];
  totalHumanCost: string;
  totalAICost: string;
  totalCost: string;
  savingsWithAI: string;
}

export interface RiskItem {
  risk: string;
  probability: "Low" | "Medium" | "High";
  impact: "Low" | "Medium" | "High";
  mitigation: string;
}

export interface BackupDRPlan {
  backupFrequency: string;
  backupRetention: string;
  backupStorage: string;
  rto: string;
  rpo: string;
  drStrategy: string;
  backupCost: string;
}

export interface EnvironmentPlan {
  environments: { name: string; purpose: string; specs: string; cost: string }[];
}

export interface NotificationPlan {
  providers: { channel: string; provider: string; cost: string; notes: string }[];
}

export interface MaintenancePlan {
  monthlyTasks: string[];
  quarterlyTasks: string[];
  annualTasks: string[];
  annualCost: string;
}

export interface ScalabilityRoadmap {
  triggers: { when: string; action: string; cost: string }[];
}

export interface GoLiveChecklist {
  items: { category: string; item: string }[];
}

export interface PerformanceTargets {
  targets: { metric: string; target: string; how: string }[];
}

export interface TechAlternatives {
  alternatives: { layer: string; primary: string; alternativeA: string; alternativeB: string; when: string }[];
}

export interface YearProjection {
  years: { year: string; infrastructure: string; maintenance: string; licensing: string; total: string }[];
}

export interface ComplianceChecklist {
  items: { requirement: string; status: string; action: string }[];
}

export interface TrainingPlan {
  sessions: { audience: string; topic: string; duration: string; format: string }[];
}

export interface WhatsAppSummary {
  text: string;
}

export interface ScopeOfWork {
  inScope: string[];
  outOfScope: string[];
  assumptions: string[];
  constraints: string[];
}

export interface CommunicationPlan {
  meetings: { type: string; frequency: string; attendees: string; purpose: string }[];
  escalationPath: string[];
  tools: string[];
}

export interface TestingStrategy {
  types: { type: string; tool: string; coverage: string; when: string }[];
  qualityGates: string[];
}

export interface AcceptanceCriteria {
  criteria: { area: string; criterion: string; verifiedBy: string }[];
  signoffProcess: string;
}

export interface ChangeRequestProcess {
  steps: { step: string; owner: string; sla: string }[];
  pricingNote: string;
}

export interface RACIMatrix {
  rows: { activity: string; responsible: string; accountable: string; consulted: string; informed: string }[];
}

export interface ProjectPlan {
  licenses: LicenseItem[];
  hardware: HardwareDetail[];
  phases: ProjectPhase[];
  resources: ResourcePlan;
  risks: RiskItem[];
  milestones: { date: string; milestone: string }[];
  totalProjectCost: { development: string; infrastructure12mo: string; licensing12mo: string; grand12mo: string };
  // New sections
  backupDR: BackupDRPlan;
  environments: EnvironmentPlan;
  notifications: NotificationPlan;
  maintenance: MaintenancePlan;
  scalabilityRoadmap: ScalabilityRoadmap;
  goLiveChecklist: GoLiveChecklist;
  performanceTargets: PerformanceTargets;
  techAlternatives: TechAlternatives;
  yearProjection: YearProjection;
  complianceChecklist: ComplianceChecklist;
  trainingPlan: TrainingPlan;
  scopeOfWork: ScopeOfWork;
  communicationPlan: CommunicationPlan;
  testingStrategy: TestingStrategy;
  acceptanceCriteria: AcceptanceCriteria;
  changeRequestProcess: ChangeRequestProcess;
  raciMatrix: RACIMatrix;
  whatsappSummary: WhatsAppSummary;
}

type ScaleTier = "tiny" | "small" | "medium" | "large" | "enterprise";

interface PlanInput {
  scale: ScaleTier;
  appType: string;
  platform: string;
  isFinancial: boolean;
  isGovernment: boolean;
  hasRealTime: boolean;
  hasPayments: boolean;
  hasSearch: boolean;
  hasAI: boolean;
  hasFileUploads: boolean;
  hasMultiTenant: boolean;
  teamSize: string;
  timeline: string;
  budget: string;
  frontendTech: string;
  backendTech: string;
  dbTech: string;
  cacheTech: string;
  queueTech?: string;
  // New fields
  deployment: string;
  geoReach: string;
  industry: string;
  uptimeRequirement: string;
  dataVolume: string;
  contentType: string;
  notificationChannels: { email: boolean; sms: boolean; push: boolean; whatsapp: boolean };
  publicAPI: boolean;
  userRoles: string;
  replacingExisting: boolean;
  trainingNeeded: boolean;
  maintenanceContract: boolean;
  dataType: string;
  clientName: string;
  projectName: string;
}

export function generateProjectPlan(input: PlanInput): ProjectPlan {
  return {
    licenses: getLicenses(input),
    hardware: getHardwareDetail(input),
    phases: getPhases(input),
    resources: getResources(input),
    risks: getRisks(input),
    milestones: getMilestones(input),
    totalProjectCost: getTotalCost(input),
    backupDR: getBackupDR(input),
    environments: getEnvironments(input),
    notifications: getNotifications(input),
    maintenance: getMaintenance(input),
    scalabilityRoadmap: getScalabilityRoadmap(input),
    goLiveChecklist: getGoLiveChecklist(input),
    performanceTargets: getPerformanceTargets(input),
    techAlternatives: getTechAlternatives(input),
    yearProjection: getYearProjection(input),
    complianceChecklist: getComplianceChecklist(input),
    trainingPlan: getTrainingPlan(input),
    scopeOfWork: getScopeOfWork(input),
    communicationPlan: getCommunicationPlan(input),
    testingStrategy: getTestingStrategy(input),
    acceptanceCriteria: getAcceptanceCriteria(input),
    changeRequestProcess: getChangeRequestProcess(input),
    raciMatrix: getRACIMatrix(input),
    whatsappSummary: getWhatsAppSummary(input),
  };
}

function getLicenses(input: PlanInput): LicenseItem[] {
  const items: LicenseItem[] = [];

  // Frontend
  if (input.frontendTech.includes("Next.js")) items.push({ technology: "Next.js 16", license: "MIT (Open Source)", cost: "FREE", notes: "No restrictions. Commercial use allowed. No attribution required." });
  if (input.frontendTech.includes("React Native")) items.push({ technology: "React Native", license: "MIT (Open Source)", cost: "FREE", notes: "Free for all use. Apple Developer Account ($99/yr) and Google Play ($25 one-time) needed for app store." });
  if (input.frontendTech.includes("Flutter")) items.push({ technology: "Flutter", license: "BSD 3-Clause (Open Source)", cost: "FREE", notes: "Google-backed, fully free. Same app store fees apply." });
  if (input.frontendTech.includes("Electron")) items.push({ technology: "Electron", license: "MIT (Open Source)", cost: "FREE", notes: "Free. Code signing certificate needed for Windows ($200-400/yr) and Mac ($99/yr Apple Developer)." });
  if (input.frontendTech.includes("Tauri")) items.push({ technology: "Tauri", license: "MIT/Apache 2.0 (Open Source)", cost: "FREE", notes: "Rust-based, very permissive. Same code signing costs as Electron." });
  if (input.frontendTech.includes(".NET")) items.push({ technology: ".NET / WPF / WinUI", license: "MIT (Open Source)", cost: "FREE (runtime), Visual Studio Community FREE", notes: "VS Community is free for <5 devs or <$1M revenue. VS Professional: $45/mo. VS Enterprise: $250/mo." });
  if (input.frontendTech.includes("Swift")) items.push({ technology: "Swift / SwiftUI", license: "Apache 2.0 (Open Source)", cost: "Apple Developer Program: $99/yr", notes: "Swift is free. Xcode is free. $99/yr for App Store distribution." });
  if (input.frontendTech.includes("Kotlin")) items.push({ technology: "Kotlin / Jetpack Compose", license: "Apache 2.0 (Open Source)", cost: "Google Play: $25 one-time", notes: "Kotlin and Android Studio are completely free. $25 for Play Store account." });
  items.push({ technology: "TypeScript", license: "Apache 2.0 (Open Source)", cost: "FREE", notes: "Microsoft open-sourced it. No restrictions." });
  items.push({ technology: "Tailwind CSS", license: "MIT (Open Source)", cost: "FREE", notes: "Free. Tailwind UI (pre-built components) is $299 one-time if you want them." });

  // Backend
  if (input.backendTech.includes("Node.js")) items.push({ technology: "Node.js", license: "MIT (Open Source)", cost: "FREE", notes: "Powers Netflix, LinkedIn, Uber. No licensing cost ever." });
  if (input.backendTech.includes("Go")) items.push({ technology: "Go (Golang)", license: "BSD 3-Clause (Open Source)", cost: "FREE", notes: "Google-created. Used by Docker, Kubernetes, Uber." });
  if (input.backendTech.includes("Fastify")) items.push({ technology: "Fastify", license: "MIT (Open Source)", cost: "FREE", notes: "2x faster than Express. No licensing." });

  // Database
  items.push({ technology: "PostgreSQL 16", license: "PostgreSQL License (Open Source)", cost: "FREE", notes: "The most permissive license in databases. No limits on usage, commercial or otherwise. Powers Instagram." });
  if (input.cacheTech.includes("Redis")) items.push({ technology: "Redis 7", license: "RSALv2 + SSPLv1", cost: "FREE (self-hosted)", notes: "Self-hosting is free. Cannot offer as managed service (SaaS). Redis Cloud starts at Rs 400/mo." });
  if (input.hasSearch) items.push({ technology: "Elasticsearch 8", license: "SSPL + Elastic License", cost: "FREE (self-hosted) or Rs 7,000/mo+ (Cloud)", notes: "Self-host for free. Cannot resell as a service. Alternative: OpenSearch (fully open, AWS fork)." });

  // Queue
  if (input.queueTech?.includes("Kafka")) items.push({ technology: "Apache Kafka", license: "Apache 2.0 (Open Source)", cost: "FREE (self-hosted)", notes: "Truly open source. Confluent Cloud: $0.11/GB. Self-host for free." });
  if (input.queueTech?.includes("RabbitMQ")) items.push({ technology: "RabbitMQ", license: "MPL 2.0 (Open Source)", cost: "FREE", notes: "Free for all use including commercial. CloudAMQP managed: from $20/mo." });

  // Infrastructure
  items.push({ technology: "nginx", license: "BSD 2-Clause (Open Source)", cost: "FREE", notes: "Open source is free. nginx Plus (enterprise): Rs 3L/yr — rarely needed." });
  items.push({ technology: "PM2", license: "AGPL 3.0 (Open Source)", cost: "FREE (CLI), PM2 Plus: $15/mo", notes: "CLI is free for all use. PM2 Plus adds web dashboard — optional." });
  items.push({ technology: "Docker Engine", license: "Apache 2.0 (Open Source)", cost: "FREE", notes: "Docker Engine is free. Docker Desktop requires license for companies >250 employees or >$10M revenue ($5/user/mo)." });
  if (input.scale === "large" || input.scale === "enterprise") {
    items.push({ technology: "Kubernetes", license: "Apache 2.0 (Open Source)", cost: "FREE (self-hosted) or Rs 5,000/mo+ (managed)", notes: "Self-host K8s for free. Managed: EKS/GKE $72/mo per cluster + node costs." });
  }
  items.push({ technology: "Let's Encrypt / Cloudflare SSL", license: "Free service", cost: "FREE", notes: "Free SSL certificates, auto-renewing. Cloudflare free plan includes SSL + basic CDN + DDoS." });

  // Monitoring
  items.push({ technology: "Prometheus + Grafana", license: "Apache 2.0 / AGPL (Open Source)", cost: "FREE (self-hosted)", notes: "Self-host for free. Grafana Cloud free tier: 10K metrics, 50GB logs." });
  if (input.scale !== "tiny") items.push({ technology: "Sentry (error tracking)", license: "BSL / Open Source", cost: "FREE tier (5K events/mo) or Rs 2,000/mo+", notes: "Free tier is enough for small-medium apps. Paid for high volume." });

  // Compliance
  if (input.isFinancial) items.push({ technology: "PCI-DSS Compliance", license: "Certification", cost: "Rs 2-10L/yr (audit + certification)", notes: "Required if you handle card data directly. Using Razorpay/Stripe eliminates most PCI requirements." });

  return items;
}

function getHardwareDetail(input: PlanInput): HardwareDetail[] {
  if (input.scale === "tiny") return [{
    role: "All-in-one (App + DB + Cache)", count: 1, cpu: "2 vCPU (shared)", ram: "4 GB DDR4",
    disk: "50 GB NVMe SSD", swap: "2 GB (swap file)", network: "1 Gbps shared",
    os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 500-1,500",
  }];

  if (input.scale === "small") return [
    { role: "Application Server", count: 1, cpu: "4 vCPU (dedicated)", ram: "8 GB DDR4", disk: "80 GB NVMe SSD", swap: "4 GB", network: "1 Gbps shared", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 2,000-3,500" },
    { role: "Database Server", count: 1, cpu: "2 vCPU (dedicated)", ram: "8 GB DDR4", disk: "100 GB NVMe SSD", swap: "4 GB", network: "1 Gbps shared", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 1,500-3,000" },
  ];

  if (input.scale === "medium") return [
    { role: "Load Balancer (nginx)", count: 1, cpu: "2 vCPU", ram: "4 GB DDR4", disk: "30 GB SSD", swap: "2 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 1,000" },
    { role: "Application Server", count: 2, cpu: "4 vCPU (dedicated)", ram: "16 GB DDR4", disk: "100 GB NVMe SSD", swap: "8 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,500 each" },
    { role: "Database Primary (PostgreSQL)", count: 1, cpu: "4 vCPU (dedicated)", ram: "16 GB DDR4", disk: "200 GB NVMe SSD (RAID-1)", swap: "8 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 4,000" },
    { role: "Cache Server (Redis)", count: 1, cpu: "2 vCPU", ram: "8 GB DDR4", disk: "30 GB SSD", swap: "0 (Redis should never swap)", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 2,000" },
    ...(input.hasSearch ? [{ role: "Search (Elasticsearch)", count: 1 as number, cpu: "4 vCPU", ram: "16 GB DDR4", disk: "200 GB NVMe SSD", swap: "0 (ES manages own heap)", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,500" }] : []),
  ];

  if (input.scale === "large") return [
    { role: "Load Balancer (nginx/HAProxy)", count: 2, cpu: "4 vCPU", ram: "8 GB DDR4", disk: "30 GB SSD", swap: "4 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 2,000 each" },
    { role: "Application Server", count: 4, cpu: "8 vCPU (dedicated)", ram: "16 GB DDR4", disk: "100 GB NVMe SSD", swap: "8 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 5,000 each" },
    { role: "DB Primary (PostgreSQL)", count: 1, cpu: "8 vCPU (dedicated)", ram: "32 GB DDR4", disk: "500 GB NVMe SSD (RAID-1)", swap: "16 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 8,000" },
    { role: "DB Read Replica", count: 2, cpu: "8 vCPU (dedicated)", ram: "32 GB DDR4", disk: "500 GB NVMe SSD", swap: "16 GB", network: "1 Gbps dedicated", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 8,000 each" },
    { role: "Redis Cluster", count: 3, cpu: "4 vCPU", ram: "16 GB DDR4", disk: "50 GB NVMe SSD", swap: "0", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,500 each" },
    { role: "Message Queue", count: 1, cpu: "4 vCPU", ram: "8 GB DDR4", disk: "100 GB NVMe SSD", swap: "4 GB", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 2,500" },
    { role: "Monitoring (Prometheus+Grafana)", count: 1, cpu: "4 vCPU", ram: "16 GB DDR4", disk: "500 GB SSD", swap: "8 GB", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,500" },
  ];

  // Enterprise
  return [
    { role: "Load Balancer (HAProxy/ALB)", count: 2, cpu: "4 vCPU", ram: "8 GB DDR5", disk: "50 GB NVMe", swap: "4 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,000 each" },
    { role: "API Gateway", count: 2, cpu: "4 vCPU", ram: "8 GB DDR5", disk: "50 GB NVMe", swap: "4 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 3,000 each" },
    { role: "Application Server", count: 8, cpu: "8 vCPU (dedicated)", ram: "32 GB DDR5", disk: "100 GB NVMe", swap: "16 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 8,000 each" },
    { role: "DB Primary (PostgreSQL)", count: 1, cpu: "16 vCPU (dedicated)", ram: "64 GB DDR5", disk: "1 TB NVMe (RAID-10)", swap: "32 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 20,000" },
    { role: "DB Read Replica", count: 3, cpu: "16 vCPU (dedicated)", ram: "64 GB DDR5", disk: "1 TB NVMe", swap: "32 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 18,000 each" },
    { role: "Redis Cluster", count: 6, cpu: "4 vCPU", ram: "32 GB DDR5", disk: "100 GB NVMe", swap: "0", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 6,000 each" },
    { role: "Kafka Cluster", count: 3, cpu: "8 vCPU", ram: "16 GB DDR5", disk: "500 GB NVMe", swap: "8 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 6,000 each" },
    { role: "Elasticsearch Cluster", count: 3, cpu: "8 vCPU", ram: "32 GB DDR5", disk: "500 GB NVMe", swap: "0", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 8,000 each" },
    { role: "Monitoring + Logging", count: 2, cpu: "4 vCPU", ram: "16 GB DDR5", disk: "1 TB SSD", swap: "8 GB", network: "10 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 5,000 each" },
    { role: "CI/CD Runner", count: 1, cpu: "8 vCPU", ram: "16 GB DDR5", disk: "200 GB NVMe", swap: "8 GB", network: "1 Gbps", os: "Ubuntu 24.04 LTS", monthlyCost: "Rs 5,000" },
  ];
}

function getPhases(input: PlanInput): ProjectPhase[] {
  const isSmall = input.scale === "tiny" || input.scale === "small";
  const isMedium = input.scale === "medium";

  if (isSmall) return [
    { phase: "0", name: "Discovery & Planning", duration: "3-5 days", tasks: ["Requirement finalization", "UI/UX wireframes", "Database schema design", "API contract definition", "Setup dev environment"], deliverables: ["Requirements document", "Wireframes (Figma/paper)", "Database ERD", "API spec (OpenAPI)"], resources: "1 developer + client", testingTime: "N/A (planning)" },
    { phase: "1", name: "Core Development", duration: "2-3 weeks", tasks: ["Setup project (Next.js + PostgreSQL + nginx)", "Build core database tables + migrations", "Implement authentication", "Build primary CRUD features", "Basic UI with Tailwind"], deliverables: ["Working local app with core features", "Auth system", "Database with seed data"], resources: "1 developer", testingTime: "3-4 days (parallel)" },
    { phase: "2", name: "Feature Completion", duration: "1-2 weeks", tasks: ["Secondary features", "File uploads (if needed)", "Reports/dashboards", "Payment integration (if needed)", "Email notifications"], deliverables: ["Feature-complete application", "Integration test suite"], resources: "1 developer", testingTime: "2-3 days" },
    { phase: "3", name: "Testing & Hardening", duration: "3-5 days", tasks: ["End-to-end testing", "Performance testing (load test with k6)", "Security review (OWASP checklist)", "Browser/device testing", "Bug fixes"], deliverables: ["Test report", "Security checklist", "Bug-free application"], resources: "1 developer + 1 tester (optional)", testingTime: "Full phase is testing" },
    { phase: "4", name: "Deployment & Launch", duration: "2-3 days", tasks: ["Server setup (VPS + nginx + PM2 + SSL)", "Database migration to production", "DNS configuration", "Monitoring setup (UptimeRobot + PM2)", "Client training / handover"], deliverables: ["Live application", "Server documentation", "Training session recording"], resources: "1 developer", testingTime: "1 day (smoke test in prod)" },
    { phase: "5", name: "Post-Launch Support", duration: "2-4 weeks", tasks: ["Monitor for issues", "Fix production bugs", "Performance optimization", "User feedback incorporation"], deliverables: ["Stable production application", "Handover complete"], resources: "1 developer (part-time)", testingTime: "Ongoing" },
  ];

  if (isMedium) return [
    { phase: "0", name: "Discovery & Architecture", duration: "1-2 weeks", tasks: ["Stakeholder interviews", "Detailed requirements", "System architecture design", "Database schema + API contracts", "UI/UX design (Figma)", "Technology evaluation", "DevOps planning"], deliverables: ["Architecture document", "Figma designs", "API specification", "Database ERD", "Project plan"], resources: "Tech lead + 1 developer + designer", testingTime: "N/A" },
    { phase: "1", name: "Foundation Sprint", duration: "2 weeks", tasks: ["Project scaffolding + CI/CD pipeline", "Auth system (JWT + roles)", "Database setup + migrations", "Shared component library", "API framework + validation"], deliverables: ["Running skeleton app", "Auth working", "CI/CD pipeline", "Shared components"], resources: "2-3 developers", testingTime: "3 days (parallel)" },
    { phase: "2", name: "Core Features (Sprint 1-3)", duration: "4-6 weeks", tasks: ["Primary business features (2-week sprints)", "CRUD operations for main entities", "Business logic implementation", "Dashboard / reporting", "File management (if needed)"], deliverables: ["Core features working", "Unit + integration tests", "Sprint demos to client"], resources: "3-4 developers", testingTime: "1 week per sprint (parallel)" },
    { phase: "3", name: "Advanced Features", duration: "2-3 weeks", tasks: ["Payment integration", "Search functionality", "Real-time features (WebSocket)", "Multi-tenant isolation", "AI features (if needed)", "Email/SMS notifications"], deliverables: ["Feature-complete application", "Integration tests"], resources: "3-4 developers", testingTime: "1 week" },
    { phase: "4", name: "QA & Performance", duration: "1-2 weeks", tasks: ["Full regression testing", "Load testing (k6/Artillery — simulate 2x expected load)", "Security audit (OWASP Top 10)", "Accessibility testing", "Cross-browser/device testing", "Performance optimization"], deliverables: ["QA signoff", "Load test report", "Security audit report", "Performance benchmarks"], resources: "1 QA + 1-2 developers", testingTime: "Full phase" },
    { phase: "5", name: "Staging & UAT", duration: "1 week", tasks: ["Deploy to staging environment", "Client UAT (User Acceptance Testing)", "Bug fixes from UAT", "Documentation finalization"], deliverables: ["UAT signoff from client", "User manual", "Admin guide"], resources: "Full team + client testers", testingTime: "Full phase" },
    { phase: "6", name: "Production Deployment", duration: "3-5 days", tasks: ["Production server setup", "Data migration", "DNS + SSL + CDN configuration", "Monitoring + alerting setup", "Backup automation", "Go-live checklist"], deliverables: ["Live production system", "Monitoring dashboard", "Runbook"], resources: "Tech lead + 1 developer", testingTime: "1 day (smoke test)" },
    { phase: "7", name: "Hypercare & Stabilization", duration: "2-4 weeks", tasks: ["24/7 monitoring for first week", "Production bug fixes", "Performance tuning", "Knowledge transfer to client team", "Maintenance contract setup"], deliverables: ["Stable production", "SLA established", "Handover complete"], resources: "1-2 developers (on-call)", testingTime: "Ongoing" },
  ];

  // Large / Enterprise
  return [
    { phase: "0", name: "Discovery & Strategy", duration: "2-4 weeks", tasks: ["Business analysis + stakeholder mapping", "System architecture + ADRs (Architecture Decision Records)", "Security architecture + threat modeling", "API design workshop", "UI/UX research + design system", "Infrastructure planning", "Risk assessment + contingency planning"], deliverables: ["Architecture document", "Security plan", "Design system (Figma)", "API spec", "Infrastructure plan", "Project charter"], resources: "Architect + 2 leads + designer + PM", testingTime: "N/A" },
    { phase: "1", name: "Foundation (Sprint 0-1)", duration: "2-3 weeks", tasks: ["Mono-repo / multi-repo setup", "CI/CD pipeline (GitHub Actions + Docker)", "Infrastructure as Code (Terraform)", "Auth service + API Gateway", "Database setup + migration framework", "Shared library / SDK", "Logging + monitoring foundation"], deliverables: ["Running infrastructure", "CI/CD deploying to staging", "Auth + gateway working"], resources: "3-4 developers + 1 DevOps", testingTime: "1 week" },
    { phase: "2", name: "Core Services (Sprint 2-6)", duration: "6-10 weeks", tasks: ["Implement core microservices (2-week sprints)", "Database per service", "Inter-service communication (queue/gRPC)", "Unit + integration test suites", "Sprint reviews with stakeholders"], deliverables: ["Core services operational", "80%+ test coverage", "Sprint demo recordings"], resources: "5-8 developers + 1 QA", testingTime: "2 days per sprint" },
    { phase: "3", name: "Integration & Advanced", duration: "4-6 weeks", tasks: ["Third-party integrations (payment, SMS, email)", "Search + analytics pipeline", "Real-time features", "Admin panel + dashboards", "Data migration from legacy (if applicable)"], deliverables: ["Fully integrated system", "Admin tools", "Migration scripts tested"], resources: "4-6 developers + 1 QA", testingTime: "1 week per major integration" },
    { phase: "4", name: "Security & Performance", duration: "2-3 weeks", tasks: ["Penetration testing", "Load testing (simulate 3-5x expected peak)", "Security audit + remediation", "Performance optimization", "Disaster recovery testing", "Failover testing"], deliverables: ["Pen test report", "Load test results", "DR procedure verified", "Performance benchmarks"], resources: "Security specialist + 2 developers + QA", testingTime: "Full phase" },
    { phase: "5", name: "UAT & Beta", duration: "2-4 weeks", tasks: ["Internal beta with team", "Client UAT with real data subset", "Bug triage + fix cycles", "Documentation (user, admin, API, runbook)", "Training material preparation"], deliverables: ["UAT signoff", "All documentation", "Training materials", "Go-live checklist"], resources: "Full team + client testers", testingTime: "Full phase" },
    { phase: "6", name: "Go-Live", duration: "1 week", tasks: ["Production deployment (blue-green)", "Data migration (final)", "DNS cutover", "Monitoring + alerting verification", "War room for first 48 hours"], deliverables: ["System live in production", "All monitoring green", "War room debrief"], resources: "Full team on standby", testingTime: "Continuous monitoring" },
    { phase: "7", name: "Hypercare", duration: "4-8 weeks", tasks: ["On-call support rotation", "Production issue resolution (SLA: 4hr for critical)", "Performance tuning under real load", "Feature refinements from user feedback", "Knowledge transfer sessions", "Transition to maintenance team"], deliverables: ["Stable production", "Maintenance SLA signed", "Full handover"], resources: "2-3 developers + 1 DevOps (on-call)", testingTime: "Ongoing" },
  ];
}

function getResources(input: PlanInput): ResourcePlan {
  const isSmall = input.scale === "tiny" || input.scale === "small";
  const isMedium = input.scale === "medium";

  // Human resources
  const humans = (() => {
    if (isSmall) return [
      { role: "Full-stack Developer", count: 1, monthlyRate: "Rs 80,000-1,50,000", duration: "2-3 months", totalCost: "Rs 1.6L-4.5L" },
      { role: "UI Designer (freelance)", count: 1, monthlyRate: "Rs 30,000-60,000", duration: "2-3 weeks", totalCost: "Rs 15K-45K" },
    ];
    if (isMedium) return [
      { role: "Tech Lead / Architect", count: 1, monthlyRate: "Rs 1,50,000-2,50,000", duration: "4-6 months", totalCost: "Rs 6L-15L" },
      { role: "Full-stack Developer", count: 2, monthlyRate: "Rs 80,000-1,50,000 each", duration: "4-6 months", totalCost: "Rs 6.4L-18L" },
      { role: "QA Engineer (part-time)", count: 1, monthlyRate: "Rs 40,000-80,000", duration: "2-3 months", totalCost: "Rs 80K-2.4L" },
      { role: "UI/UX Designer", count: 1, monthlyRate: "Rs 50,000-1,00,000", duration: "1-2 months", totalCost: "Rs 50K-2L" },
    ];
    // Large/Enterprise
    return [
      { role: "Solution Architect", count: 1, monthlyRate: "Rs 2,50,000-4,00,000", duration: "6-12 months", totalCost: "Rs 15L-48L" },
      { role: "Backend Developer", count: 3, monthlyRate: "Rs 1,00,000-2,00,000 each", duration: "6-12 months", totalCost: "Rs 18L-72L" },
      { role: "Frontend Developer", count: 2, monthlyRate: "Rs 80,000-1,50,000 each", duration: "6-12 months", totalCost: "Rs 9.6L-36L" },
      { role: "DevOps Engineer", count: 1, monthlyRate: "Rs 1,20,000-2,50,000", duration: "6-12 months", totalCost: "Rs 7.2L-30L" },
      { role: "QA Engineer", count: 2, monthlyRate: "Rs 60,000-1,20,000 each", duration: "4-8 months", totalCost: "Rs 4.8L-19.2L" },
      { role: "Project Manager", count: 1, monthlyRate: "Rs 1,00,000-2,00,000", duration: "6-12 months", totalCost: "Rs 6L-24L" },
      { role: "UI/UX Designer", count: 1, monthlyRate: "Rs 60,000-1,20,000", duration: "2-4 months", totalCost: "Rs 1.2L-4.8L" },
    ];
  })();

  // Claude Code / AI resources
  const claudeCode = (() => {
    if (isSmall) return [
      { task: "Boilerplate & scaffolding generation", estimatedHours: "5-10 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 500-2,000" },
      { task: "CRUD API generation", estimatedHours: "8-15 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 800-3,000" },
      { task: "UI component generation", estimatedHours: "10-20 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,000-4,000" },
      { task: "Test case generation", estimatedHours: "5-10 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 500-2,000" },
      { task: "Documentation generation", estimatedHours: "3-5 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 300-1,000" },
      { task: "Code review & bug finding", estimatedHours: "5-10 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 500-2,000" },
    ];
    if (isMedium) return [
      { task: "Architecture scaffolding + project setup", estimatedHours: "10-15 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,000-3,000" },
      { task: "API + database layer generation", estimatedHours: "20-40 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 2,000-8,000" },
      { task: "UI pages + component library", estimatedHours: "30-50 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 3,000-10,000" },
      { task: "Test suite generation (unit + integration)", estimatedHours: "15-25 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,500-5,000" },
      { task: "DevOps + deployment scripts", estimatedHours: "5-10 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 500-2,000" },
      { task: "Documentation + API docs", estimatedHours: "8-12 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 800-2,400" },
      { task: "Code review + refactoring", estimatedHours: "15-25 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,500-5,000" },
    ];
    return [
      { task: "Microservice scaffolding (per service)", estimatedHours: "5-8 hrs × services", costPerHour: "~Rs 100-200", totalCost: "Rs 5,000-20,000" },
      { task: "API + business logic generation", estimatedHours: "50-100 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 5,000-20,000" },
      { task: "Frontend pages + design system", estimatedHours: "40-80 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 4,000-16,000" },
      { task: "Comprehensive test suite", estimatedHours: "30-50 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 3,000-10,000" },
      { task: "Infrastructure as Code (Terraform/Docker)", estimatedHours: "10-20 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,000-4,000" },
      { task: "Documentation (API, user, admin, runbook)", estimatedHours: "15-25 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,500-5,000" },
      { task: "Code review + security analysis", estimatedHours: "20-40 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 2,000-8,000" },
      { task: "Performance optimization suggestions", estimatedHours: "10-15 hrs", costPerHour: "~Rs 100-200", totalCost: "Rs 1,000-3,000" },
    ];
  })();

  const totalHuman = isSmall ? "Rs 1.75L-5L" : isMedium ? "Rs 14L-37L" : "Rs 62L-2.3Cr";
  const totalAI = isSmall ? "Rs 3,600-14,000" : isMedium ? "Rs 10,300-35,400" : "Rs 22,500-86,000";
  const savings = isSmall ? "30-40% faster development with AI assist" : isMedium ? "25-35% faster, ~Rs 4L-10L saved vs. purely human team" : "20-30% faster, ~Rs 15L-40L saved in developer time";

  return {
    humans, claudeCode,
    totalHumanCost: totalHuman,
    totalAICost: totalAI,
    totalCost: isSmall ? "Rs 1.8L-5.2L" : isMedium ? "Rs 14.1L-37.4L" : "Rs 62.2L-2.4Cr",
    savingsWithAI: savings,
  };
}

function getRisks(input: PlanInput): RiskItem[] {
  const risks: RiskItem[] = [
    { risk: "Scope creep — client adds features mid-project", probability: "High", impact: "High", mitigation: "Written scope document with change request process. Every addition gets a revised quote." },
    { risk: "Key developer leaves mid-project", probability: "Medium", impact: "High", mitigation: "Code documentation, pair programming, Git-based workflow. AI can help new dev ramp up faster." },
    { risk: "Client delays in providing content/feedback", probability: "High", impact: "Medium", mitigation: "Define feedback windows in contract. Auto-proceed with defaults if no response in 5 business days." },
    { risk: "Technology choice doesn't scale as expected", probability: "Low", impact: "High", mitigation: "Load test early (Phase 2). Architecture allows swapping components. PostgreSQL scales to millions." },
  ];

  if (input.isFinancial) risks.push(
    { risk: "Payment gateway integration issues", probability: "Medium", impact: "High", mitigation: "Use Razorpay (well-documented, good Indian support). Start integration in Phase 1, not Phase 3." },
    { risk: "Data breach / security incident", probability: "Low", impact: "High", mitigation: "Encryption at rest + transit, regular security audits, no PII in logs, principle of least privilege." },
  );

  if (input.hasRealTime) risks.push(
    { risk: "WebSocket scaling issues under load", probability: "Medium", impact: "Medium", mitigation: "Load test WebSocket connections specifically. Use Redis Pub/Sub for horizontal scaling." },
  );

  if (input.scale === "large" || input.scale === "enterprise") risks.push(
    { risk: "Microservice communication failures", probability: "Medium", impact: "High", mitigation: "Circuit breakers, retry policies, dead letter queues. Comprehensive distributed tracing." },
    { risk: "Database performance degradation", probability: "Medium", impact: "High", mitigation: "Query monitoring from day 1. Read replicas for dashboards. Index strategy review every sprint." },
  );

  risks.push(
    { risk: "Hosting provider outage", probability: "Low", impact: "High", mitigation: "Automated backups to separate provider. DNS failover if budget allows. Documented recovery procedure." },
    { risk: "Budget overrun", probability: "Medium", impact: "Medium", mitigation: "Phase-based delivery with go/no-go gates. MVP first, then iterate. Weekly burn rate tracking." },
  );

  return risks;
}

function getMilestones(input: PlanInput): { date: string; milestone: string }[] {
  const isSmall = input.scale === "tiny" || input.scale === "small";
  const isMedium = input.scale === "medium";

  if (isSmall) return [
    { date: "Week 1", milestone: "Requirements signed off, wireframes approved" },
    { date: "Week 2-3", milestone: "Core features demo to client" },
    { date: "Week 4", milestone: "Feature-complete, testing begins" },
    { date: "Week 5", milestone: "UAT by client" },
    { date: "Week 6", milestone: "GO LIVE" },
    { date: "Week 7-10", milestone: "Post-launch support + stabilization" },
  ];
  if (isMedium) return [
    { date: "Week 1-2", milestone: "Architecture approved, designs signed off" },
    { date: "Week 3-4", milestone: "Foundation + auth working in staging" },
    { date: "Week 5-10", milestone: "Core features sprint demos (every 2 weeks)" },
    { date: "Week 11-12", milestone: "Feature freeze, QA begins" },
    { date: "Week 13-14", milestone: "Client UAT in staging" },
    { date: "Week 15", milestone: "GO LIVE" },
    { date: "Week 16-20", milestone: "Hypercare + stabilization" },
  ];
  return [
    { date: "Week 1-4", milestone: "Architecture + design approved, infrastructure provisioned" },
    { date: "Week 5-6", milestone: "Foundation services + CI/CD running" },
    { date: "Week 7-16", milestone: "Core service sprint demos (every 2 weeks)" },
    { date: "Week 17-20", milestone: "Advanced features + integrations" },
    { date: "Week 21-23", milestone: "Security audit + performance testing" },
    { date: "Week 24-26", milestone: "Beta / UAT with real users" },
    { date: "Week 27-28", milestone: "GO LIVE (blue-green deployment)" },
    { date: "Week 29-36", milestone: "Hypercare + transition to maintenance" },
  ];
}

function getTotalCost(input: PlanInput): ProjectPlan["totalProjectCost"] {
  const isSmall = input.scale === "tiny" || input.scale === "small";
  const isMedium = input.scale === "medium";

  if (isSmall) return {
    development: "Rs 1.8L - 5.2L",
    infrastructure12mo: "Rs 6K - 42K",
    licensing12mo: "Rs 0 (all open-source)",
    grand12mo: "Rs 2.4L - 5.6L",
  };
  if (isMedium) return {
    development: "Rs 14L - 37L",
    infrastructure12mo: "Rs 1.7L - 3L",
    licensing12mo: "Rs 0 - 50K (Sentry, domains, SSL certs)",
    grand12mo: "Rs 16L - 40L",
  };
  if (input.scale === "large") return {
    development: "Rs 40L - 1.2Cr",
    infrastructure12mo: "Rs 5L - 12L",
    licensing12mo: "Rs 50K - 3L (monitoring, security tools)",
    grand12mo: "Rs 46L - 1.35Cr",
  };
  return {
    development: "Rs 62L - 2.4Cr",
    infrastructure12mo: "Rs 15L - 40L",
    licensing12mo: "Rs 2L - 10L (managed services, compliance)",
    grand12mo: "Rs 79L - 2.9Cr",
  };
}

// ═══════════════════════════════════════════════════════
// NEW SECTIONS
// ═══════════════════════════════════════════════════════

function getBackupDR(input: PlanInput): BackupDRPlan {
  const isHighAvail = input.uptimeRequirement === "99.99" || input.uptimeRequirement === "99.95";
  const isFinGov = input.isFinancial || input.isGovernment;

  if (input.scale === "enterprise" || isHighAvail) return {
    backupFrequency: "Database: WAL streaming (continuous). Full backup: every 6 hours. Files: incremental every hour.",
    backupRetention: "Daily backups: 30 days. Weekly: 12 weeks. Monthly: 12 months. Yearly: as per retention policy.",
    backupStorage: "Primary: same-region object storage (S3/Hetzner Storage Box). Secondary: cross-region replica for DR.",
    rto: "< 15 minutes (automated failover to read replica promoted to primary)",
    rpo: "< 1 minute (WAL streaming provides near-zero data loss)",
    drStrategy: "Active-passive: hot standby in secondary region. Automated DNS failover via health checks. Quarterly DR drills.",
    backupCost: "Rs 2,000-8,000/mo (storage + cross-region transfer)",
  };
  if (input.scale === "large" || isFinGov) return {
    backupFrequency: "Database: daily full + hourly incremental (pg_dump + WAL archiving). Files: daily sync to backup server.",
    backupRetention: "Daily: 14 days. Weekly: 8 weeks. Monthly: 6 months.",
    backupStorage: "Separate backup server in same data center + weekly offsite copy (S3 or Hetzner Storage Box).",
    rto: "< 1 hour (promote read replica, restore from latest backup if needed)",
    rpo: "< 1 hour (hourly incremental backups)",
    drStrategy: "Read replica serves as warm standby. Documented failover procedure. Tested quarterly.",
    backupCost: "Rs 1,000-3,000/mo",
  };
  if (input.scale === "medium") return {
    backupFrequency: "Database: daily full backup (pg_dump) at 2 AM. Files: daily rsync to backup location.",
    backupRetention: "Daily: 7 days. Weekly: 4 weeks.",
    backupStorage: "Automated backup to separate VPS or S3-compatible storage. 3-2-1 rule: 3 copies, 2 media, 1 offsite.",
    rto: "< 4 hours (restore from latest backup to new server)",
    rpo: "< 24 hours (daily backups)",
    drStrategy: "Documented restore procedure. Backup tested monthly by restoring to staging.",
    backupCost: "Rs 500-1,500/mo",
  };
  return {
    backupFrequency: "Database: daily pg_dump at 2 AM via cron. Files: daily rsync to backup folder.",
    backupRetention: "Daily: 7 days (auto-rotate with find + delete).",
    backupStorage: "Local backup folder + weekly copy to external storage (Google Drive / S3 free tier).",
    rto: "< 8 hours (manual restore from backup)",
    rpo: "< 24 hours (daily backup)",
    drStrategy: "Simple: restore from latest backup to new VPS. Document the process. Test once a month.",
    backupCost: "Rs 0-500/mo (free tier storage)",
  };
}

function getEnvironments(input: PlanInput): EnvironmentPlan {
  if (input.scale === "enterprise") return { environments: [
    { name: "Development", purpose: "Day-to-day coding and testing", specs: "Local Docker Compose or shared dev server", cost: "Rs 0-3,000/mo" },
    { name: "Staging", purpose: "Pre-production testing, UAT, demo to client", specs: "Mirror of production (smaller scale)", cost: "Rs 10,000-20,000/mo" },
    { name: "Pre-production", purpose: "Final validation with production data subset", specs: "Identical to production", cost: "Rs 15,000-30,000/mo" },
    { name: "Production", purpose: "Live system serving real users", specs: "Full production infrastructure", cost: "As per hardware plan" },
    { name: "DR / Failover", purpose: "Disaster recovery standby", specs: "Hot/warm standby in secondary region", cost: "50-80% of production cost" },
  ]};
  if (input.scale === "large") return { environments: [
    { name: "Development", purpose: "Local development", specs: "Docker Compose on developer machines", cost: "Rs 0" },
    { name: "Staging", purpose: "Testing, UAT, client demos", specs: "1 server mirroring production (smaller)", cost: "Rs 5,000-10,000/mo" },
    { name: "Production", purpose: "Live system", specs: "Full production infrastructure", cost: "As per hardware plan" },
  ]};
  if (input.scale === "medium") return { environments: [
    { name: "Development", purpose: "Local development", specs: "npm run dev on developer machine", cost: "Rs 0" },
    { name: "Staging", purpose: "Testing + client preview", specs: "Small VPS with production-like setup", cost: "Rs 1,500-3,000/mo" },
    { name: "Production", purpose: "Live system", specs: "Production servers", cost: "As per hardware plan" },
  ]};
  return { environments: [
    { name: "Development", purpose: "Local development + testing", specs: "npm run dev on your machine", cost: "Rs 0" },
    { name: "Production", purpose: "Live system", specs: "Single VPS", cost: "As per hardware plan" },
  ]};
}

function getNotifications(input: PlanInput): NotificationPlan {
  const providers: NotificationPlan["providers"] = [];
  if (input.notificationChannels.email) providers.push(
    { channel: "Email", provider: "Resend (recommended) or SendGrid", cost: "Free: 100 emails/day (Resend) or 100/day (SendGrid). Paid: Rs 1,500/mo for 50K emails", notes: "Resend has excellent developer experience. SendGrid is industry standard. Both have good deliverability." },
  );
  if (input.notificationChannels.sms) providers.push(
    { channel: "SMS", provider: "MSG91 (India) or Twilio (global)", cost: "MSG91: Rs 0.15-0.25 per SMS. Twilio: Rs 0.50+ per SMS", notes: "MSG91 is cheapest for India. Twilio for international. Both support OTP templates." },
  );
  if (input.notificationChannels.push) providers.push(
    { channel: "Push Notifications", provider: "Firebase Cloud Messaging (FCM)", cost: "FREE (unlimited)", notes: "FCM is free for unlimited push notifications. Works on Android, iOS, and web. Industry standard." },
  );
  if (input.notificationChannels.whatsapp) providers.push(
    { channel: "WhatsApp", provider: "WhatsApp Business API via Interakt / Gupshup / Twilio", cost: "Utility msgs: Rs 0.35/msg. Marketing: Rs 0.75/msg + platform fee Rs 1,000-5,000/mo", notes: "Interakt is cheapest for India. Gupshup for scale. Need Meta Business verification (takes 2-4 weeks)." },
  );
  if (providers.length === 0) providers.push(
    { channel: "None selected", provider: "—", cost: "Rs 0", notes: "Add notification channels in Step 3 if needed later." },
  );
  return { providers };
}

function getMaintenance(input: PlanInput): MaintenancePlan {
  const monthly = [
    "Security patches for OS and packages (apt update, npm audit fix)",
    "SSL certificate renewal check (Let's Encrypt auto-renews, but verify)",
    "Database vacuum and reindex (PostgreSQL maintenance)",
    "Review error logs and fix recurring issues",
    "Disk space check and cleanup (logs, temp files, old backups)",
    "Backup restoration test (restore to staging, verify data integrity)",
  ];
  const quarterly = [
    "Dependency updates (npm update, review changelogs for breaking changes)",
    "Performance review (slow queries, page load times, API latency)",
    "Security review (OWASP checklist, check for known vulnerabilities)",
    "Review and optimize cloud costs (right-size servers, remove unused resources)",
    "User feedback review and minor improvements",
  ];
  const annual = [
    "Major version upgrades (Node.js, Next.js, PostgreSQL)",
    "Full security audit (penetration test for sensitive apps)",
    "Disaster recovery drill (full restore from backup, verify RTO/RPO)",
    "Infrastructure capacity review (do we need to scale up?)",
    "License and subscription review",
    "Documentation update (architecture, runbook, API docs)",
  ];

  if (input.maintenanceContract) {
    monthly.push("Monthly status report to client", "SLA compliance review");
    quarterly.push("Quarterly business review meeting with client");
  }

  const cost = input.scale === "enterprise" ? "Rs 1.5L - 4L/month" :
    input.scale === "large" ? "Rs 50K - 1.5L/month" :
    input.scale === "medium" ? "Rs 20K - 50K/month" :
    input.scale === "small" ? "Rs 10K - 25K/month" : "Rs 5K - 15K/month";

  return { monthlyTasks: monthly, quarterlyTasks: quarterly, annualTasks: annual, annualCost: cost };
}

function getScalabilityRoadmap(input: PlanInput): ScalabilityRoadmap {
  return { triggers: [
    { when: "CPU consistently > 70% for 1 week", action: "Add more app server instances or upgrade CPU", cost: "Rs 2,000-5,000/mo per server" },
    { when: "Database query time > 500ms average", action: "Add read replica + review indexes + add Redis caching", cost: "Rs 3,000-8,000/mo for replica" },
    { when: "RAM usage > 80% consistently", action: "Upgrade server RAM or add connection pooling (PgBouncer)", cost: "Rs 1,000-3,000/mo upgrade" },
    { when: "Disk usage > 75%", action: "Expand storage or archive old data to cold storage (S3)", cost: "Rs 500-2,000/mo" },
    { when: "Concurrent users > current × 2", action: "Add load balancer + additional app servers", cost: "Rs 5,000-15,000/mo" },
    { when: "API response time > 1 second (P99)", action: "Add Redis caching layer for hot queries", cost: "Rs 2,000-4,000/mo for Redis server" },
    { when: "Background jobs backing up", action: "Add message queue (Redis Streams → RabbitMQ → Kafka)", cost: "Rs 2,000-8,000/mo" },
    { when: "Search queries slow or complex", action: "Add Elasticsearch for full-text search", cost: "Rs 3,000-8,000/mo" },
    { when: "Need 99.99% uptime", action: "Add failover replica, multi-zone deployment, automated health checks", cost: "2× infrastructure cost" },
    { when: "Multiple teams deploying to same codebase", action: "Consider splitting into microservices for independent deployment", cost: "Significant architecture effort" },
  ]};
}

function getGoLiveChecklist(input: PlanInput): GoLiveChecklist {
  const items: GoLiveChecklist["items"] = [
    // Security
    { category: "Security", item: "SSL/TLS certificate installed and working (check expiry)" },
    { category: "Security", item: "All default passwords changed (database, admin panel, server)" },
    { category: "Security", item: "Firewall rules configured (only 80, 443, 22 open)" },
    { category: "Security", item: "Environment variables secured (not in code, not in Git)" },
    { category: "Security", item: "SQL injection and XSS protection verified" },
    { category: "Security", item: "Rate limiting enabled on all API endpoints" },
    // Database
    { category: "Database", item: "Production database created with correct permissions" },
    { category: "Database", item: "All migrations run successfully" },
    { category: "Database", item: "Automated backups configured and tested" },
    { category: "Database", item: "Database connection pool sized correctly" },
    // Application
    { category: "Application", item: "Environment variables set for production (API keys, secrets)" },
    { category: "Application", item: "Error tracking configured (Sentry or similar)" },
    { category: "Application", item: "Logging configured (not verbose, not silent)" },
    { category: "Application", item: "PM2 / process manager configured with cluster mode" },
    { category: "Application", item: "Build completes without errors or warnings" },
    // Infrastructure
    { category: "Infrastructure", item: "DNS configured and propagated" },
    { category: "Infrastructure", item: "CDN configured for static assets" },
    { category: "Infrastructure", item: "nginx reverse proxy configured with gzip" },
    { category: "Infrastructure", item: "Server time synced (NTP)" },
    // Monitoring
    { category: "Monitoring", item: "Uptime monitoring configured (UptimeRobot / Pingdom)" },
    { category: "Monitoring", item: "Alert notifications configured (email / Slack / phone)" },
    { category: "Monitoring", item: "Server resource monitoring active" },
    // Testing
    { category: "Testing", item: "All critical user flows tested in production" },
    { category: "Testing", item: "Load test completed (minimum 2× expected peak)" },
    { category: "Testing", item: "Mobile responsiveness verified on real devices" },
    { category: "Testing", item: "Payment flow tested with real (small amount) transaction" },
    // Process
    { category: "Process", item: "Rollback plan documented (how to revert if things break)" },
    { category: "Process", item: "On-call contact list defined for first 48 hours" },
    { category: "Process", item: "Client sign-off obtained on UAT" },
    { category: "Process", item: "User documentation / training materials ready" },
  ];

  if (input.isFinancial) {
    items.push({ category: "Compliance", item: "PCI-DSS self-assessment questionnaire completed (if handling cards)" });
    items.push({ category: "Compliance", item: "Audit trail enabled for all financial transactions" });
  }
  if (input.replacingExisting) {
    items.push({ category: "Migration", item: "Data migration validated (row counts, checksums match)" });
    items.push({ category: "Migration", item: "Old system kept running in parallel for rollback period" });
    items.push({ category: "Migration", item: "Redirect/DNS cutover plan documented" });
  }
  return { items };
}

function getPerformanceTargets(input: PlanInput): PerformanceTargets {
  return { targets: [
    { metric: "Page Load Time", target: "< 2 seconds (First Contentful Paint)", how: "CDN for static assets, server-side rendering, image optimization, code splitting" },
    { metric: "Time to Interactive", target: "< 3.5 seconds on 4G mobile", how: "Lazy loading, minimal JavaScript, progressive hydration" },
    { metric: "API Response Time (P50)", target: "< 100ms for simple queries", how: "Redis caching, database indexing, connection pooling" },
    { metric: "API Response Time (P99)", target: "< 500ms even under load", how: "Load balancing, query optimization, async processing for heavy operations" },
    { metric: "Database Query Time", target: "< 50ms for indexed queries", how: "Proper indexes, EXPLAIN ANALYZE on slow queries, connection pooling (PgBouncer)" },
    { metric: "Uptime", target: input.uptimeRequirement ? `${input.uptimeRequirement}%` : "99.9%", how: "Health checks, auto-restart (PM2), monitoring alerts, documented runbook" },
    { metric: "Error Rate", target: "< 0.1% of requests", how: "Error tracking (Sentry), alerting on spikes, automated test suite" },
    { metric: "Concurrent Users", target: `Support ${input.scale === "tiny" ? "50" : input.scale === "small" ? "200" : input.scale === "medium" ? "2,000" : "10,000+"}+ concurrent`, how: "PM2 cluster mode, connection pooling, Redis caching, load balancing" },
    { metric: "Core Web Vitals (LCP)", target: "< 2.5 seconds", how: "Optimize largest element (hero image/text), preload critical resources" },
    { metric: "Core Web Vitals (CLS)", target: "< 0.1", how: "Set image dimensions, avoid dynamic content injection above the fold" },
  ]};
}

function getTechAlternatives(input: PlanInput): TechAlternatives {
  return { alternatives: [
    { layer: "Frontend", primary: input.frontendTech.split("(")[0].trim(), alternativeA: "Remix (React-based, nested routing)", alternativeB: "SvelteKit (lighter, faster builds)", when: "If Next.js feels too heavy or you want simpler data loading patterns" },
    { layer: "Backend Runtime", primary: "Node.js", alternativeA: "Go (2-5x faster, lower memory)", alternativeB: "Python (FastAPI — great for AI/ML heavy)", when: "Go for high-throughput APIs. Python if AI/ML is the core feature." },
    { layer: "Database", primary: "PostgreSQL", alternativeA: "MySQL 8 (simpler, good enough for most)", alternativeB: "MongoDB (if schema is truly flexible/unknown)", when: "MySQL if team knows it better. MongoDB only if data structure varies wildly per record." },
    { layer: "Cache", primary: "Redis", alternativeA: "Memcached (simpler, multi-threaded)", alternativeB: "KeyDB (Redis-compatible, multi-threaded)", when: "Memcached for simple key-value caching. KeyDB as Redis drop-in with better multi-core usage." },
    { layer: "Message Queue", primary: input.queueTech || "Redis Streams", alternativeA: "RabbitMQ (complex routing, guaranteed delivery)", alternativeB: "Apache Kafka (event streaming, replay)", when: "RabbitMQ for task queues. Kafka for event sourcing and analytics pipelines." },
    { layer: "Search", primary: "Elasticsearch", alternativeA: "Meilisearch (simpler, great for typo-tolerant)", alternativeB: "PostgreSQL full-text search (no extra service)", when: "Meilisearch for smaller datasets with great UX. PG full-text if you want to avoid another service." },
    { layer: "Hosting", primary: input.deployment === "cloud" ? "AWS" : "Hetzner VPS", alternativeA: "DigitalOcean (simple, good UI)", alternativeB: "Railway / Render (zero-config deploy)", when: "DigitalOcean for simplicity. Railway/Render for startups who don't want to manage servers." },
    { layer: "Mobile", primary: "React Native", alternativeA: "Flutter (better UI consistency)", alternativeB: "Capacitor (wrap web app as native)", when: "Flutter for pixel-perfect custom UI. Capacitor to quickly wrap an existing web app." },
    { layer: "CI/CD", primary: "GitHub Actions", alternativeA: "GitLab CI (if using GitLab)", alternativeB: "Jenkins (self-hosted, maximum control)", when: "GitLab CI if repo is on GitLab. Jenkins only if you need complex pipelines with custom plugins." },
    { layer: "Monitoring", primary: "Prometheus + Grafana", alternativeA: "Datadog (all-in-one, paid)", alternativeB: "New Relic (free tier is generous)", when: "Datadog if budget allows and you want one tool. New Relic free tier for startups." },
  ]};
}

function getYearProjection(input: PlanInput): YearProjection {
  const infra = input.scale === "enterprise" ? [40, 48, 58] : input.scale === "large" ? [12, 15, 18] : input.scale === "medium" ? [3, 3.6, 4.3] : input.scale === "small" ? [0.6, 0.72, 0.86] : [0.18, 0.22, 0.26];
  const maint = input.scale === "enterprise" ? [30, 32, 35] : input.scale === "large" ? [12, 14, 16] : input.scale === "medium" ? [4, 5, 6] : input.scale === "small" ? [1.8, 2.2, 2.5] : [0.6, 0.8, 1];
  const lic = input.scale === "enterprise" ? [8, 9, 10] : input.scale === "large" ? [2, 2.5, 3] : input.scale === "medium" ? [0.5, 0.6, 0.7] : [0, 0, 0];

  const fmt = (v: number) => v >= 1 ? `Rs ${v}L` : `Rs ${Math.round(v * 100) / 100}L`;
  return { years: [
    { year: "Year 1", infrastructure: fmt(infra[0]), maintenance: fmt(maint[0]), licensing: fmt(lic[0]), total: fmt(infra[0] + maint[0] + lic[0]) },
    { year: "Year 2 (est. +20%)", infrastructure: fmt(infra[1]), maintenance: fmt(maint[1]), licensing: fmt(lic[1]), total: fmt(infra[1] + maint[1] + lic[1]) },
    { year: "Year 3 (est. +20%)", infrastructure: fmt(infra[2]), maintenance: fmt(maint[2]), licensing: fmt(lic[2]), total: fmt(infra[2] + maint[2] + lic[2]) },
  ]};
}

function getComplianceChecklist(input: PlanInput): ComplianceChecklist {
  const items: ComplianceChecklist["items"] = [
    { requirement: "Data encryption at rest (AES-256)", status: "Required", action: "Enable PostgreSQL encryption, encrypt file storage" },
    { requirement: "Data encryption in transit (TLS 1.3)", status: "Required", action: "SSL certificate via Let's Encrypt / Cloudflare" },
    { requirement: "Access logging / audit trail", status: input.isFinancial || input.isGovernment ? "Mandatory" : "Recommended", action: "Log all data access and modifications with timestamp + user ID" },
    { requirement: "Password hashing (bcrypt/argon2)", status: "Required", action: "Never store plain-text passwords. Use bcrypt with cost factor 12+" },
    { requirement: "Input validation / sanitization", status: "Required", action: "Validate all user input server-side. Prevent SQL injection and XSS." },
    { requirement: "Privacy policy / terms of service", status: "Required", action: "Draft and display privacy policy. Required by law for collecting personal data." },
    { requirement: "Data backup and recovery procedure", status: "Required", action: "Automated backups + tested restoration procedure" },
  ];

  if (input.isFinancial) {
    items.push({ requirement: "PCI-DSS compliance (if handling cards directly)", status: "Mandatory", action: "Use Razorpay/Stripe to avoid direct card handling. Complete SAQ-A if using hosted checkout." });
    items.push({ requirement: "RBI data localization (for payment data)", status: "Mandatory", action: "All payment data must be stored on servers in India. Use ap-south-1 (Mumbai) region." });
    items.push({ requirement: "Transaction audit trail (immutable)", status: "Mandatory", action: "Append-only transaction log. No delete/update on financial records." });
    items.push({ requirement: "Two-factor authentication for admin", status: "Mandatory", action: "OTP via SMS/email for all admin actions" });
  }
  if (input.isGovernment) {
    items.push({ requirement: "IT Act 2000 compliance", status: "Mandatory", action: "Data retention, access controls, audit logs as per IT Act requirements" });
    items.push({ requirement: "CERT-In incident reporting", status: "Mandatory", action: "Report security incidents to CERT-In within 6 hours" });
    items.push({ requirement: "Data localization (servers in India)", status: "Mandatory", action: "All servers and backups must be in India" });
  }
  if (input.industry === "healthcare") {
    items.push({ requirement: "Health data protection (DISHA bill)", status: "Recommended", action: "Encrypt health records, strict access controls, consent management" });
    items.push({ requirement: "Patient data anonymization for analytics", status: "Recommended", action: "Remove PII before running analytics or sharing data" });
  }
  if (input.dataType === "sensitive") {
    items.push({ requirement: "DPDP Act 2023 (Digital Personal Data Protection)", status: "Mandatory", action: "Consent collection, data processing purpose limitation, breach notification, data erasure on request" });
  }

  return { items };
}

function getTrainingPlan(input: PlanInput): TrainingPlan {
  const sessions: TrainingPlan["sessions"] = [];

  if (input.trainingNeeded) {
    sessions.push({ audience: "End Users", topic: "Application walkthrough — all features, workflows, and shortcuts", duration: "2-3 hours", format: "Live demo + recorded video" });
    sessions.push({ audience: "End Users", topic: "Common tasks: data entry, search, reports, exports", duration: "1-2 hours", format: "Hands-on workshop" });
    sessions.push({ audience: "Admin Users", topic: "Admin panel: user management, settings, permissions, data management", duration: "2 hours", format: "Live demo + documentation" });
    sessions.push({ audience: "Admin Users", topic: "Troubleshooting: common issues, error messages, who to contact", duration: "1 hour", format: "FAQ document + walkthrough" });
  }

  if (input.scale !== "tiny") {
    sessions.push({ audience: "IT Team / Developer", topic: "System architecture, deployment procedure, server access", duration: "3-4 hours", format: "Technical documentation + live session" });
    sessions.push({ audience: "IT Team / Developer", topic: "Monitoring dashboard, alerting, backup/restore procedure", duration: "2 hours", format: "Runbook + hands-on" });
  }

  if (input.maintenanceContract) {
    sessions.push({ audience: "Client Stakeholders", topic: "Monthly reporting, SLA review, escalation procedure", duration: "1 hour", format: "Process document + kickoff meeting" });
  }

  if (sessions.length === 0) {
    sessions.push({ audience: "Self-serve", topic: "User guide document with screenshots", duration: "Self-paced", format: "PDF / web-based documentation" });
  }

  return { sessions };
}

function getScopeOfWork(input: PlanInput): ScopeOfWork {
  const appLabel = { web: "web application", mobile: "mobile application", both: "web + mobile application", "api-only": "backend API", desktop: "desktop application", "desktop-web": "desktop + web application" }[input.appType] || "application";

  const inScope: string[] = [
    `Design, develop, test, and deploy a ${appLabel}`,
    "Database design, setup, and initial data migration",
    "User authentication and role-based access control",
    "Admin panel for system management",
    `Deployment to ${input.deployment === "cloud" ? "cloud infrastructure" : input.deployment === "self-hosted" ? "self-hosted VPS" : input.deployment === "on-premise" ? "on-premise servers" : "hybrid infrastructure"}`,
    "Post-launch support during hypercare period",
    "Technical documentation (architecture, API, runbook)",
  ];
  if (input.hasPayments) inScope.push("Payment gateway integration (Razorpay / Stripe)");
  if (input.hasRealTime) inScope.push("Real-time features (WebSocket / Server-Sent Events)");
  if (input.hasSearch) inScope.push("Full-text search implementation (Elasticsearch / PostgreSQL FTS)");
  if (input.hasAI) inScope.push("AI feature integration (Gemini / Claude API)");
  if (input.hasFileUploads) inScope.push("File upload and storage system");
  if (input.hasMultiTenant) inScope.push("Multi-tenant architecture with data isolation");
  if (input.trainingNeeded) inScope.push("End-user and admin training sessions");
  if (input.maintenanceContract) inScope.push("Post-launch maintenance contract (SLA-based)");

  const outOfScope: string[] = [
    "Content creation (text, images, marketing material) — client responsibility",
    "Third-party service costs (hosting, API subscriptions, domain, SSL)",
    "Hardware procurement (if on-premise)",
    "Legal/regulatory compliance certification (we build compliant, but certification is client's responsibility)",
    "SEO/marketing campaigns",
    "Features not documented in the approved requirements document",
  ];
  if (!input.hasPayments) outOfScope.push("Payment processing integration");
  if (!input.trainingNeeded) outOfScope.push("End-user training sessions");

  const assumptions: string[] = [
    "Client will provide timely feedback within 5 business days of each review cycle",
    "Client will provide all required content, logos, and brand guidelines before design phase",
    "Client has or will procure necessary third-party service accounts (hosting, domain, APIs)",
    "Requirements are finalized before development begins — changes go through Change Request process",
    "Client team is available for UAT during the designated testing window",
  ];
  if (input.replacingExisting) assumptions.push("Client will provide access to existing system and database for data migration analysis");

  const constraints: string[] = [
    `Budget: ${input.budget}`,
    `Timeline: ${input.timeline} to first release`,
    `Team size: ${input.teamSize}`,
  ];
  if (input.industry === "fintech" || input.isFinancial) constraints.push("Must comply with RBI data localization — all financial data stored in India");
  if (input.isGovernment) constraints.push("Must comply with IT Act 2000 and CERT-In requirements");
  if (input.uptimeRequirement) constraints.push(`Uptime SLA: ${input.uptimeRequirement}%`);

  return { inScope, outOfScope, assumptions, constraints };
}

function getCommunicationPlan(input: PlanInput): CommunicationPlan {
  const isSmall = input.scale === "tiny" || input.scale === "small";
  const isMedium = input.scale === "medium";

  const meetings = isSmall ? [
    { type: "Kickoff Meeting", frequency: "Once (project start)", attendees: "Developer + Client", purpose: "Align on scope, timeline, and expectations" },
    { type: "Progress Update", frequency: "Weekly (WhatsApp / call)", attendees: "Developer + Client", purpose: "Demo progress, collect feedback, unblock issues" },
    { type: "UAT Review", frequency: "Once (before launch)", attendees: "Developer + Client + end users", purpose: "Walk through all features, collect sign-off" },
    { type: "Handover Meeting", frequency: "Once (after launch)", attendees: "Developer + Client", purpose: "Training, documentation review, support process" },
  ] : isMedium ? [
    { type: "Kickoff Meeting", frequency: "Once (project start)", attendees: "Full team + Client stakeholders", purpose: "Align scope, roles, timeline, communication norms" },
    { type: "Sprint Demo", frequency: "Every 2 weeks", attendees: "Team + Client PM", purpose: "Demo completed features, get feedback, plan next sprint" },
    { type: "Standup (internal)", frequency: "Daily (15 min)", attendees: "Dev team", purpose: "What I did, what I'll do, blockers" },
    { type: "Stakeholder Update", frequency: "Bi-weekly (email/report)", attendees: "Client leadership", purpose: "Budget status, timeline adherence, risk summary" },
    { type: "UAT Sessions", frequency: "2-3 sessions before launch", attendees: "Team + Client testers", purpose: "End-to-end testing, bug triage, acceptance" },
    { type: "Retrospective", frequency: "End of each phase", attendees: "Full team", purpose: "What went well, what to improve" },
  ] : [
    { type: "Kickoff & Strategy", frequency: "Once (2-4 hours)", attendees: "Architect + PM + Client CTO/CIO", purpose: "Architecture decisions, risk assessment, governance model" },
    { type: "Sprint Planning", frequency: "Every 2 weeks", attendees: "Team leads + PM", purpose: "Backlog grooming, sprint goal setting, capacity planning" },
    { type: "Sprint Demo", frequency: "Every 2 weeks", attendees: "Full team + Client stakeholders", purpose: "Feature demos, feedback collection, priority adjustments" },
    { type: "Daily Standup", frequency: "Daily (15 min)", attendees: "Dev team", purpose: "Progress, blockers, coordination" },
    { type: "Steering Committee", frequency: "Monthly", attendees: "PM + Client leadership + Architect", purpose: "Budget review, timeline status, strategic decisions, risk escalation" },
    { type: "Technical Review", frequency: "End of each phase", attendees: "Architect + Senior devs", purpose: "Code quality, architecture compliance, tech debt assessment" },
    { type: "Security Review", frequency: "Before UAT + before go-live", attendees: "Security lead + Architect", purpose: "Vulnerability assessment, compliance verification" },
    { type: "Go-Live War Room", frequency: "Go-live day (24-48 hours)", attendees: "Full team on standby", purpose: "Real-time monitoring, instant issue resolution" },
  ];

  const escalationPath = isSmall
    ? ["Issue raised by client → Developer acknowledges within 4 hours → Resolved within 24 hours (non-critical) or 4 hours (critical)"]
    : [
      "Level 1: Developer/QA → resolves within 4 hours (bugs, minor issues)",
      "Level 2: Tech Lead → resolves within 8 hours (architecture, integration issues)",
      "Level 3: PM + Client PM → resolves within 24 hours (scope, timeline, budget decisions)",
      "Level 4: Company leadership → resolves within 48 hours (contract disputes, project-level risks)",
    ];

  const tools = isSmall
    ? ["WhatsApp (daily communication)", "Email (formal decisions, scope changes)", "Google Meet / Zoom (demo calls)", "GitHub (code + issue tracking)"]
    : ["Slack / Teams (daily communication)", "Email (formal decisions, contracts)", "Zoom / Google Meet (scheduled meetings)", "GitHub / GitLab (code, PRs, issues)", "Linear / Jira (project tracking)", "Google Drive / Notion (documentation)"];

  return { meetings, escalationPath, tools };
}

function getTestingStrategy(input: PlanInput): TestingStrategy {
  const isSmall = input.scale === "tiny" || input.scale === "small";

  const types: TestingStrategy["types"] = [
    { type: "Unit Testing", tool: "Jest / Vitest", coverage: isSmall ? "Critical paths (60%+)" : "All business logic (80%+)", when: "During development (every PR)" },
    { type: "Integration Testing", tool: "Supertest / Playwright", coverage: "All API endpoints + DB operations", when: "After each feature completion" },
    { type: "End-to-End (E2E)", tool: "Playwright / Cypress", coverage: "Critical user flows (login, CRUD, payment)", when: "Before each release" },
    { type: "Manual / Exploratory", tool: "Human testers", coverage: "UI/UX, edge cases, real-device testing", when: "UAT phase" },
  ];

  if (input.hasPayments) types.push({ type: "Payment Flow Testing", tool: "Razorpay test mode + manual verification", coverage: "All payment paths: success, failure, refund, partial", when: "Before UAT + before go-live" });
  if (!isSmall) types.push({ type: "Load / Performance Testing", tool: "k6 / Artillery", coverage: `Simulate ${input.scale === "enterprise" ? "5x" : "2-3x"} expected peak traffic`, when: "Before go-live" });
  if (input.isFinancial || input.isGovernment) types.push({ type: "Security / Penetration Testing", tool: "OWASP ZAP / Burp Suite / manual audit", coverage: "OWASP Top 10, SQL injection, XSS, CSRF, auth bypass", when: "Before UAT + annually" });
  if (!isSmall) types.push({ type: "Regression Testing", tool: "Automated test suite (CI)", coverage: "All previously passing tests must continue passing", when: "Every deployment (automated)" });
  if (input.scale === "large" || input.scale === "enterprise") types.push({ type: "Disaster Recovery Testing", tool: "Manual failover drill", coverage: "Backup restore, replica promotion, DNS failover", when: "Before go-live + quarterly" });

  const qualityGates: string[] = [
    "No critical or high-severity bugs in production release",
    `Test coverage: minimum ${isSmall ? "60" : "80"}% for business logic`,
    "All E2E tests passing on staging before production deploy",
    "Performance: page load < 3s, API response < 500ms (P99)",
    "Security: zero known vulnerabilities (npm audit, OWASP scan)",
  ];
  if (input.hasPayments) qualityGates.push("Payment flow: 100% tested with test cards (success, failure, refund)");
  if (!isSmall) qualityGates.push("Load test: system stable at 2x expected peak with < 1% error rate");

  return { types, qualityGates };
}

function getAcceptanceCriteria(input: PlanInput): AcceptanceCriteria {
  const criteria: AcceptanceCriteria["criteria"] = [
    { area: "Functionality", criterion: "All features listed in approved scope document are working as specified", verifiedBy: "Client UAT team" },
    { area: "Performance", criterion: "Page loads < 3 seconds, API responses < 500ms under normal load", verifiedBy: "Load test report" },
    { area: "Security", criterion: "No critical/high vulnerabilities in security scan; SSL, auth, and data encryption working", verifiedBy: "Security audit report" },
    { area: "Data", criterion: "All migrated data is accurate and complete (row counts and checksums verified)", verifiedBy: "Client data team + automated checks" },
    { area: "Browser/Device", criterion: "Works on Chrome, Safari, Firefox (latest), iOS Safari, Android Chrome", verifiedBy: "Manual cross-browser testing" },
    { area: "Documentation", criterion: "User manual, admin guide, API documentation, and runbook delivered", verifiedBy: "Client review" },
    { area: "Training", criterion: "All training sessions completed and recorded", verifiedBy: "Client confirmation" },
  ];

  if (input.hasPayments) criteria.push({ area: "Payments", criterion: "Successful test transactions on all payment methods; refund flow verified", verifiedBy: "Client finance team" });
  if (input.isFinancial || input.isGovernment) criteria.push({ area: "Compliance", criterion: "All mandatory compliance items checked and evidenced", verifiedBy: "Compliance officer / auditor" });
  if (input.scale !== "tiny") criteria.push({ area: "Monitoring", criterion: "Uptime monitoring, error tracking, and alerting configured and verified", verifiedBy: "Ops team / developer" });

  const signoffProcess = input.scale === "tiny" || input.scale === "small"
    ? "Client reviews all features during UAT session → provides written approval (email/WhatsApp) → go-live within 48 hours of sign-off. Any bugs found post-sign-off are handled under warranty (30 days)."
    : "1. Client UAT team tests all features against acceptance criteria (5-10 business days). 2. Bug report submitted and triaged (critical: fix before sign-off, minor: fix in first maintenance cycle). 3. Client PM provides formal written sign-off (email or signed document). 4. Go-live scheduled within 1 week of sign-off. 5. 30-day warranty period for bug fixes at no additional cost.";

  return { criteria, signoffProcess };
}

function getChangeRequestProcess(input: PlanInput): ChangeRequestProcess {
  const isSmall = input.scale === "tiny" || input.scale === "small";

  const steps = isSmall ? [
    { step: "Client describes the change (WhatsApp / email)", owner: "Client", sla: "Anytime" },
    { step: "Developer assesses impact on timeline and cost", owner: "Developer", sla: "Within 24 hours" },
    { step: "Developer sends revised quote (if cost impact)", owner: "Developer", sla: "Within 48 hours" },
    { step: "Client approves or withdraws the request", owner: "Client", sla: "Within 5 business days" },
    { step: "Work begins after written approval received", owner: "Developer", sla: "Next sprint / immediately" },
  ] : [
    { step: "Change Request submitted (email / ticket system)", owner: "Client PM", sla: "Anytime" },
    { step: "Tech Lead assesses technical impact (effort, risk, dependencies)", owner: "Tech Lead", sla: "Within 2 business days" },
    { step: "PM prepares impact analysis (timeline + cost + risk)", owner: "Project Manager", sla: "Within 3 business days" },
    { step: "Impact report shared with client for review", owner: "PM → Client PM", sla: "Within 1 business day" },
    { step: "Client approves, defers, or withdraws the request", owner: "Client stakeholder", sla: "Within 5 business days" },
    { step: "Approved changes added to backlog with revised timeline", owner: "PM + Tech Lead", sla: "Next sprint planning" },
    { step: "Original sign-off document amended to reflect new scope", owner: "PM", sla: "Before work begins" },
  ];

  const pricingNote = isSmall
    ? "Changes that add more than 2 days of work will be quoted separately. Minor tweaks (< 2 hours) included at no extra cost during active development. Post-launch changes are billed at the agreed maintenance rate."
    : "All changes are categorized: Minor (< 1 day effort, absorbed into current sprint), Moderate (1-5 days, quoted separately), Major (> 5 days, requires revised SOW and timeline). Emergency changes (production-critical) are prioritized but billed at 1.5x rate.";

  return { steps, pricingNote };
}

function getRACIMatrix(input: PlanInput): RACIMatrix {
  const isSmall = input.scale === "tiny" || input.scale === "small";

  if (isSmall) return { rows: [
    { activity: "Requirements & Scope", responsible: "Developer", accountable: "Client", consulted: "End users", informed: "—" },
    { activity: "UI/UX Design", responsible: "Developer", accountable: "Client", consulted: "End users", informed: "—" },
    { activity: "Development", responsible: "Developer", accountable: "Developer", consulted: "Client", informed: "Client" },
    { activity: "Testing & QA", responsible: "Developer", accountable: "Developer", consulted: "Client (UAT)", informed: "Client" },
    { activity: "Deployment", responsible: "Developer", accountable: "Developer", consulted: "—", informed: "Client" },
    { activity: "Sign-off & Acceptance", responsible: "Client", accountable: "Client", consulted: "Developer", informed: "End users" },
    { activity: "Content & Data", responsible: "Client", accountable: "Client", consulted: "Developer", informed: "—" },
    { activity: "Training", responsible: "Developer", accountable: "Client", consulted: "End users", informed: "—" },
    { activity: "Maintenance & Support", responsible: "Developer", accountable: "Developer", consulted: "Client", informed: "Client" },
  ]};

  return { rows: [
    { activity: "Project Charter & SOW", responsible: "PM", accountable: "Client Sponsor", consulted: "Architect, Client PM", informed: "Full team" },
    { activity: "Architecture & Tech Decisions", responsible: "Architect", accountable: "Tech Lead", consulted: "Senior devs, Client CTO", informed: "PM, Client PM" },
    { activity: "UI/UX Design", responsible: "Designer", accountable: "PM", consulted: "Client PM, End users", informed: "Developers" },
    { activity: "Sprint Planning", responsible: "Tech Lead", accountable: "PM", consulted: "Developers, Client PM", informed: "Client Sponsor" },
    { activity: "Development", responsible: "Developers", accountable: "Tech Lead", consulted: "Architect", informed: "PM, Client PM" },
    { activity: "Code Review", responsible: "Senior Developer", accountable: "Tech Lead", consulted: "Architect", informed: "Developer (author)" },
    { activity: "QA & Testing", responsible: "QA Engineer", accountable: "Tech Lead", consulted: "Developers", informed: "PM, Client PM" },
    { activity: "Security Review", responsible: "Architect / Security Lead", accountable: "Tech Lead", consulted: "DevOps", informed: "PM, Client" },
    { activity: "Deployment & DevOps", responsible: "DevOps", accountable: "Tech Lead", consulted: "Developers", informed: "PM, Client PM" },
    { activity: "UAT & Sign-off", responsible: "Client UAT team", accountable: "Client PM", consulted: "QA, Developer", informed: "PM, Client Sponsor" },
    { activity: "Go-Live Decision", responsible: "PM", accountable: "Client Sponsor", consulted: "Tech Lead, QA", informed: "Full team" },
    { activity: "Budget & Timeline Decisions", responsible: "PM", accountable: "Client Sponsor", consulted: "Tech Lead, Client PM", informed: "Full team" },
    { activity: "Change Requests", responsible: "PM", accountable: "Client Sponsor", consulted: "Tech Lead, Client PM", informed: "Developers" },
    { activity: "Post-launch Maintenance", responsible: "Support Dev", accountable: "PM", consulted: "Original developers", informed: "Client PM" },
  ]};
}

function getWhatsAppSummary(input: PlanInput): WhatsAppSummary {
  const appTypeLabel = { web: "Web Application", mobile: "Mobile App", both: "Web + Mobile App", "api-only": "Backend API", desktop: "Desktop Application", "desktop-web": "Desktop + Web App" }[input.appType] || "Application";
  const scaleLabel = input.scale === "tiny" ? "Small" : input.scale === "small" ? "Small-Medium" : input.scale === "medium" ? "Medium" : input.scale === "large" ? "Large" : "Enterprise";

  const clientLine = input.clientName ? ` for ${input.clientName}` : "";
  const projectLine = input.projectName ? `\n*Project:* ${input.projectName}` : "";

  const text = `*📋 Project Proposal${clientLine} — ${appTypeLabel}*
━━━━━━━━━━━━━━━━━━━━━━
${projectLine}
*Type:* ${appTypeLabel}
*Scale:* ${scaleLabel}
*Platform:* ${input.platform || "Web"}

*Tech Stack:*
• Frontend: ${input.frontendTech.split("(")[0].trim()}
• Backend: ${input.backendTech.split("(")[0].trim()}
• Database: ${input.dbTech.split("(")[0].trim()}
${input.queueTech ? `• Queue: ${input.queueTech.split("(")[0].trim()}` : ""}

*Infrastructure:*
• Hosting: ${input.deployment === "cloud" ? "Cloud (AWS/GCP)" : input.deployment === "self-hosted" ? "Self-hosted VPS" : input.deployment === "on-premise" ? "On-premise" : "Hybrid"}
• Region: ${input.geoReach === "india" ? "India" : input.geoReach === "global" ? "Global" : input.geoReach}

*Estimated Timeline:* ${input.timeline}
*Team Size:* ${input.teamSize}

*All technologies are open-source (zero licensing cost)*

_Prepared by AREA KPI Technology_
_+919819800214 | areakpi.in_`;

  return { text };
}

