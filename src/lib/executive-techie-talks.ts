import { PowerCheckItem } from "./power-checks";

// 200 technical jargon tips — what the term means in plain English + when to use it
export const techieTalksTips: PowerCheckItem[] = [
  // --- Legacy & Foundational Tech ---
  { id: "tt-1", label: "Tech term: COBOL — a 60-year-old language that STILL runs 95% of ATM transactions and 80% of in-person banking. Banks can't replace it. Say: 'Even COBOL systems need modernization layers.'", theme: "techie-talks" },
  { id: "tt-2", label: "Tech term: Mainframe — massive, ultra-reliable computers that handle millions of transactions. Banks, airlines, governments use them. Say: 'Mainframe-grade reliability is our benchmark.'", theme: "techie-talks" },
  { id: "tt-3", label: "Tech term: Monolith — one big application where everything is connected. Easy to start, hard to scale. Say: 'We should break this monolith into services.'", theme: "techie-talks" },
  { id: "tt-4", label: "Tech term: SOAP — older web service protocol, heavy XML-based. Still used in banking/insurance. Say: 'We'll wrap the legacy SOAP service with a modern REST API.'", theme: "techie-talks" },
  { id: "tt-5", label: "Tech term: REST API — the modern standard for systems talking to each other over HTTP. Clean, simple, JSON-based. Say: 'We expose a RESTful API for integration.'", theme: "techie-talks" },
  { id: "tt-6", label: "Tech term: SQL — Structured Query Language. The language to talk to databases. 50+ years old and still dominant. Say: 'The data is queryable via standard SQL.'", theme: "techie-talks" },
  { id: "tt-7", label: "Tech term: Stored Procedure — pre-compiled SQL code stored in the database. Fast but hard to maintain. Legacy systems love them. Say: 'We can optimize with stored procedures for critical paths.'", theme: "techie-talks" },
  { id: "tt-8", label: "Tech term: FTP — File Transfer Protocol. Ancient but still used to transfer files between servers. Say: 'We'll replace the FTP workflow with a secure API upload.'", theme: "techie-talks" },
  { id: "tt-9", label: "Tech term: Batch Processing — processing large volumes of data in scheduled chunks (nightly, hourly). Banks do this. Say: 'The reconciliation runs as a nightly batch job.'", theme: "techie-talks" },
  { id: "tt-10", label: "Tech term: CRON job — a scheduled task that runs automatically at set times (like a daily backup at 2 AM). Say: 'We'll set up a cron job for the daily report generation.'", theme: "techie-talks" },

  // --- Modern Web Stack ---
  { id: "tt-11", label: "Tech term: React — Facebook's UI library. The most popular way to build interactive web interfaces. Say: 'The frontend is built in React for a smooth user experience.'", theme: "techie-talks" },
  { id: "tt-12", label: "Tech term: Next.js — React framework that adds server-side rendering, routing, and optimization. What this app is built on. Say: 'Next.js gives us SEO + performance out of the box.'", theme: "techie-talks" },
  { id: "tt-13", label: "Tech term: TypeScript — JavaScript with type safety. Catches bugs before they happen. Say: 'We use TypeScript for reliability — errors are caught at compile time, not in production.'", theme: "techie-talks" },
  { id: "tt-14", label: "Tech term: Node.js — JavaScript running on servers (not just browsers). Powers Netflix, LinkedIn, Uber backends. Say: 'Our backend runs on Node.js — same tech as Netflix.'", theme: "techie-talks" },
  { id: "tt-15", label: "Tech term: Tailwind CSS — utility-first CSS framework. Write styles directly in HTML. Fast development. Say: 'Tailwind lets us iterate on design 3x faster than traditional CSS.'", theme: "techie-talks" },
  { id: "tt-16", label: "Tech term: SPA (Single Page Application) — the entire app loads once, then updates dynamically. No page refreshes. Gmail is an SPA. Say: 'It's an SPA — feels like a native app.'", theme: "techie-talks" },
  { id: "tt-17", label: "Tech term: SSR (Server-Side Rendering) — HTML is generated on the server, not the browser. Faster first load, better SEO. Say: 'We use SSR for search engine optimization.'", theme: "techie-talks" },
  { id: "tt-18", label: "Tech term: SSG (Static Site Generation) — pages are pre-built at deploy time. Blazing fast. Say: 'Static pages load in under 100ms — faster than any dynamic site.'", theme: "techie-talks" },
  { id: "tt-19", label: "Tech term: PWA (Progressive Web App) — a website that behaves like a mobile app. Works offline, installable. This app is a PWA. Say: 'It's a PWA — no app store needed, works offline.'", theme: "techie-talks" },
  { id: "tt-20", label: "Tech term: Service Worker — background script that enables offline mode, push notifications, and caching. Say: 'The service worker caches everything for offline access.'", theme: "techie-talks" },

  // --- Database & Data ---
  { id: "tt-21", label: "Tech term: PostgreSQL — the world's most advanced open-source database. Powers Instagram, Spotify, NASA. Say: 'We use PostgreSQL — same database that powers Instagram.'", theme: "techie-talks" },
  { id: "tt-22", label: "Tech term: MongoDB — NoSQL document database. Good for flexible, unstructured data. Say: 'MongoDB is ideal when data structure varies — like user-generated content.'", theme: "techie-talks" },
  { id: "tt-23", label: "Tech term: Redis — ultra-fast in-memory data store. Used for caching, sessions, real-time features. Say: 'Redis caches frequent queries — response time drops from 200ms to 2ms.'", theme: "techie-talks" },
  { id: "tt-24", label: "Tech term: ORM (Object-Relational Mapping) — code that talks to databases without writing raw SQL. Prisma, Sequelize. Say: 'The ORM handles all database operations safely.'", theme: "techie-talks" },
  { id: "tt-25", label: "Tech term: Migration — versioned database changes. Like git for your database structure. Say: 'We'll run the migration to add the new columns safely.'", theme: "techie-talks" },
  { id: "tt-26", label: "Tech term: Indexing — database optimization that makes searches faster by creating lookup tables. Say: 'Adding an index on that column will speed up queries 10x.'", theme: "techie-talks" },
  { id: "tt-27", label: "Tech term: Normalization — organizing data to reduce redundancy. 1NF, 2NF, 3NF. Say: 'The database is normalized to 3NF — no duplicate data, clean structure.'", theme: "techie-talks" },
  { id: "tt-28", label: "Tech term: Denormalization — intentionally duplicating data for faster reads. Trade storage for speed. Say: 'We denormalized the dashboard queries for sub-second response.'", theme: "techie-talks" },
  { id: "tt-29", label: "Tech term: ACID — Atomicity, Consistency, Isolation, Durability. Guarantees that database transactions are reliable. Say: 'PostgreSQL is ACID-compliant — your data is always consistent.'", theme: "techie-talks" },
  { id: "tt-30", label: "Tech term: Sharding — splitting a database across multiple servers. Each shard holds a subset of data. Say: 'At scale, we'd shard by region — Mumbai data on one server, Delhi on another.'", theme: "techie-talks" },

  // --- API & Integration ---
  { id: "tt-31", label: "Tech term: API (Application Programming Interface) — how two software systems talk to each other. Say: 'We'll expose an API so your mobile app and website share the same data.'", theme: "techie-talks" },
  { id: "tt-32", label: "Tech term: GraphQL — Facebook's alternative to REST. Client asks for exactly the data it needs, nothing more. Say: 'GraphQL reduces data transfer by 40% compared to REST.'", theme: "techie-talks" },
  { id: "tt-33", label: "Tech term: Webhook — automatic notification when something happens. 'When a payment completes, our webhook notifies your system instantly.' Real-time triggers.", theme: "techie-talks" },
  { id: "tt-34", label: "Tech term: WebSocket — persistent connection for real-time data. Chat apps, live dashboards, stock tickers use this. Say: 'WebSockets give you live updates without refreshing.'", theme: "techie-talks" },
  { id: "tt-35", label: "Tech term: Middleware — code that runs BETWEEN request and response. Authentication, logging, error handling. Say: 'Our middleware validates every request before it hits the database.'", theme: "techie-talks" },
  { id: "tt-36", label: "Tech term: SDK (Software Development Kit) — pre-built tools that make integration easier. Say: 'We provide an SDK — your team can integrate in hours, not weeks.'", theme: "techie-talks" },
  { id: "tt-37", label: "Tech term: OAuth 2.0 — the standard for secure authentication. 'Sign in with Google' uses OAuth. Say: 'We use OAuth 2.0 — industry-standard security for authentication.'", theme: "techie-talks" },
  { id: "tt-38", label: "Tech term: JWT (JSON Web Token) — a secure token for authenticating users. Compact, self-contained. Say: 'Session management is JWT-based — stateless and scalable.'", theme: "techie-talks" },
  { id: "tt-39", label: "Tech term: Rate Limiting — restricting how many requests a user can make per minute. Prevents abuse. Say: 'Rate limiting protects the API from DDoS attacks and abuse.'", theme: "techie-talks" },
  { id: "tt-40", label: "Tech term: Idempotent — an operation that gives the same result no matter how many times you run it. Say: 'Our payment API is idempotent — no duplicate charges even if called twice.'", theme: "techie-talks" },

  // --- DevOps & Deployment ---
  { id: "tt-41", label: "Tech term: CI/CD — Continuous Integration/Continuous Deployment. Code is tested and deployed automatically. Say: 'Our CI/CD pipeline deploys tested code in under 5 minutes.'", theme: "techie-talks" },
  { id: "tt-42", label: "Tech term: Docker — packages your app + all its dependencies into a container. Runs the same everywhere. Say: 'Docker ensures the app works identically in dev, staging, and production.'", theme: "techie-talks" },
  { id: "tt-43", label: "Tech term: Kubernetes (K8s) — orchestrates thousands of Docker containers. Auto-scales, self-heals. Say: 'Kubernetes manages our containers — if one dies, it auto-restarts.'", theme: "techie-talks" },
  { id: "tt-44", label: "Tech term: nginx — high-performance web server and reverse proxy. Handles millions of connections. Say: 'nginx sits in front, handling SSL, load balancing, and static files.'", theme: "techie-talks" },
  { id: "tt-45", label: "Tech term: PM2 — Node.js process manager. Keeps apps running, restarts on crash, manages clusters. Say: 'PM2 ensures zero-downtime — if the process crashes, it restarts in milliseconds.'", theme: "techie-talks" },
  { id: "tt-46", label: "Tech term: SSL/TLS — encryption for data in transit. The padlock icon in browsers. Say: 'All data is encrypted with TLS 1.3 — bank-grade security.'", theme: "techie-talks" },
  { id: "tt-47", label: "Tech term: Reverse Proxy — server that sits between users and your app. Handles security, caching, load balancing. Say: 'The reverse proxy protects the application server from direct exposure.'", theme: "techie-talks" },
  { id: "tt-48", label: "Tech term: Blue-Green Deployment — two identical environments. Deploy to green, test, then switch traffic from blue to green. Zero downtime. Say: 'Blue-green deployment means zero downtime during updates.'", theme: "techie-talks" },
  { id: "tt-49", label: "Tech term: Canary Release — deploy to 5% of users first, monitor, then gradually increase. Say: 'We'll canary this release — 5% first, then full rollout if metrics are green.'", theme: "techie-talks" },
  { id: "tt-50", label: "Tech term: Infrastructure as Code (IaC) — manage servers with code files instead of manual setup. Terraform, Ansible. Say: 'Our infrastructure is version-controlled — every server change is tracked.'", theme: "techie-talks" },

  // --- Cloud & Infrastructure ---
  { id: "tt-51", label: "Tech term: AWS — Amazon Web Services. The biggest cloud platform. Powers Netflix, Airbnb, NASA. Say: 'AWS gives us global infrastructure with pay-as-you-go pricing.'", theme: "techie-talks" },
  { id: "tt-52", label: "Tech term: EC2 — AWS virtual servers. You rent computing power by the hour. Say: 'We run on EC2 instances — scalable from 1 to 1000 servers in minutes.'", theme: "techie-talks" },
  { id: "tt-53", label: "Tech term: S3 — AWS storage. Virtually unlimited file storage. 99.999999999% durability. Say: 'Files are stored on S3 — 11 nines of durability. Your data is safer than a bank vault.'", theme: "techie-talks" },
  { id: "tt-54", label: "Tech term: Lambda — serverless functions. Code runs only when triggered. No server to manage. Say: 'Lambda functions handle spikes automatically — zero server management.'", theme: "techie-talks" },
  { id: "tt-55", label: "Tech term: CDN (Content Delivery Network) — copies your content to servers worldwide. Users get data from the nearest location. Say: 'Our CDN ensures sub-100ms load times from Mumbai to New York.'", theme: "techie-talks" },
  { id: "tt-56", label: "Tech term: Serverless — you write functions, the cloud handles servers. No patching, no scaling worries. Say: 'Serverless architecture means you pay only when code actually runs.'", theme: "techie-talks" },
  { id: "tt-57", label: "Tech term: Microservices — instead of one big app, many small independent services. Each does one thing well. Say: 'Microservices let us update the payment system without touching the user module.'", theme: "techie-talks" },
  { id: "tt-58", label: "Tech term: Load Balancer — distributes traffic across multiple servers. If one server is overloaded, traffic goes to another. Say: 'The load balancer ensures no single server is overwhelmed.'", theme: "techie-talks" },
  { id: "tt-59", label: "Tech term: Auto-scaling — automatically adding/removing servers based on traffic. Say: 'Auto-scaling handles Black Friday traffic spikes — scales up at 9 AM, scales down at midnight.'", theme: "techie-talks" },
  { id: "tt-60", label: "Tech term: VPC (Virtual Private Cloud) — your own isolated network within the cloud. Secure boundary. Say: 'The database lives in a VPC — not accessible from the public internet.'", theme: "techie-talks" },

  // --- Security ---
  { id: "tt-61", label: "Tech term: Encryption at Rest — data is encrypted when stored on disk. Even if stolen, it's unreadable. Say: 'All data is encrypted at rest with AES-256 — military-grade encryption.'", theme: "techie-talks" },
  { id: "tt-62", label: "Tech term: Encryption in Transit — data is encrypted while moving between systems. HTTPS does this. Say: 'Every byte of data is encrypted in transit — no eavesdropping possible.'", theme: "techie-talks" },
  { id: "tt-63", label: "Tech term: SQL Injection — hacker inserts malicious SQL through input fields. Can delete entire databases. Say: 'We use parameterized queries — SQL injection is impossible.'", theme: "techie-talks" },
  { id: "tt-64", label: "Tech term: XSS (Cross-Site Scripting) — hacker injects malicious scripts into web pages. Say: 'All user input is sanitized — XSS attacks are blocked at every entry point.'", theme: "techie-talks" },
  { id: "tt-65", label: "Tech term: OWASP Top 10 — the ten most critical web security risks. The industry checklist. Say: 'We audit against the OWASP Top 10 — every known vulnerability is addressed.'", theme: "techie-talks" },
  { id: "tt-66", label: "Tech term: DDoS (Distributed Denial of Service) — flooding a server with fake traffic to take it down. Say: 'Cloudflare DDoS protection handles up to 100 Tbps of attack traffic.'", theme: "techie-talks" },
  { id: "tt-67", label: "Tech term: WAF (Web Application Firewall) — filters malicious web traffic before it reaches your app. Say: 'The WAF blocks known attack patterns — your app never even sees malicious requests.'", theme: "techie-talks" },
  { id: "tt-68", label: "Tech term: Penetration Testing — hiring ethical hackers to find vulnerabilities before real hackers do. Say: 'We conduct annual pen tests — proactive security, not reactive.'", theme: "techie-talks" },
  { id: "tt-69", label: "Tech term: Zero Trust Architecture — never trust, always verify. Every request is authenticated, even from inside the network. Say: 'We follow zero trust — even internal services authenticate.'", theme: "techie-talks" },
  { id: "tt-70", label: "Tech term: 2FA/MFA — Two-Factor/Multi-Factor Authentication. Password + phone code. Say: 'MFA is mandatory — even if a password leaks, the account stays secure.'", theme: "techie-talks" },

  // --- Architecture Patterns ---
  { id: "tt-71", label: "Tech term: Event-Driven Architecture — systems react to events (user clicked, payment received) instead of polling. Say: 'Event-driven design means real-time response to every action.'", theme: "techie-talks" },
  { id: "tt-72", label: "Tech term: Message Queue — systems communicate by putting messages in a queue (RabbitMQ, Kafka). Decouples services. Say: 'The queue handles 10,000 messages/second without losing a single one.'", theme: "techie-talks" },
  { id: "tt-73", label: "Tech term: CQRS — Command Query Responsibility Segregation. Separate reads from writes for performance. Say: 'CQRS gives us read performance of 1ms even with millions of records.'", theme: "techie-talks" },
  { id: "tt-74", label: "Tech term: Event Sourcing — instead of storing current state, store every change that happened. Perfect audit trail. Say: 'Event sourcing gives you a complete, immutable history of every transaction.'", theme: "techie-talks" },
  { id: "tt-75", label: "Tech term: Saga Pattern — managing transactions across multiple microservices. If one fails, all roll back. Say: 'The saga pattern ensures data consistency across all services.'", theme: "techie-talks" },
  { id: "tt-76", label: "Tech term: Circuit Breaker — if a service fails, stop calling it temporarily. Prevents cascading failures. Say: 'The circuit breaker isolates failures — one broken service doesn't crash the whole system.'", theme: "techie-talks" },
  { id: "tt-77", label: "Tech term: API Gateway — single entry point for all microservices. Handles auth, rate limiting, routing. Say: 'The API gateway manages all 20 microservices through one secure endpoint.'", theme: "techie-talks" },
  { id: "tt-78", label: "Tech term: Service Mesh — manages communication between microservices. Handles retries, encryption, observability. Say: 'The service mesh gives us visibility into every inter-service call.'", theme: "techie-talks" },
  { id: "tt-79", label: "Tech term: Domain-Driven Design (DDD) — structuring software around business domains, not technical layers. Say: 'DDD ensures the code mirrors your business structure — intuitive for everyone.'", theme: "techie-talks" },
  { id: "tt-80", label: "Tech term: Hexagonal Architecture — core business logic is isolated from external concerns (DB, UI, APIs). Say: 'Hexagonal architecture means we can swap the database without touching business logic.'", theme: "techie-talks" },

  // --- AI & Machine Learning ---
  { id: "tt-81", label: "Tech term: LLM (Large Language Model) — AI models like ChatGPT/Claude that understand and generate text. Say: 'We integrate LLMs for intelligent automation — the AI handles natural language queries.'", theme: "techie-talks" },
  { id: "tt-82", label: "Tech term: RAG (Retrieval-Augmented Generation) — AI that searches your data before answering. Say: 'RAG lets the AI answer questions about YOUR business data, not just general knowledge.'", theme: "techie-talks" },
  { id: "tt-83", label: "Tech term: Vector Database — stores data as mathematical vectors for similarity search. Powers AI search. Say: 'The vector database finds similar documents in milliseconds using semantic understanding.'", theme: "techie-talks" },
  { id: "tt-84", label: "Tech term: Embeddings — converting text/images into numbers that capture meaning. Say: 'Embeddings let the system understand that 'revenue' and 'income' mean similar things.'", theme: "techie-talks" },
  { id: "tt-85", label: "Tech term: Fine-tuning — training an AI model on your specific data to improve accuracy. Say: 'We fine-tuned the model on your industry data — 95% accuracy on domain-specific questions.'", theme: "techie-talks" },
  { id: "tt-86", label: "Tech term: Prompt Engineering — crafting instructions for AI to get optimal results. Say: 'Our prompt engineering ensures consistent, high-quality AI outputs every time.'", theme: "techie-talks" },
  { id: "tt-87", label: "Tech term: Edge AI — running AI models on the device (phone, camera) instead of the cloud. Faster, private. Say: 'Edge AI processes on-device — no data leaves the user's phone.'", theme: "techie-talks" },
  { id: "tt-88", label: "Tech term: MLOps — DevOps for machine learning. Deploying, monitoring, retraining AI models. Say: 'Our MLOps pipeline ensures the model stays accurate as your data evolves.'", theme: "techie-talks" },
  { id: "tt-89", label: "Tech term: Computer Vision — AI that 'sees' and interprets images. Used in surveillance, quality control, medical. Say: 'Computer vision can detect defects on a production line faster than human inspectors.'", theme: "techie-talks" },
  { id: "tt-90", label: "Tech term: NLP (Natural Language Processing) — AI understanding human language. Chatbots, translation, sentiment analysis. Say: 'NLP powers the chatbot — it understands Hindi, Gujarati, and English queries.'", theme: "techie-talks" },

  // --- Performance & Optimization ---
  { id: "tt-91", label: "Tech term: Latency — the delay between request and response. Measured in milliseconds. Say: 'Our API latency is under 50ms — users feel instant response.'", theme: "techie-talks" },
  { id: "tt-92", label: "Tech term: Throughput — how many requests a system handles per second. Say: 'The system handles 5,000 requests/second at peak — more than enough for 10,000 concurrent users.'", theme: "techie-talks" },
  { id: "tt-93", label: "Tech term: P99 Latency — 99% of requests complete within this time. The real measure. Say: 'Our P99 latency is 100ms — even the slowest 1% of requests are fast.'", theme: "techie-talks" },
  { id: "tt-94", label: "Tech term: Cache Hit Ratio — percentage of requests served from cache vs. database. Say: '95% cache hit ratio means only 5% of requests actually hit the database.'", theme: "techie-talks" },
  { id: "tt-95", label: "Tech term: Connection Pooling — reusing database connections instead of creating new ones. Huge performance gain. Say: 'Connection pooling reduced database load by 80%.'", theme: "techie-talks" },
  { id: "tt-96", label: "Tech term: Lazy Loading — loading resources only when needed, not upfront. Say: 'Lazy loading images reduced page load time from 4 seconds to 1.2 seconds.'", theme: "techie-talks" },
  { id: "tt-97", label: "Tech term: Code Splitting — breaking JavaScript into chunks, loading only what's needed. Say: 'Code splitting reduced our initial bundle size by 60%.'", theme: "techie-talks" },
  { id: "tt-98", label: "Tech term: Tree Shaking — removing unused code from the final bundle. Like pruning a tree. Say: 'Tree shaking eliminated 40% of dead code from the production build.'", theme: "techie-talks" },
  { id: "tt-99", label: "Tech term: Profiling — measuring where your code spends time. Find bottlenecks. Say: 'Profiling revealed the bottleneck was in the PDF generation — we optimized it from 8s to 0.5s.'", theme: "techie-talks" },
  { id: "tt-100", label: "Tech term: Benchmark — measuring performance against a standard. Say: 'We benchmark every release against the previous version — no performance regressions allowed.'", theme: "techie-talks" },

  // --- Testing & Quality ---
  { id: "tt-101", label: "Tech term: Unit Test — testing individual functions in isolation. Say: 'We have 500+ unit tests — every function is verified independently.'", theme: "techie-talks" },
  { id: "tt-102", label: "Tech term: Integration Test — testing how components work together. Say: 'Integration tests verify the entire payment flow — from button click to database record.'", theme: "techie-talks" },
  { id: "tt-103", label: "Tech term: E2E Test (End-to-End) — testing the entire user journey. A robot clicks through the app. Say: 'E2E tests simulate real users — we catch bugs before they reach production.'", theme: "techie-talks" },
  { id: "tt-104", label: "Tech term: Load Testing — simulating thousands of users to find breaking points. Say: 'We load tested with 10,000 concurrent users — the system handled it with 99.9% uptime.'", theme: "techie-talks" },
  { id: "tt-105", label: "Tech term: Code Coverage — percentage of code tested by automated tests. Say: '85% code coverage means 85% of all code paths are verified by tests.'", theme: "techie-talks" },
  { id: "tt-106", label: "Tech term: Regression Testing — re-running all tests after a change to ensure nothing broke. Say: 'Every code change triggers full regression — no surprises in production.'", theme: "techie-talks" },
  { id: "tt-107", label: "Tech term: Chaos Engineering — intentionally breaking things in production to test resilience. Netflix invented this. Say: 'Chaos engineering proves our system survives server failures.'", theme: "techie-talks" },
  { id: "tt-108", label: "Tech term: Feature Flag — toggle features on/off without deploying code. Say: 'Feature flags let us enable the new dashboard for 10% of users first.'", theme: "techie-talks" },
  { id: "tt-109", label: "Tech term: A/B Testing — showing two versions to different users to see which performs better. Say: 'A/B testing showed the new checkout flow increased conversions by 23%.'", theme: "techie-talks" },
  { id: "tt-110", label: "Tech term: Observability — ability to understand what's happening inside your system from outside. Logs + metrics + traces. Say: 'Full observability means we know about issues before users do.'", theme: "techie-talks" },

  // --- Mobile & Cross-Platform ---
  { id: "tt-111", label: "Tech term: React Native — build iOS and Android apps with one codebase using React. Say: 'React Native gives you both iOS and Android at 60% of the cost of building two separate apps.'", theme: "techie-talks" },
  { id: "tt-112", label: "Tech term: Flutter — Google's cross-platform framework. Beautiful, fast apps. Say: 'Flutter delivers 60fps animations on both platforms — native-quality from a single codebase.'", theme: "techie-talks" },
  { id: "tt-113", label: "Tech term: Native App — built specifically for one platform (Swift for iOS, Kotlin for Android). Best performance. Say: 'Native gives the best experience but costs 2x — one app per platform.'", theme: "techie-talks" },
  { id: "tt-114", label: "Tech term: Responsive Design — one website that adapts to any screen size. Phone, tablet, desktop. Say: 'Responsive design means one codebase serves all devices — no separate mobile site needed.'", theme: "techie-talks" },
  { id: "tt-115", label: "Tech term: Deep Linking — opening a specific page in an app from a URL. Say: 'Deep links let WhatsApp messages open directly to the relevant screen in your app.'", theme: "techie-talks" },

  // --- Data & Analytics ---
  { id: "tt-116", label: "Tech term: ETL (Extract, Transform, Load) — moving data from source systems into a data warehouse. Say: 'The ETL pipeline consolidates data from 5 systems into one dashboard.'", theme: "techie-talks" },
  { id: "tt-117", label: "Tech term: Data Warehouse — centralized repository for reporting and analytics. Say: 'The data warehouse enables cross-department reporting that was impossible with siloed systems.'", theme: "techie-talks" },
  { id: "tt-118", label: "Tech term: Data Lake — raw, unstructured data storage. Cheaper than a warehouse. Say: 'The data lake stores everything — we decide later what's valuable for analysis.'", theme: "techie-talks" },
  { id: "tt-119", label: "Tech term: Real-time Analytics — analyzing data as it arrives, not in batches. Say: 'Real-time analytics show live transaction counts — you see today's numbers update second by second.'", theme: "techie-talks" },
  { id: "tt-120", label: "Tech term: Kafka — distributed event streaming platform by LinkedIn. Handles trillions of events/day. Say: 'Kafka processes our event stream — every user action is captured and analyzed in real-time.'", theme: "techie-talks" },

  // --- Modern Practices ---
  { id: "tt-121", label: "Tech term: GitOps — managing infrastructure through Git. Every change is a pull request, reviewed and auditable. Say: 'GitOps means every infrastructure change has a paper trail.'", theme: "techie-talks" },
  { id: "tt-122", label: "Tech term: Immutable Infrastructure — never update servers, always replace them. Deploy new, destroy old. Say: 'Immutable infrastructure eliminates 'works on my machine' problems.'", theme: "techie-talks" },
  { id: "tt-123", label: "Tech term: 12-Factor App — 12 best practices for building cloud-native apps. Industry standard. Say: 'We follow 12-factor principles — the app is cloud-ready from day one.'", theme: "techie-talks" },
  { id: "tt-124", label: "Tech term: Mono-repo vs. Multi-repo — one big repository vs. many small ones. Each has tradeoffs. Say: 'Google uses a mono-repo for 2 billion lines of code. We use it for related services.'", theme: "techie-talks" },
  { id: "tt-125", label: "Tech term: Trunk-Based Development — everyone commits to the main branch frequently. No long-lived branches. Say: 'Trunk-based development means we ship multiple times per day.'", theme: "techie-talks" },
  { id: "tt-126", label: "Tech term: Semantic Versioning — version numbers that mean something. MAJOR.MINOR.PATCH (e.g., 2.1.3). Say: 'We follow semver — breaking changes increment the major version.'", theme: "techie-talks" },
  { id: "tt-127", label: "Tech term: Technical Debt — shortcuts taken now that cost more to fix later. Like financial debt. Say: 'We need to address technical debt before it compounds into a rewrite.'", theme: "techie-talks" },
  { id: "tt-128", label: "Tech term: Refactoring — restructuring code without changing behavior. Cleaning up. Say: 'Refactoring improved code quality — same features, 40% less code, 3x easier to maintain.'", theme: "techie-talks" },
  { id: "tt-129", label: "Tech term: Code Review — another developer reviews your code before it merges. Catches bugs early. Say: 'Every line of code is peer-reviewed — four eyes catch more bugs than two.'", theme: "techie-talks" },
  { id: "tt-130", label: "Tech term: Pair Programming — two developers working on one task together. One codes, one reviews. Say: 'Pair programming on critical features reduces bugs by 60%.'", theme: "techie-talks" },

  // --- Networking & Protocols ---
  { id: "tt-131", label: "Tech term: HTTP/3 — the latest web protocol. Uses QUIC instead of TCP. 30% faster connections. Say: 'We serve over HTTP/3 — the latest protocol for faster page loads.'", theme: "techie-talks" },
  { id: "tt-132", label: "Tech term: gRPC — Google's high-performance RPC framework. 10x faster than REST for service-to-service. Say: 'Internal services communicate via gRPC — 10x faster than REST.'", theme: "techie-talks" },
  { id: "tt-133", label: "Tech term: DNS — Domain Name System. Translates 'google.com' to an IP address. The phone book of the internet. Say: 'DNS propagation takes 24-48 hours after a domain change.'", theme: "techie-talks" },
  { id: "tt-134", label: "Tech term: TCP vs. UDP — TCP guarantees delivery (web, email). UDP is faster but no guarantee (video, gaming). Say: 'Video streaming uses UDP — speed matters more than perfect delivery.'", theme: "techie-talks" },
  { id: "tt-135", label: "Tech term: IP Whitelisting — only allowing specific IP addresses to access a system. Say: 'The admin panel is IP-whitelisted — only your office network can access it.'", theme: "techie-talks" },

  // --- Emerging Tech ---
  { id: "tt-136", label: "Tech term: Web3 — decentralized internet built on blockchain. Smart contracts, dApps. Say: 'Web3 enables trustless transactions — no middleman needed for verification.'", theme: "techie-talks" },
  { id: "tt-137", label: "Tech term: Smart Contract — self-executing code on blockchain. Runs when conditions are met. Say: 'Smart contracts automate agreement execution — no lawyer needed for simple contracts.'", theme: "techie-talks" },
  { id: "tt-138", label: "Tech term: Edge Computing — processing data close to where it's generated (IoT devices, local servers). Say: 'Edge computing reduces latency from 200ms to 5ms by processing locally.'", theme: "techie-talks" },
  { id: "tt-139", label: "Tech term: IoT (Internet of Things) — everyday objects connected to the internet. Sensors, cameras, thermostats. Say: 'IoT sensors can track inventory automatically — no manual counting.'", theme: "techie-talks" },
  { id: "tt-140", label: "Tech term: Digital Twin — a virtual replica of a physical system. Test changes virtually before implementing. Say: 'The digital twin lets us simulate changes before touching the real system.'", theme: "techie-talks" },

  // --- Business-Relevant Tech Language ---
  { id: "tt-141", label: "Impress with: 'We follow a headless architecture — the frontend and backend are completely decoupled.' Means: they can be changed independently.", theme: "techie-talks" },
  { id: "tt-142", label: "Impress with: 'The system is horizontally scalable.' Means: we add more servers (not bigger servers) to handle more traffic.", theme: "techie-talks" },
  { id: "tt-143", label: "Impress with: 'We've implemented a write-ahead log for crash recovery.' Means: even if the server crashes mid-transaction, no data is lost.", theme: "techie-talks" },
  { id: "tt-144", label: "Impress with: 'The API follows RESTful conventions with HATEOAS.' Means: the API is self-documenting — clients discover capabilities by navigating links.", theme: "techie-talks" },
  { id: "tt-145", label: "Impress with: 'We use eventual consistency for non-critical data.' Means: slight delay in data sync (milliseconds) in exchange for much higher performance.", theme: "techie-talks" },
  { id: "tt-146", label: "Impress with: 'The database has multi-region replication.' Means: data is copied to servers in multiple cities. If Mumbai goes down, Bangalore takes over.", theme: "techie-talks" },
  { id: "tt-147", label: "Impress with: 'We implement graceful degradation.' Means: if a feature fails, the rest of the app keeps working. No full crashes.", theme: "techie-talks" },
  { id: "tt-148", label: "Impress with: 'The architecture supports multi-tenancy.' Means: one system serves multiple organizations, each seeing only their own data. Cost-efficient.", theme: "techie-talks" },
  { id: "tt-149", label: "Impress with: 'We've set up a distributed tracing system.' Means: we can follow a single user request across 20 services and find exactly where any slowdown occurs.", theme: "techie-talks" },
  { id: "tt-150", label: "Impress with: 'The deployment pipeline is fully automated with rollback capability.' Means: code goes live automatically, and if anything breaks, we revert in 60 seconds.", theme: "techie-talks" },

  // --- Database Deep Cuts ---
  { id: "tt-151", label: "Tech term: CAP Theorem — you can only have 2 of 3: Consistency, Availability, Partition tolerance. Say: 'We chose CP for financial data — consistency over availability.'", theme: "techie-talks" },
  { id: "tt-152", label: "Tech term: Read Replica — a copy of the database that handles read queries. Master handles writes. Say: 'Read replicas handle dashboard queries — the master stays fast for transactions.'", theme: "techie-talks" },
  { id: "tt-153", label: "Tech term: Materialized View — pre-computed query results stored as a table. Instant complex reports. Say: 'Materialized views give you instant analytics — complex queries pre-computed every hour.'", theme: "techie-talks" },
  { id: "tt-154", label: "Tech term: Deadlock — two transactions waiting for each other forever. Say: 'Our transaction design prevents deadlocks — all resources are acquired in consistent order.'", theme: "techie-talks" },
  { id: "tt-155", label: "Tech term: Connection Pool — pre-opened database connections shared by the application. Say: 'Connection pooling with PgBouncer reduced connection overhead by 90%.'", theme: "techie-talks" },

  // --- Observability & Monitoring ---
  { id: "tt-156", label: "Tech term: APM (Application Performance Monitoring) — tools like New Relic, Datadog that watch your app's health. Say: 'APM alerts us to performance degradation before users notice.'", theme: "techie-talks" },
  { id: "tt-157", label: "Tech term: Log Aggregation — collecting logs from all servers into one searchable place. ELK Stack, Grafana Loki. Say: 'Centralized logging means we can trace any issue across 50 servers.'", theme: "techie-talks" },
  { id: "tt-158", label: "Tech term: SLO/SLI/SLA — Service Level Objectives/Indicators/Agreements. How we measure and promise reliability. Say: 'Our SLO is 99.95% uptime — that's less than 22 minutes of downtime per month.'", theme: "techie-talks" },
  { id: "tt-159", label: "Tech term: Alerting & On-call — automated notifications when something breaks. PagerDuty, OpsGenie. Say: 'Our alerting pipeline notifies the team within 30 seconds of any anomaly.'", theme: "techie-talks" },
  { id: "tt-160", label: "Tech term: Runbook — documented step-by-step guide for handling incidents. Say: 'Every known failure scenario has a runbook — the team resolves issues in minutes, not hours.'", theme: "techie-talks" },

  // --- Architecture Decision Language ---
  { id: "tt-161", label: "Impress with: 'We made a deliberate architectural trade-off here — favoring read performance over write speed.' Shows you think in trade-offs, not absolutes.", theme: "techie-talks" },
  { id: "tt-162", label: "Impress with: 'The system follows the principle of least privilege.' Means: every component has the minimum permissions needed. Limits damage from breaches.", theme: "techie-talks" },
  { id: "tt-163", label: "Impress with: 'We implemented bulkhead isolation.' Means: failure in one part is contained and can't bring down other parts. Like watertight compartments on a ship.", theme: "techie-talks" },
  { id: "tt-164", label: "Impress with: 'The architecture is designed for observability, not just monitoring.' Means: we can ask NEW questions about system behavior, not just check predefined dashboards.", theme: "techie-talks" },
  { id: "tt-165", label: "Impress with: 'We use a strangler fig pattern for legacy migration.' Means: gradually replacing the old system piece by piece, while both run in parallel.", theme: "techie-talks" },
  { id: "tt-166", label: "Impress with: 'The system implements back-pressure mechanisms.' Means: when overloaded, it slows down gracefully instead of crashing. Like a traffic light for data.", theme: "techie-talks" },
  { id: "tt-167", label: "Impress with: 'We've designed for failure — not just success.' Means: we assume things WILL break and built the system to handle it gracefully.", theme: "techie-talks" },
  { id: "tt-168", label: "Impress with: 'The data pipeline is idempotent and exactly-once.' Means: even if processing fails and retries, no duplicate data, no lost data.", theme: "techie-talks" },
  { id: "tt-169", label: "Impress with: 'We use feature toggles for trunk-based development.' Means: new features are hidden behind flags, allowing rapid deployment without risking stability.", theme: "techie-talks" },
  { id: "tt-170", label: "Impress with: 'The system supports multi-region active-active deployment.' Means: servers in Mumbai AND Bangalore both handle traffic — zero single point of failure.", theme: "techie-talks" },

  // --- Scaling & Performance Language ---
  { id: "tt-171", label: "Tech term: Vertical Scaling — making one server bigger (more RAM, CPU). Limited ceiling. Say: 'We hit the vertical scaling limit at 64GB RAM — time to scale horizontally.'", theme: "techie-talks" },
  { id: "tt-172", label: "Tech term: Horizontal Scaling — adding more servers. No ceiling. Say: 'Horizontal scaling means unlimited growth — just add more nodes to the cluster.'", theme: "techie-talks" },
  { id: "tt-173", label: "Tech term: Database Partitioning — dividing a large table into smaller chunks. Say: 'Partitioning by date means last month's queries are 10x faster — they scan less data.'", theme: "techie-talks" },
  { id: "tt-174", label: "Tech term: Hot Path vs. Cold Path — frequently accessed data (hot) stays in fast storage. Rarely accessed (cold) goes to cheap storage. Say: 'Hot data in Redis, cold data in S3 — optimal cost and speed.'", theme: "techie-talks" },
  { id: "tt-175", label: "Tech term: Write-Behind Cache — writes go to cache first, then asynchronously to database. Ultra-fast writes. Say: 'Write-behind caching gives us 10x write throughput.'", theme: "techie-talks" },

  // --- Compliance & Enterprise ---
  { id: "tt-176", label: "Tech term: SOC 2 — security certification for service companies. Audited controls for data protection. Say: 'SOC 2 compliance means your data is protected by audited, certified controls.'", theme: "techie-talks" },
  { id: "tt-177", label: "Tech term: GDPR — European data privacy law. Even Indian companies serving EU must comply. Say: 'We're GDPR-ready — user data can be exported or deleted on request.'", theme: "techie-talks" },
  { id: "tt-178", label: "Tech term: RBAC (Role-Based Access Control) — users see only what their role permits. Say: 'RBAC ensures the secretary sees member data, but the accountant sees only financials.'", theme: "techie-talks" },
  { id: "tt-179", label: "Tech term: Audit Trail — immutable log of who did what and when. Say: 'The audit trail records every action — full accountability for every data change.'", theme: "techie-talks" },
  { id: "tt-180", label: "Tech term: Data Retention Policy — rules for how long data is kept. Say: 'Our retention policy auto-archives data after 7 years — compliant with Indian IT Act requirements.'", theme: "techie-talks" },

  // --- Dev Workflow Terms ---
  { id: "tt-181", label: "Tech term: Sprint — a 2-week focused work cycle in Agile. Clear goals, daily standups, demo at end. Say: 'Each sprint delivers working features — you see progress every 2 weeks.'", theme: "techie-talks" },
  { id: "tt-182", label: "Tech term: Standup — daily 15-minute team sync. What I did, what I'll do, any blockers. Say: 'Daily standups keep the project on track — no surprises at the end.'", theme: "techie-talks" },
  { id: "tt-183", label: "Tech term: Retrospective — team review after each sprint. What worked? What didn't? How to improve? Say: 'Retros ensure we get better every sprint — continuous improvement built into the process.'", theme: "techie-talks" },
  { id: "tt-184", label: "Tech term: User Story — a feature described from the user's perspective. 'As a secretary, I want to see all members so I can take attendance.' Say: 'Every feature starts with a user story — we build what users need, not what we assume.'", theme: "techie-talks" },
  { id: "tt-185", label: "Tech term: Technical Spike — a time-boxed research task to answer a technical question. Say: 'Before committing, we'll do a 2-day spike to validate the approach.'", theme: "techie-talks" },

  // --- Deployment & Reliability ---
  { id: "tt-186", label: "Tech term: SLA (Service Level Agreement) — guaranteed uptime/performance. Say: 'Our SLA guarantees 99.9% uptime — less than 8 hours of downtime per year.'", theme: "techie-talks" },
  { id: "tt-187", label: "Tech term: RTO (Recovery Time Objective) — max acceptable downtime after failure. Say: 'Our RTO is 15 minutes — full recovery within a quarter hour of any outage.'", theme: "techie-talks" },
  { id: "tt-188", label: "Tech term: RPO (Recovery Point Objective) — max acceptable data loss. Say: 'RPO of 5 minutes means we lose at most 5 minutes of data in a worst-case scenario.'", theme: "techie-talks" },
  { id: "tt-189", label: "Tech term: Hot Standby — a backup server running in parallel, ready to take over instantly. Say: 'Hot standby means zero data loss — the backup is always synchronized.'", theme: "techie-talks" },
  { id: "tt-190", label: "Tech term: Disaster Recovery — plan for recovering from catastrophic failures. Say: 'Our DR plan includes multi-region backups — even if an entire data center goes down.'", theme: "techie-talks" },

  // --- Conversation Starters with Tech People ---
  { id: "tt-191", label: "Ask a CTO: 'What's your deployment frequency?' — reveals their engineering maturity. Daily = advanced. Monthly = legacy.", theme: "techie-talks" },
  { id: "tt-192", label: "Ask a CTO: 'How do you handle database migrations in production?' — shows you understand operational complexity.", theme: "techie-talks" },
  { id: "tt-193", label: "Ask a CTO: 'What's your incident response process?' — signals you think about reliability, not just features.", theme: "techie-talks" },
  { id: "tt-194", label: "Ask a CTO: 'Are you running a monolith or microservices?' — classic architecture conversation starter.", theme: "techie-talks" },
  { id: "tt-195", label: "Ask a CTO: 'What's your observability stack?' — shows you care about system health, not just building features.", theme: "techie-talks" },
  { id: "tt-196", label: "Ask a developer: 'What's your test coverage like?' — signals quality-first mindset.", theme: "techie-talks" },
  { id: "tt-197", label: "Ask a developer: 'Do you use feature flags?' — shows modern deployment awareness.", theme: "techie-talks" },
  { id: "tt-198", label: "Ask anyone technical: 'How do you handle secrets management?' — shows security awareness.", theme: "techie-talks" },
  { id: "tt-199", label: "Say in any tech meeting: 'What are the non-functional requirements?' — means performance, security, scalability. Shows you think beyond just features.", theme: "techie-talks" },
  { id: "tt-200", label: "Say in any tech meeting: 'Have we considered the blast radius of this change?' — means: if this goes wrong, how much is affected? Shows senior-level thinking.", theme: "techie-talks" },

  // --- Real Dev Sentences Decoded (What They Actually Mean) ---
  { id: "tt-201", label: "Dev sentence: 'serverTimestamp() can't be used inside arrayUnion() — it throws because arrayUnion is an atomic operation that doesn't allow sentinel values.' → Plain English: You're trying to auto-stamp the time inside a list-add command, but Firestore doesn't allow that combo. Save the timestamp separately, then add to the array.", theme: "techie-talks" },
  { id: "tt-202", label: "Dev sentence: 'We're getting a race condition on the checkout flow — two requests are hitting the same row and one overwrites the other.' → Plain English: Two users (or two clicks) are updating the same record at the exact same time, so one change gets lost. Fix: use a database lock or optimistic concurrency.", theme: "techie-talks" },
  { id: "tt-203", label: "Dev sentence: 'The build is failing because of a circular dependency between the auth module and the user service.' → Plain English: Module A needs Module B, and Module B needs Module A — they're stuck in a loop. Fix: extract the shared logic into a third module.", theme: "techie-talks" },
  { id: "tt-204", label: "Dev sentence: 'We need to debounce the search input — right now it's firing an API call on every keystroke and hammering the server.' → Plain English: Every letter typed sends a request. Debouncing waits until the user stops typing (say 300ms pause) before sending one request. Saves server load and money.", theme: "techie-talks" },
  { id: "tt-205", label: "Dev sentence: 'The memory leak is coming from event listeners that aren't being cleaned up when the component unmounts.' → Plain English: The app is listening for clicks/scrolls but never stops listening when you leave the page. Over time, memory fills up and the app slows to a crawl.", theme: "techie-talks" },
  { id: "tt-206", label: "Dev sentence: 'CORS is blocking the request — the backend needs to whitelist our frontend domain in the Access-Control-Allow-Origin header.' → Plain English: The browser is refusing to talk to the server because the server hasn't said \"I trust this website.\" It's a security feature. Fix: add the frontend URL to the server's allowed list.", theme: "techie-talks" },
  { id: "tt-207", label: "Dev sentence: 'The N+1 query problem is killing our page load — we're making 200 database calls instead of 2.' → Plain English: For every item in a list, the code makes a separate database call. If you have 200 items, that's 200 calls. Fix: fetch all related data in one query using a JOIN or eager loading.", theme: "techie-talks" },
  { id: "tt-208", label: "Dev sentence: 'We hit a deadlock in production — two transactions were waiting on each other and neither could proceed.' → Plain English: Transaction A locked Row 1 and wanted Row 2. Transaction B locked Row 2 and wanted Row 1. Both froze. The database eventually killed one. Fix: always lock rows in the same order.", theme: "techie-talks" },
  { id: "tt-209", label: "Dev sentence: 'The Docker container keeps getting OOMKilled because the memory limit is set too low for the Node process.' → Plain English: OOM = Out Of Memory. The app needs more RAM than the container allows, so Linux kills it. Fix: increase the memory limit in docker-compose.yml or optimize the app's memory usage.", theme: "techie-talks" },
  { id: "tt-210", label: "Dev sentence: 'We need to invalidate the CDN cache — users are seeing stale assets after the deployment.' → Plain English: The CDN (global copies of your files) still has the old version. Users see yesterday's code even though you deployed today. Fix: purge the CDN cache or use versioned file names.", theme: "techie-talks" },
  { id: "tt-211", label: "Dev sentence: 'The SSL certificate expired and now Chrome is showing a NET::ERR_CERT_DATE_INVALID warning to all users.' → Plain English: The security certificate that makes the padlock icon work has expired. Visitors see a scary \"Not Secure\" page. Fix: renew the certificate (or set up auto-renewal with Let's Encrypt).", theme: "techie-talks" },
  { id: "tt-212", label: "Dev sentence: 'The migration failed halfway through and left the database in an inconsistent state — we need to rollback.' → Plain English: A database structure change crashed midway. Some tables are updated, some aren't. The data is now messy. Fix: undo (rollback) the migration, fix the script, try again.", theme: "techie-talks" },
  { id: "tt-213", label: "Dev sentence: 'We're getting 429 Too Many Requests from the third-party API — we need to implement exponential backoff.' → Plain English: The API is saying \"slow down, you're calling me too fast.\" Exponential backoff = wait 1 second, then 2, then 4, then 8 before retrying. It's polite retry logic.", theme: "techie-talks" },
  { id: "tt-214", label: "Dev sentence: 'The environment variable isn't being read because it's only available at build time, not at runtime.' → Plain English: Some settings are baked in when you build the app, others are read live. If a setting changes after build, the app won't see the new value. Fix: use runtime env vars or rebuild.", theme: "techie-talks" },
  { id: "tt-215", label: "Dev sentence: 'The WebSocket connection keeps dropping because the load balancer has a 60-second idle timeout.' → Plain English: Real-time connections (chat, live updates) go silent if nothing is sent for 60 seconds, and the load balancer kills them. Fix: send a small \"ping\" message every 30 seconds to keep it alive.", theme: "techie-talks" },
  { id: "tt-216", label: "Dev sentence: 'We can't use localStorage for auth tokens — it's vulnerable to XSS attacks. We should use httpOnly cookies instead.' → Plain English: localStorage is readable by any JavaScript on the page, including malicious scripts. httpOnly cookies are invisible to JavaScript — only the browser and server can see them. Much safer.", theme: "techie-talks" },
  { id: "tt-217", label: "Dev sentence: 'The Kubernetes pod is stuck in CrashLoopBackOff — the health check endpoint is returning 503.' → Plain English: The app container keeps crashing and restarting in a loop. The health check (\"are you alive?\") is failing. Fix: check the logs to see why the app can't start — missing config, bad DB connection, or port conflict.", theme: "techie-talks" },
  { id: "tt-218", label: "Dev sentence: 'We need to add an index on that column — the query is doing a full table scan on 10 million rows.' → Plain English: Without an index, the database reads EVERY row to find what you need. Like searching a 500-page book without a table of contents. Adding an index turns a 5-second query into 5 milliseconds.", theme: "techie-talks" },
  { id: "tt-219", label: "Dev sentence: 'The payload is too large — we should paginate the response instead of returning all 50,000 records at once.' → Plain English: The API is trying to send everything in one go, which is slow and can crash the browser. Pagination = send 20-50 items at a time, load more on scroll or button click.", theme: "techie-talks" },
  { id: "tt-220", label: "Dev sentence: 'There's a hydration mismatch — the server-rendered HTML doesn't match what React generates on the client.' → Plain English: The page looks one way when the server sends it, but React changes it when it loads in the browser. This flicker confuses React. Fix: make sure server and client render the exact same thing (avoid browser-only code like window or localStorage during initial render).", theme: "techie-talks" },
  { id: "tt-221", label: "Dev sentence: 'The DNS propagation hasn't completed yet — some users are still hitting the old IP address.' → Plain English: You changed where your domain points, but the internet's phone book (DNS) takes time to update worldwide (up to 48 hours). Some users see the new site, others still see the old one. Fix: wait, or lower the TTL before making changes.", theme: "techie-talks" },
];
