import { PowerCheckItem } from "./power-checks";

// 150 high-traffic architecture tips — real-world examples, techniques, Docker vs K8s, hardware
export const highTrafficTips: PowerCheckItem[] = [
  // --- Real-World Scale Examples ---
  { id: "ht-1", label: "VISA processes 65,000 transactions/second (peak). Architecture: global mesh of data centers, in-memory processing, custom hardware, triple redundancy. Every transaction completes in <1 second.", theme: "high-traffic" },
  { id: "ht-2", label: "Google Search handles 100,000 queries/second. Architecture: custom distributed file system (GFS), MapReduce for indexing, 30+ data centers worldwide, custom-built servers with emphasis on RAM over CPU.", theme: "high-traffic" },
  { id: "ht-3", label: "Netflix serves 400M+ hours of video/month. Architecture: AWS (thousands of EC2 instances), custom CDN (Open Connect), microservices (1000+), Chaos Monkey for resilience testing.", theme: "high-traffic" },
  { id: "ht-4", label: "WhatsApp handled 2B users with just 50 engineers. Secret: Erlang (designed for telecom), custom-tuned FreeBSD kernel, each server handled 2M+ connections. Efficiency over headcount.", theme: "high-traffic" },
  { id: "ht-5", label: "Amazon processes 66,000 orders/HOUR during Prime Day. Architecture: microservices (hundreds), DynamoDB for sub-millisecond reads, auto-scaling across 25+ regions, teams of 'two pizza' size.", theme: "high-traffic" },
  { id: "ht-6", label: "Uber handles 14M trips/day globally. Architecture: Go + Java microservices, Kafka for event streaming (1 trillion events/day), H3 hexagonal grid for geospatial matching, Redis for real-time state.", theme: "high-traffic" },
  { id: "ht-7", label: "Twitter (X) handles 500M tweets/day. Architecture: Manhattan (distributed database), Kafka for fan-out, Redis for timeline caching, GraphQL API gateway, Thrift for service communication.", theme: "high-traffic" },
  { id: "ht-8", label: "UPI (India) processes 10B+ transactions/month. Architecture: NPCI's multi-tier system with bank switches, ISO 8583 messaging, sub-second clearing. The world's largest real-time payment system.", theme: "high-traffic" },
  { id: "ht-9", label: "Hotstar streamed to 25M concurrent viewers (cricket). Architecture: multi-CDN strategy, adaptive bitrate streaming, pre-warmed infrastructure, edge servers across 200+ cities.", theme: "high-traffic" },
  { id: "ht-10", label: "Flipkart Big Billion Days: 15M orders/day. Architecture: auto-scaling on Flipkart Cloud, message queues for order processing, circuit breakers, war rooms with 100+ engineers monitoring.", theme: "high-traffic" },

  // --- Load Balancing ---
  { id: "ht-11", label: "Load balancing 101: distribute requests across servers. Round-robin (equal), least-connections (to least busy), weighted (stronger servers get more). nginx, HAProxy, AWS ALB do this.", theme: "high-traffic" },
  { id: "ht-12", label: "Layer 4 vs Layer 7 load balancing: L4 works at TCP level (fast, simple). L7 works at HTTP level (can route based on URL, headers, cookies). L7 for web apps, L4 for raw performance.", theme: "high-traffic" },
  { id: "ht-13", label: "Sticky sessions: send the same user to the same server every time. Useful for session state. But limits scalability. Better: use Redis for shared session storage.", theme: "high-traffic" },
  { id: "ht-14", label: "Global Server Load Balancing (GSLB): routes users to the nearest healthy data center worldwide. GeoDNS + health checks. Say: 'GSLB gives users sub-50ms response from their nearest region.'", theme: "high-traffic" },
  { id: "ht-15", label: "Health checks: load balancers ping servers every few seconds. If a server doesn't respond, traffic automatically routes to healthy servers. Self-healing without human intervention.", theme: "high-traffic" },

  // --- Caching Strategies ---
  { id: "ht-16", label: "Caching layers: Browser cache → CDN cache → Application cache (Redis) → Database cache (query cache). Each layer reduces load on the next. Say: 'Multi-layer caching means 99% of requests never hit the database.'", theme: "high-traffic" },
  { id: "ht-17", label: "Cache-aside pattern: app checks cache first. Miss → read from DB → store in cache → return. Most common pattern. Redis + PostgreSQL is the classic combo.", theme: "high-traffic" },
  { id: "ht-18", label: "Write-through cache: every write goes to cache AND database simultaneously. Ensures cache is always fresh. Slower writes but reads are always consistent.", theme: "high-traffic" },
  { id: "ht-19", label: "Cache invalidation — the hardest problem in CS. When data changes, old cache must be cleared. Strategies: TTL (time-based), event-based (invalidate on write), versioning.", theme: "high-traffic" },
  { id: "ht-20", label: "CDN caching: static assets (images, JS, CSS) cached at 200+ edge locations worldwide. Cloudflare, AWS CloudFront. Say: 'CDN serves 80% of our traffic — origin servers handle only dynamic requests.'", theme: "high-traffic" },

  // --- Database Scaling ---
  { id: "ht-21", label: "Read replicas: master handles writes, replicas handle reads. Common ratio: 1 master + 5 read replicas. Say: 'Read replicas handle dashboard queries — master stays fast for transactions.'", theme: "high-traffic" },
  { id: "ht-22", label: "Database sharding: split data across multiple servers by a key (user_id, region). Each shard handles a subset. Instagram shards PostgreSQL across thousands of servers.", theme: "high-traffic" },
  { id: "ht-23", label: "Connection pooling: PgBouncer for PostgreSQL. Instead of 500 app connections → 500 DB connections, PgBouncer maintains 50 DB connections shared by all 500 app connections.", theme: "high-traffic" },
  { id: "ht-24", label: "Query optimization: EXPLAIN ANALYZE reveals how the database executes a query. Slow query log → find bottlenecks → add indexes → measure again. Say: 'That query went from 8 seconds to 12 milliseconds after indexing.'", theme: "high-traffic" },
  { id: "ht-25", label: "NoSQL for scale: when relational DB can't handle the load, consider DynamoDB (AWS), Cassandra (write-heavy), or MongoDB (flexible schema). Each has trade-offs.", theme: "high-traffic" },

  // --- Message Queues & Async Processing ---
  { id: "ht-26", label: "Message queues decouple systems: Producer → Queue → Consumer. If consumer is slow, messages wait in queue. Nothing is lost. RabbitMQ, SQS, Kafka.", theme: "high-traffic" },
  { id: "ht-27", label: "Kafka architecture: topics (categories), partitions (parallelism), consumer groups (load sharing). LinkedIn processes 7 trillion messages/day on Kafka.", theme: "high-traffic" },
  { id: "ht-28", label: "Queue-based load leveling: during traffic spikes, requests go into a queue and are processed at a steady rate. No overload. Say: 'Queues absorb traffic spikes — no dropped requests.'", theme: "high-traffic" },
  { id: "ht-29", label: "Dead letter queue: messages that fail processing repeatedly go to a special queue for investigation. Nothing is silently lost. Say: 'Failed messages are captured for manual review — zero data loss.'", theme: "high-traffic" },
  { id: "ht-30", label: "Event streaming vs. message queues: Kafka retains events (replay possible). RabbitMQ delivers and forgets. Use Kafka for event sourcing. RabbitMQ for task distribution.", theme: "high-traffic" },

  // --- Microservices at Scale ---
  { id: "ht-31", label: "Microservices scaling: each service scales independently. Payment service needs 10 instances during checkout rush? Scale just that one. No need to scale the entire app.", theme: "high-traffic" },
  { id: "ht-32", label: "Service discovery: how do services find each other? Consul, Eureka, or Kubernetes DNS. Say: 'Service discovery handles routing — services find each other automatically.'", theme: "high-traffic" },
  { id: "ht-33", label: "Circuit breaker pattern (Netflix Hystrix): if a downstream service fails, stop calling it for 30 seconds. Prevents cascading failures. Like a household circuit breaker.", theme: "high-traffic" },
  { id: "ht-34", label: "Bulkhead pattern: isolate failures. Each service gets its own thread pool. If payment service exhausts its threads, user service is unaffected. Like watertight compartments on a ship.", theme: "high-traffic" },
  { id: "ht-35", label: "API Gateway: single entry point for all microservices. Kong, AWS API Gateway. Handles authentication, rate limiting, request routing, and analytics.", theme: "high-traffic" },

  // --- Docker Deep Dive ---
  { id: "ht-36", label: "Docker: packages your app + OS + dependencies into a container. 'Works on my machine' problem solved forever. Container starts in 1-2 seconds vs. minutes for a VM.", theme: "high-traffic" },
  { id: "ht-37", label: "When to use Docker: (1) consistent environments across dev/staging/prod, (2) microservices, (3) rapid scaling, (4) isolating dependencies, (5) CI/CD pipelines.", theme: "high-traffic" },
  { id: "ht-38", label: "Docker image layers: each instruction in Dockerfile creates a layer. Layers are cached and shared. Smart layering = faster builds and smaller images.", theme: "high-traffic" },
  { id: "ht-39", label: "Docker Compose: define multi-container apps in one YAML file. App + database + Redis + nginx all start with one command: `docker-compose up`. Perfect for development.", theme: "high-traffic" },
  { id: "ht-40", label: "Docker networking: containers communicate through virtual networks. By default, isolated. You explicitly connect services. Say: 'Container networking provides built-in isolation and security.'", theme: "high-traffic" },
  { id: "ht-41", label: "Docker volumes: persistent storage that survives container restarts. Database data MUST be on volumes. Never store critical data inside a container.", theme: "high-traffic" },
  { id: "ht-42", label: "Docker security: run as non-root user, scan images for vulnerabilities (Trivy, Snyk), use multi-stage builds (smaller image = smaller attack surface), never store secrets in images.", theme: "high-traffic" },
  { id: "ht-43", label: "Docker in production: use Docker Swarm (simpler) or Kubernetes (more powerful) for orchestration. Never run single Docker containers in production without an orchestrator.", theme: "high-traffic" },

  // --- Kubernetes Deep Dive ---
  { id: "ht-44", label: "Kubernetes: container orchestration for production. Manages deployment, scaling, networking, and self-healing for thousands of containers. Google invented it (based on Borg).", theme: "high-traffic" },
  { id: "ht-45", label: "When to use Kubernetes: (1) 10+ microservices, (2) need auto-scaling, (3) multi-team deployments, (4) zero-downtime requirements, (5) complex networking between services.", theme: "high-traffic" },
  { id: "ht-46", label: "K8s Pods: smallest deployable unit. One or more containers that share network/storage. Usually one container per pod. Say: 'Each pod is a self-contained application unit.'", theme: "high-traffic" },
  { id: "ht-47", label: "K8s Deployment: manages pod replicas. Say 'I want 5 copies of this service.' K8s ensures exactly 5 are always running. If one dies, it creates a new one.", theme: "high-traffic" },
  { id: "ht-48", label: "K8s Service: stable network endpoint for pods. Pods come and go, but the Service address stays constant. Like a phone number that routes to the right person.", theme: "high-traffic" },
  { id: "ht-49", label: "K8s Horizontal Pod Autoscaler (HPA): automatically adds/removes pods based on CPU/memory/custom metrics. Say: 'HPA scaled from 3 to 50 pods during the traffic spike — automatically.'", theme: "high-traffic" },
  { id: "ht-50", label: "K8s Ingress: manages external access to services. Routes traffic based on hostname/URL path. Say: 'Ingress routes api.example.com to the API service and app.example.com to the frontend.'", theme: "high-traffic" },
  { id: "ht-51", label: "K8s Namespaces: virtual clusters within a cluster. Separate dev/staging/prod environments. Say: 'Namespaces isolate teams — each team deploys independently without interference.'", theme: "high-traffic" },
  { id: "ht-52", label: "K8s ConfigMaps & Secrets: externalize configuration from containers. Change config without rebuilding. Say: 'Configuration changes don't require redeployment — update the ConfigMap and pods reload.'", theme: "high-traffic" },
  { id: "ht-53", label: "When NOT to use Kubernetes: (1) single monolith app, (2) small team (<5 devs), (3) simple scaling needs, (4) limited ops knowledge. K8s adds complexity. Use only when complexity is justified.", theme: "high-traffic" },

  // --- Standard Server Deployment ---
  { id: "ht-54", label: "When standard servers win: (1) simple apps, (2) small traffic (<1000 req/s), (3) cost-sensitive, (4) small team, (5) predictable load. PM2 + nginx on a VPS is proven and simple.", theme: "high-traffic" },
  { id: "ht-55", label: "VPS (Virtual Private Server): your own server in the cloud. DigitalOcean, Linode, Hetzner. Rs 500-5000/month. Full control, simple setup. Perfect for most Indian businesses.", theme: "high-traffic" },
  { id: "ht-56", label: "PM2 cluster mode: runs multiple copies of your Node.js app on all CPU cores. 4-core server = 4 workers. Say: 'PM2 cluster mode utilizes all 8 cores — 8x throughput on one server.'", theme: "high-traffic" },
  { id: "ht-57", label: "nginx tuning: worker_processes = CPU cores. worker_connections = 10000+. gzip on. keepalive_timeout = 65. These settings alone handle 50,000+ concurrent connections.", theme: "high-traffic" },
  { id: "ht-58", label: "Linux kernel tuning for high traffic: increase net.core.somaxconn (65535), net.ipv4.tcp_max_syn_backlog (65535), fs.file-max (2097152). Default Linux settings are too conservative.", theme: "high-traffic" },
  { id: "ht-59", label: "Comparison: VPS ($5-50/mo) vs Docker Swarm ($20-200/mo) vs Kubernetes ($100-1000/mo). Choose based on complexity needs, not hype. Most apps work fine on a VPS.", theme: "high-traffic" },

  // --- Docker vs K8s vs Standard — Decision Matrix ---
  { id: "ht-60", label: "Docker vs K8s vs Standard:\n• 1-3 services, <1000 req/s → Standard (PM2 + nginx)\n• 3-10 services, <10K req/s → Docker Compose or Swarm\n• 10+ services, >10K req/s → Kubernetes", theme: "high-traffic" },
  { id: "ht-61", label: "Standard deployment wins when: team is small, budget is tight, traffic is predictable, and simplicity matters. 90% of Indian SME apps fit this category perfectly.", theme: "high-traffic" },
  { id: "ht-62", label: "Docker Compose wins when: you need reproducible environments, multiple services (app + DB + cache), but don't need auto-scaling or self-healing. Great for staging.", theme: "high-traffic" },
  { id: "ht-63", label: "Docker Swarm wins when: you need simple orchestration, 3-10 services, basic auto-scaling. Easier than K8s. Built into Docker. Good middle ground.", theme: "high-traffic" },
  { id: "ht-64", label: "Kubernetes wins when: you have 10+ microservices, need auto-scaling, zero-downtime deployments, multi-team workflows, and have dedicated DevOps. Overkill for small apps.", theme: "high-traffic" },
  { id: "ht-65", label: "Cost comparison for 10K req/s:\n• 2× Hetzner VPS (8-core, 32GB): €40/mo\n• Docker Swarm on 3 nodes: €60/mo\n• Managed K8s (EKS/GKE): $300-500/mo\nSimple always wins on cost.", theme: "high-traffic" },

  // --- Hardware & Server Tuning ---
  { id: "ht-66", label: "RAM is king for web apps. More RAM = more cache, more connections, more workers. 32GB RAM on a web server handles 10,000+ concurrent users comfortably.", theme: "high-traffic" },
  { id: "ht-67", label: "CPU cores: web servers are I/O bound, not CPU bound. 4-8 cores is enough for most apps. Exception: image processing, AI inference — these need more cores.", theme: "high-traffic" },
  { id: "ht-68", label: "SSD vs HDD: SSD is 100x faster for random reads. Database servers MUST use SSD. NVMe SSD is 5x faster than SATA SSD. Say: 'NVMe storage gives us 500,000 IOPS.'", theme: "high-traffic" },
  { id: "ht-69", label: "Worker processes: Node.js is single-threaded but PM2 cluster mode runs N workers (N = CPU cores). 8-core = 8 workers = 8x throughput. Say: 'PM2 cluster utilizes all CPU cores.'", theme: "high-traffic" },
  { id: "ht-70", label: "Database server sizing: prioritize RAM (for caching query results), then SSD (for fast reads), then CPU. A 64GB RAM PostgreSQL server can cache most medium databases entirely in memory.", theme: "high-traffic" },
  { id: "ht-71", label: "Connection limits: each PostgreSQL connection uses ~10MB RAM. 500 connections = 5GB RAM just for connections. Use PgBouncer to pool — 50 real connections serve 1000 app connections.", theme: "high-traffic" },
  { id: "ht-72", label: "Network bandwidth: a 1Gbps connection handles ~125MB/s. For 10,000 users loading a 500KB page simultaneously = 5GB = 40 seconds. Solution: CDN for static assets.", theme: "high-traffic" },

  // --- Performance Patterns ---
  { id: "ht-73", label: "The thundering herd problem: cache expires, 1000 requests simultaneously hit the database. Solution: cache stampede protection — only one request fetches from DB, others wait for cache.", theme: "high-traffic" },
  { id: "ht-74", label: "Rate limiting patterns: token bucket (smooth, allows bursts), sliding window (strict per-interval), leaky bucket (constant rate). Say: 'Token bucket allows brief bursts while maintaining average rate.'", theme: "high-traffic" },
  { id: "ht-75", label: "Back-pressure: when a service is overwhelmed, it signals upstream to slow down. Like telling the kitchen 'stop sending orders, the dining room is full.' Prevents cascading overload.", theme: "high-traffic" },
  { id: "ht-76", label: "Graceful degradation: when traffic spikes, disable non-critical features. Turn off recommendations, reduce image quality, serve cached pages. Core functionality stays alive.", theme: "high-traffic" },
  { id: "ht-77", label: "Pre-warming: before a known traffic spike (sale, event), pre-scale servers and pre-fill caches. Don't wait for auto-scaling. Say: 'We pre-warmed 50 servers before the event launch.'", theme: "high-traffic" },
  { id: "ht-78", label: "Connection keep-alive: reuse TCP connections instead of creating new ones per request. Reduces handshake overhead. nginx keepalive + HTTP/2 multiplexing = massive performance gain.", theme: "high-traffic" },
  { id: "ht-79", label: "Database query batching: instead of 100 individual queries, batch into 1 query that returns 100 results. N+1 query problem is the #1 performance killer in web apps.", theme: "high-traffic" },
  { id: "ht-80", label: "Asynchronous processing: don't make users wait. Send email? Queue it. Generate PDF? Queue it. Resize image? Queue it. Return 'processing' immediately, notify when done.", theme: "high-traffic" },

  // --- Architecture Patterns for Scale ---
  { id: "ht-81", label: "VISA's architecture: 4 global processing centers (2 US, 1 UK, 1 Singapore). Each processes independently. Transaction → Authorization → Clearing → Settlement. Triple redundancy at every layer.", theme: "high-traffic" },
  { id: "ht-82", label: "VISA's VisaNet: custom-built network (not the public internet). Dedicated fiber optic lines. Message format: ISO 8583. Authorization in <1 second. Uptime: 99.999% (5 minutes downtime/year).", theme: "high-traffic" },
  { id: "ht-83", label: "Netflix's architecture: Zuul (API gateway) → Eureka (service discovery) → Ribbon (client-side load balancing) → Hystrix (circuit breaker) → Kafka (event streaming). All open-sourced.", theme: "high-traffic" },
  { id: "ht-84", label: "Google's architecture: Custom hardware (TPUs for AI, custom servers), Bigtable (distributed database), Spanner (globally consistent DB), Borg (precursor to Kubernetes), Colossus (file system).", theme: "high-traffic" },
  { id: "ht-85", label: "Amazon's architecture lesson: every team's service MUST be accessible via API. No exceptions. No direct database access. This one rule made AWS possible.", theme: "high-traffic" },

  // --- Monitoring & Observability at Scale ---
  { id: "ht-86", label: "The three pillars of observability: Logs (what happened), Metrics (how many/how fast), Traces (the journey of one request across services). You need all three.", theme: "high-traffic" },
  { id: "ht-87", label: "Prometheus + Grafana: the standard open-source monitoring stack. Prometheus collects metrics, Grafana visualizes them. Real-time dashboards for CPU, memory, request rates, error rates.", theme: "high-traffic" },
  { id: "ht-88", label: "Distributed tracing (Jaeger, Zipkin): follow one request across 20 microservices. See exactly where it spent time. Say: 'Tracing showed 80% of latency was in the payment gateway call.'", theme: "high-traffic" },
  { id: "ht-89", label: "Alerting best practices: alert on symptoms (high error rate), not causes (CPU spike). Reduce alert fatigue. On-call should get <5 alerts/week. Every alert should be actionable.", theme: "high-traffic" },
  { id: "ht-90", label: "Chaos engineering: Netflix's Chaos Monkey randomly kills production servers. If your system can't handle one server dying, it can't handle real failures. Test resilience deliberately.", theme: "high-traffic" },

  // --- Content Delivery & Edge ---
  { id: "ht-91", label: "CDN architecture: origin server + 200+ edge servers (PoPs). User in Mumbai gets content from Mumbai PoP (5ms), not US origin (200ms). Cloudflare, AWS CloudFront, Fastly.", theme: "high-traffic" },
  { id: "ht-92", label: "Edge computing: run code at CDN edge locations. User's request is processed at the nearest server. Cloudflare Workers, AWS Lambda@Edge. Sub-10ms response times globally.", theme: "high-traffic" },
  { id: "ht-93", label: "Static site + API architecture: pre-build HTML pages (SSG), serve from CDN. Dynamic data via API. The CDN handles 99% of requests. Origin server barely sweats.", theme: "high-traffic" },
  { id: "ht-94", label: "Image optimization: serve WebP/AVIF (50% smaller than JPEG), use responsive images (srcset), lazy load below-fold images. Images are typically 60% of page weight.", theme: "high-traffic" },
  { id: "ht-95", label: "HTTP/2 multiplexing: multiple requests over a single TCP connection. No head-of-line blocking. HTTP/3 uses QUIC (UDP-based) — even faster. Enable these on nginx.", theme: "high-traffic" },

  // --- Data Architecture ---
  { id: "ht-96", label: "CQRS at scale: separate read and write databases. Writes go to PostgreSQL (consistency). Reads go to Elasticsearch (speed). Sync via event streaming.", theme: "high-traffic" },
  { id: "ht-97", label: "Event sourcing for financial systems: don't store 'balance = 5000'. Store every transaction. Replay to calculate balance. Perfect audit trail. VISA and banks use this.", theme: "high-traffic" },
  { id: "ht-98", label: "Time-series databases: InfluxDB, TimescaleDB for metrics, IoT, and monitoring data. Optimized for time-based queries. Say: '1 billion data points queried in milliseconds.'", theme: "high-traffic" },
  { id: "ht-99", label: "Data partitioning strategies: by time (last month vs. archive), by geography (India vs. US data), by customer (tenant isolation). Each reduces query scope.", theme: "high-traffic" },
  { id: "ht-100", label: "Polyglot persistence: use the right database for each job. PostgreSQL for transactions, Redis for cache, Elasticsearch for search, S3 for files. Don't force one DB to do everything.", theme: "high-traffic" },

  // --- Real-World Scaling Stories ---
  { id: "ht-101", label: "Stack Overflow serves 1.3B page views/month on just 9 web servers. Secret: aggressive caching, SQL Server optimized queries, minimal microservices. Proof that simple architecture scales.", theme: "high-traffic" },
  { id: "ht-102", label: "Wikipedia runs one of the top 10 websites on ~300 servers. Secret: Varnish cache in front of everything, MediaWiki PHP, MariaDB with aggressive read caching. Open source stack.", theme: "high-traffic" },
  { id: "ht-103", label: "Shopify handles $7.5B in Black Friday sales. Architecture: Rails monolith (yes, a monolith!), pods (isolated groups of shops), MySQL sharding, Lua-based load balancing.", theme: "high-traffic" },
  { id: "ht-104", label: "Discord handles 4M concurrent voice users. Architecture: Elixir for real-time, Rust for performance-critical paths, Cassandra for messages, custom voice infrastructure.", theme: "high-traffic" },
  { id: "ht-105", label: "IRCTC (Indian Railways) handles 25K tickets/minute during Tatkal. Architecture: moved from mainframe to cloud, CDN for static content, queue-based ticket processing, aggressive caching.", theme: "high-traffic" },

  // --- Networking & Protocol Optimization ---
  { id: "ht-106", label: "TCP tuning: increase tcp_max_syn_backlog, enable tcp_fastopen, tune tcp_keepalive_time. Default Linux TCP settings are designed for reliability, not performance.", theme: "high-traffic" },
  { id: "ht-107", label: "HTTP keep-alive: reuse TCP connections. Creating a new TCP connection = 3-way handshake (1 round trip). Keep-alive eliminates this for subsequent requests.", theme: "high-traffic" },
  { id: "ht-108", label: "Compression: gzip/brotli compress HTML, CSS, JS by 70-90%. A 500KB page becomes 50KB over the wire. Enable in nginx: `gzip on; gzip_types text/html application/json;`", theme: "high-traffic" },
  { id: "ht-109", label: "DNS resolution caching: each DNS lookup takes 20-50ms. Cache DNS results locally. Use a local DNS resolver. Reduce external lookups per page.", theme: "high-traffic" },
  { id: "ht-110", label: "WebSocket vs. polling: polling checks every 5 seconds (wasteful). WebSocket maintains a permanent connection (efficient). For real-time features, always choose WebSocket.", theme: "high-traffic" },

  // --- Reliability & Disaster Recovery ---
  { id: "ht-111", label: "The five 9s: 99.999% uptime = 5.26 minutes downtime/year. VISA achieves this. Requires: redundancy at every layer, auto-failover, no single point of failure.", theme: "high-traffic" },
  { id: "ht-112", label: "Active-active vs. active-passive: active-active = both data centers handle traffic. Active-passive = one waits idle as backup. Active-active = better utilization, harder to implement.", theme: "high-traffic" },
  { id: "ht-113", label: "Database failover: master dies → promote replica to master → redirect traffic. Automated with tools like Patroni (PostgreSQL), Orchestrator (MySQL). Target: <30 second failover.", theme: "high-traffic" },
  { id: "ht-114", label: "Multi-region deployment: deploy in at least 2 geographic regions. If ap-south-1 (Mumbai) has an outage, traffic routes to ap-southeast-1 (Singapore). Distance = latency trade-off.", theme: "high-traffic" },
  { id: "ht-115", label: "Backup strategy: 3-2-1 rule. 3 copies of data, on 2 different media types, with 1 copy offsite. Test restores monthly. A backup you've never tested isn't a backup.", theme: "high-traffic" },

  // --- Cost Optimization at Scale ---
  { id: "ht-116", label: "Spot/preemptible instances: AWS Spot = 60-90% cheaper. Can be terminated with 2-minute notice. Perfect for batch jobs, CI/CD, non-critical workers. Not for databases.", theme: "high-traffic" },
  { id: "ht-117", label: "Reserved instances: commit to 1-3 years = 30-60% discount. Use for baseline capacity. Spot for burst. On-demand for the rest. Optimize the cost mix.", theme: "high-traffic" },
  { id: "ht-118", label: "Right-sizing: most servers are over-provisioned. Monitor actual CPU/RAM usage. A server using 20% CPU can be halved. Say: 'Right-sizing reduced our cloud bill by 40%.'", theme: "high-traffic" },
  { id: "ht-119", label: "Serverless for spiky workloads: pay only when code runs. $0 when idle. Perfect for APIs with unpredictable traffic. AWS Lambda, Vercel Functions.", theme: "high-traffic" },
  { id: "ht-120", label: "Data transfer costs are the hidden cloud killer. Data IN is free. Data OUT is expensive. Use CDN, compress everything, keep data in the same region as compute.", theme: "high-traffic" },

  // --- Security at Scale ---
  { id: "ht-121", label: "DDoS protection: Cloudflare absorbs up to 100 Tbps of attack traffic. Their global network is larger than most attacks. Say: 'Cloudflare mitigates DDoS attacks before they reach our servers.'", theme: "high-traffic" },
  { id: "ht-122", label: "WAF rules for high traffic: rate limit per IP (100 req/min), block known bad user-agents, challenge suspicious traffic with CAPTCHA, geographic blocking for irrelevant regions.", theme: "high-traffic" },
  { id: "ht-123", label: "Secrets management: never hardcode API keys. Use HashiCorp Vault, AWS Secrets Manager, or environment variables. Rotate secrets automatically. Say: 'Secrets are rotated every 90 days automatically.'", theme: "high-traffic" },
  { id: "ht-124", label: "TLS everywhere: encrypt ALL traffic, even internal service-to-service. Zero-trust networking. Let's Encrypt for free certificates. Auto-renewal via certbot.", theme: "high-traffic" },
  { id: "ht-125", label: "API security at scale: OAuth 2.0 + JWT tokens + rate limiting + IP whitelisting + request signing. Multiple layers. No single point of security failure.", theme: "high-traffic" },

  // --- Practical Architecture Decisions ---
  { id: "ht-126", label: "Architecture rule: start with a monolith. Extract services only when you have a specific scaling need. Premature microservices = premature complexity. Amazon started as a monolith.", theme: "high-traffic" },
  { id: "ht-127", label: "The 'boring technology' principle: use proven, well-understood tech. PostgreSQL over the newest NewSQL. nginx over the latest proxy. Boring tech has fewer surprises at 3 AM.", theme: "high-traffic" },
  { id: "ht-128", label: "Capacity planning formula: current peak × 3 = target capacity. If you handle 1000 req/s today, design for 3000 req/s. Growth + spikes + safety margin.", theme: "high-traffic" },
  { id: "ht-129", label: "The single most impactful optimization: add a cache layer (Redis) between your app and database. This one change often improves performance by 10-100x.", theme: "high-traffic" },
  { id: "ht-130", label: "Performance budget: set hard limits. Page load <2 seconds. API response <200ms. Time to first byte <100ms. If any metric exceeds budget, fix it before adding features.", theme: "high-traffic" },

  // --- Advanced Patterns ---
  { id: "ht-131", label: "Consistent hashing: distribute data across servers so adding/removing a server only moves ~1/N of the data. Used by DynamoDB, Cassandra, and CDNs.", theme: "high-traffic" },
  { id: "ht-132", label: "Bloom filter: probabilistic data structure that tells you 'definitely not in set' or 'probably in set.' Used by databases to avoid unnecessary disk reads. Incredibly space-efficient.", theme: "high-traffic" },
  { id: "ht-133", label: "Leader election: in a distributed system, one node must be the leader (e.g., for writes). ZooKeeper, etcd handle this. If leader dies, new election in seconds.", theme: "high-traffic" },
  { id: "ht-134", label: "Gossip protocol: nodes share information by 'gossiping' to random neighbors. Eventually, all nodes know everything. Used by Cassandra, Consul. Scalable and fault-tolerant.", theme: "high-traffic" },
  { id: "ht-135", label: "Write-ahead log (WAL): before changing data, write the change to a log. If server crashes mid-write, replay the log to recover. PostgreSQL, Kafka, and most databases use WAL.", theme: "high-traffic" },

  // --- Interview & Discussion Questions ---
  { id: "ht-136", label: "System design question: 'How would you design a URL shortener like bit.ly?' Answer: hash function → key-value store (Redis/DynamoDB) → 301 redirect. Handles billions of URLs.", theme: "high-traffic" },
  { id: "ht-137", label: "System design question: 'How would you design Twitter's feed?' Answer: fan-out on write (pre-compute feeds), celebrity exception (fan-out on read for huge accounts), Redis timeline cache.", theme: "high-traffic" },
  { id: "ht-138", label: "System design question: 'How would you handle 100K concurrent WebSocket connections?' Answer: Redis Pub/Sub for message distribution, sticky sessions or shared state, horizontal scaling with load balancer.", theme: "high-traffic" },
  { id: "ht-139", label: "System design question: 'How would you design UPI?' Answer: message queue for transactions, distributed database with sharding, circuit breakers for bank API failures, idempotency keys to prevent double-charging.", theme: "high-traffic" },
  { id: "ht-140", label: "System design question: 'How would you migrate a monolith to microservices?' Answer: strangler fig pattern — extract one service at a time, run both in parallel, gradually redirect traffic.", theme: "high-traffic" },

  // --- Quick Reference Numbers ---
  { id: "ht-141", label: "Know your numbers: L1 cache: 1ns, L2 cache: 4ns, RAM: 100ns, SSD read: 150μs, HDD seek: 10ms, Network round trip (same datacenter): 500μs, CA→Mumbai: 150ms.", theme: "high-traffic" },
  { id: "ht-142", label: "Know your numbers: 1 PostgreSQL server (32GB RAM, SSD) handles ~10,000 simple queries/second. With connection pooling and indexing: 50,000+. Most apps never need more.", theme: "high-traffic" },
  { id: "ht-143", label: "Know your numbers: Redis handles 100,000+ operations/second on a single node. With cluster mode: millions/second. This is why caching is the #1 performance optimization.", theme: "high-traffic" },
  { id: "ht-144", label: "Know your numbers: nginx handles 10,000+ concurrent connections per worker process. 8 workers = 80,000+ concurrent connections. One $20/month server handles most Indian websites.", theme: "high-traffic" },
  { id: "ht-145", label: "Know your numbers: a well-optimized Node.js server handles 10,000-30,000 requests/second on a 4-core machine. With clustering (PM2): 40,000-120,000 req/s.", theme: "high-traffic" },

  // --- Philosophy of Scale ---
  { id: "ht-146", label: "Premature optimization is the root of all evil — Knuth. But premature scaling is the root of all bankrupt startups. Scale when you need it, not before.", theme: "high-traffic" },
  { id: "ht-147", label: "The 'good enough' architecture: don't design for Google-scale traffic when you have 1000 users. The best architecture is one that matches your CURRENT scale with room to grow.", theme: "high-traffic" },
  { id: "ht-148", label: "Vertical scaling first: it's cheaper, simpler, and works until it doesn't. A $100/month server handles more than most people think. Only go horizontal when you must.", theme: "high-traffic" },
  { id: "ht-149", label: "The cost of complexity: every layer of abstraction (K8s, microservices, distributed databases) adds operational cost. Simple systems are reliable systems. Choose complexity only when forced.", theme: "high-traffic" },
  { id: "ht-150", label: "The ultimate scaling secret: measure first, optimize second. Profile your actual bottleneck. It's almost never where you think it is. Data-driven optimization > gut feeling.", theme: "high-traffic" },
];
