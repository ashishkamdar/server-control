# Server Control — Access & Operations Plan

## Server Access

- **Host**: Nuremberg (`46.225.62.158`)
- **SSH**: `ssh nuremberg` (port 1476, root, key-based auth)
- **Control Panel**: https://control.areakpi.in
- **Password**: stored in `config.json` (field: `password`) — single login only (nginx basic auth removed 2026-04-02)
- **Session**: 1-year rolling cookie, refreshes on every page load — login once, stay logged in

## Git Repositories

| Repo | URL | Contents |
|------|-----|----------|
| **Server Control** | https://github.com/ashishkamdar/server-control | Server control dashboard (Go app) |
| **JSG Seating (main)** | https://github.com/ashishkamdar/jsg1 | Main JSG Seating app — admin, allocation, groups, tickets, templates, models |
| **JSG Scanner** | https://github.com/ashishkamdar/jsg1-scanner | Kiosk scanner only — scanner_kiosk.html, scan routes, service worker, PWA |

All three deploy to the same Nuremberg server. JSG repos map to `/var/www/jsg-seating/`.

## Hosted Applications (monitored in control panel)

| App | URL | Local Port | Workdir | Stack | Process Manager |
|-----|-----|-----------|---------|-------|-----------------|
| Server Control | https://control.areakpi.in | 9000 | `/opt/server-control` | Go, nginx | systemd |
| hetalkamdar.com | https://hetalkamdar.com | 8080 | `/var/www/html` | WordPress, Apache, MySQL, PHP 8.3, Redis | systemd |
| areakpi.in | https://areakpi.in | — | `/var/www/areakpi-landing` | nginx static | — |
| JSG Seating | https://jsg1.areakpi.in | 5050 | `/var/www/jsg-seating` | Python, SQLite, gunicorn | systemd |
| JSG Scanner (sidecar) | https://jsg1.areakpi.in/scan/kiosk | 5050 | `/var/www/jsg-seating` | PWA, service worker | — (shares JSG Seating process) |
| JSG Superadmin (sidecar) | https://jsg1.areakpi.in/superadmin | 5050 | `/var/www/jsg-seating` | Multi-tenant management | — (shares JSG Seating process) |
| Change Requests | https://cr.areakpi.in | 5001 | `/var/www/change-requests` | Python, SQLite, gunicorn | PM2 |
| Olistic | https://olistic.areakpi.in | 3000 | `/var/www/olistic` | Next.js, Firebase | PM2 |
| Netra Security | https://netram.areakpi.in | 3001 | `/var/www/netra` | Next.js | PM2 |
| NSWADI | https://ns.areakpi.in | 5002 | `/home/nswadi/app` | Python, gunicorn | systemd |
| Nginx | — | — | `/etc/nginx` | Reverse proxy | systemd |
| Security Dashboard | — (in control panel) | — | `/opt/server-control` | fail2ban, iptables | systemd |
| MGCL Tournament | https://mgcl.areakpi.in | 9001 | `/home/adminuser/mgcl_tournament` | Python, gunicorn | systemd |
| MG Demo | https://mgdemo.areakpi.in | 9000 | `/var/www/matunga_gymkhana` | Python, gunicorn | systemd |
| nymaara.com | https://nymaara.com | 3100 | `/var/www/nymaara` | Next.js, SQLite, Supabase, Razorpay | PM2 |
| MMAM | https://mmam.areakpi.in | 3200 | `/root/Projects/mmam` | Next.js | PM2 |
| No Ransomware | https://no-ransomware.areakpi.in | 3004 | `/opt/noransomware-portal` | Node.js | PM2 |
| OSINT | https://osint.areakpi.in | 8100 | `/opt/osint/backend` | Python, Celery, uvicorn, Neo4j | PM2 (osint-api + osint-worker) |
| Server Tools | https://server-tools.areakpi.in | 3003 | `/var/www/servertools-web` | Next.js | PM2 |
| StockWords | https://sw.areakpi.in | 3005 | `/var/www/stockwords` | Next.js | PM2 |
| RSS World | https://rss.areakpi.in | 3006 | `/opt/rss-world` | Next.js, TSX workers | PM2 (rss-world + rss-scraper + crude-signal + algo-trading) |
| Netra Desktop | https://netra-desktop.areakpi.in | 3001 | `/root/netra/netra-desktop/cloud` | Rust, PostgreSQL | systemd (netra-cloud + netra-service) |
| NT Precious Metals | https://nt.areakpi.in | 3020 | `/var/www/nt-metals` | Next.js, SQLite | PM2 |

## Apps on nginx but NOT in control panel

| App | URL | Port | Reason |
|-----|-----|------|--------|
| KSPL | https://kspl.areakpi.in | 3007 | Not selected for monitoring |
| Staging | https://staging1.areakpi.in | — | Static staging site |
| JSG Demo | (behind jsg1 nginx on :5099) | 5099 | Demo/test instance |

## Dashboard Features

### Streaming Loading Screen
- **Instant TTFB** (~0.6ms) — HTML head + animated progress bar sent immediately via HTTP chunked streaming
- Shimmer-animated gradient progress bar with "Loading..." text
- Dashboard content replaces loader once data arrives (1.7s warm / 4.5s cold)
- Users never see a blank white screen, even on slow mobile connections

### Quick Controls (compact view)
- Compact table at top of dashboard showing all apps on one mobile screen
- **Two sections**: Running apps (top) and Inactive apps (dimmed, below)
- Columns: App Name, Status (dot), CPU %, RAM (MB), Disk Size, Start/Stop/Restart buttons
- **Sortable columns**: Click CPU ⇅, RAM ⇅, or Disk ⇅ headers to sort ascending/descending
- Disk usage refreshes once per day (cached, `du` is expensive)
- CPU/RAM refreshes every 60 seconds via cached `ps aux` + batched `pm2 pid`

### Port Reference (compact view)
- Shows all apps sorted by port number (client-side JS sort)
- Columns: PORT, APP, PROCS (process count), STATUS (green/red dot)
- Doubles as a **port conflict detector** — e.g., Server Control and MG Demo both claim :9000
- Apps without a port (nginx, security dashboard) pushed to bottom

### Orphan Process Monitor
- Detects unmanaged processes listening on ports (not under systemd `system.slice`)
- Shows in both Quick Controls area and Security Dashboard detail card
- Columns: Port, Process Name, PID, User, Memory, Uptime
- **Kill button** on each orphan with confirmation dialog
- Kill handler: SIGTERM → 3s grace → SIGKILL if still alive
- **Safety**: refuses to kill systemd-managed processes (checks `/proc/PID/cgroup`)
- Displays "No orphan processes detected" (green) when server is clean

### Per-App Detail Cards (below Quick Controls)
- Full metrics from each app's `metrics_cmd`
- Port number shown in each app's description (e.g., `[:3020]`)
- Error URLs (24h) parsed from nginx logs
- Worker controls (add/remove for gunicorn and PM2 apps)
- Auto-scaling (JSG Seating — based on req/worker thresholds)

### JSG Seating — Daily Ticket Logs
- Three sections: **Today**, **Yesterday**, **2 Days Ago**
- Each section header shows date, unique hits, and total hits
- Ticket accesses grouped by member code — repeat visits show as ×count
- Shows last access time, time ago, and devices used (iPhone, Android, Mac, etc.)
- Cached for 5 minutes (single `tac` of nginx access log, parsed in-memory)
- Replaced the old "Recent Tickets" section which showed ungrouped individual hits

### Slack Alerts
- **CPU**: 75% (info), 85% (warning), 95% (critical)
- **RAM**: 75% (info), 85% (warning), 95% (critical)
- **App crash**: alerts when a previously running app stops
- **Worker count**: alerts when workers drop below min or exceed max
- 5-minute cooldown between alerts of the same level

## App Config System

- **Primary config**: `/opt/server-control/config.json` — main app definitions
- **Drop-in configs**: `/opt/server-control/apps.d/*.json` — additional apps loaded at startup (merged with config.json)
- **Avoid duplicates**: If an app is in both `config.json` and `apps.d/`, it will appear twice. Keep each app in only one place.
- **App struct fields**: `name`, `description`, `workdir`, `port`, `start_cmd`, `stop_cmd`, `status_cmd`, `proc_match`, `deps`, `metrics_cmd`, `worker_pid_cmd`, `worker_min`, `worker_max`, `worker_add_cmd`, `worker_remove_cmd`, `worker_count_cmd`, `log_pattern`, `is_security_dashboard`, `auto_scale_enabled`, `auto_scale_up_threshold`, `auto_scale_down_threshold`, `alert_worker_min`, `alert_worker_max`

### HTTP Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/login` | No | Login page |
| POST | `/login` | No | Login form submission |
| GET | `/` | Yes | Main dashboard (streaming: loader then data) |
| POST | `/action` | Yes | Start/stop/restart/add_worker/remove_worker |
| POST | `/kill-orphan` | Yes | Kill an orphan process by PID (with cgroup safety check) |
| POST | `/autoscale` | Yes | Enable/disable auto-scaling |
| POST | `/worker-limits` | Yes | Update worker min/max |
| GET | `/logout` | No | Clear session cookie |

## Deployment Commands

### Server Control (this app)
```bash
# Deploy a single file + build + restart (preferred workflow)
scp -P 1476 main.go root@46.225.62.158:/opt/server-control/main.go && \
ssh nuremberg 'cd /opt/server-control && go build -o server-control main.go && systemctl restart server-control'

# Deploy just config changes (no rebuild needed, just restart)
scp -P 1476 config.json root@46.225.62.158:/opt/server-control/config.json && \
ssh nuremberg 'systemctl restart server-control'

# Note: server git is divergent from GitHub — use scp, not git pull
```

### JSG Seating
```bash
# Deploy
ssh nuremberg 'cd /var/www/jsg-seating && git pull'

# Restart (systemd managed)
ssh nuremberg 'systemctl restart jsg-seating'

# Database
ssh nuremberg 'sqlite3 /var/www/jsg-seating/data/jsg_seating.db ".tables"'
```

### PM2-managed apps (Olistic, Nymaara, MMAM, No Ransomware, OSINT, Server Tools, StockWords, RSS World, NT Precious Metals)
```bash
# Restart any PM2 app
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 restart <app-name>'

# View logs
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 logs <app-name> --lines 50'

# List all PM2 apps
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 list'
```

### OSINT (includes Neo4j)
```bash
# Start (also starts Neo4j)
ssh nuremberg 'systemctl start neo4j; export HOME=/root PM2_HOME=/root/.pm2; pm2 start osint-api && pm2 start osint-worker'

# Stop (also stops Neo4j to free ~486MB RAM)
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 stop osint-api; pm2 stop osint-worker; systemctl stop neo4j'
```

### RSS World (4 PM2 processes)
```bash
# Start all RSS World processes
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 start rss-world && pm2 start rss-scraper && pm2 start crude-signal && pm2 start algo-trading'

# Stop all (frees ~768MB RAM + significant CPU)
ssh nuremberg 'export HOME=/root PM2_HOME=/root/.pm2; pm2 stop rss-world; pm2 stop rss-scraper; pm2 stop crude-signal; pm2 stop algo-trading'
```

### Nginx
```bash
# Test config
ssh nuremberg 'nginx -t'

# Reload (after config changes)
ssh nuremberg 'systemctl reload nginx'

# Site configs
ssh nuremberg 'ls /etc/nginx/sites-enabled/'
```

## Key File Paths on Server

| Purpose | Path |
|---------|------|
| Nginx site configs | `/etc/nginx/sites-enabled/` |
| Nginx logs | `/var/log/nginx/access.log` |
| Server Control binary | `/opt/server-control/server-control` |
| Server Control config | `/opt/server-control/config.json` |
| Server Control source | `/opt/server-control/main.go` |
| Drop-in app configs | `/opt/server-control/apps.d/*.json` |
| JSG Seating DB | `/var/www/jsg-seating/data/jsg_seating.db` |
| JSG Seating metrics | `/var/www/jsg-seating/get_metrics.py` |
| Server Control metrics | `/opt/server-control/get_metrics_jsg.py`, `hetal_metrics.sh`, `security_metrics.sh`, `nginx_metrics.sh`, `olistic_metrics.sh`, `nymaara_metrics.sh`, `nt_gold_metrics.sh`, `scanner_metrics.sh`, `superadmin_metrics.sh` |
| fail2ban config | `/etc/fail2ban/` |
| PM2 config | `HOME=/root PM2_HOME=/root/.pm2` (must export before pm2 commands) |
| SSL certs | `/etc/letsencrypt/live/<domain>/` |
| Neo4j (used by OSINT) | systemd service `neo4j`, data at `/var/lib/neo4j` |

## Architecture Notes

- **Config-driven**: All apps are defined in `/opt/server-control/config.json` + `apps.d/*.json`. Adding/removing apps only requires editing JSON and restarting the service.
- **Streaming HTML**: Loading screen sent via HTTP chunked transfer immediately (~0.6ms TTFB). Data-dependent content follows after gathering completes.
- **Parallel app status**: All 21 app status checks run concurrently via goroutines (was sequential, causing 7.4s page loads).
- **Metrics**: Each app can optionally have a `metrics_cmd` that returns JSON array of `{label, value, color}` objects.
- **Process stats**: One `ps aux` call (cached 60s) + batched `pm2 pid` calls serve CPU/RAM for all apps. No `pm2 jlist` (it was causing 128% CPU spikes).
- **Disk stats**: One `du -sh` call for all workdirs, cached 24 hours.
- **Sidecar apps**: JSG Scanner and JSG Superadmin are "sidecar" entries — they share JSG Seating's gunicorn process on :5050 (same workdir, same `proc_match`). Their start/stop buttons display an info message directing operators to use JSG Seating controls. Status tracks the shared process. Each has its own metrics script (`scanner_metrics.sh`, `superadmin_metrics.sh`).
- **Auto-scaling**: JSG Seating supports auto-scaling via gunicorn worker management (TTIN/TTOU signals). Olistic and Nymaara support PM2 scaling.
- **Slack alerts**: Configured via `slack_webhook` in config.json. Alerts for CPU/RAM thresholds (75/85/95%), worker count changes, and app crashes.
- **Daily Ticket Logs**: JSG Seating parses nginx access logs for `/seats/` requests, grouped by day (Today/Yesterday/2 Days Ago) and by ticket code. Cached 5 minutes.
- **Security Dashboard**: Reads fail2ban stats, SSH fail counts, probe detection, and orphan process detection. All 5 data-gathering sections run in parallel within the script.
- **Orphan detection**: Uses `/proc/PID/cgroup` to check if a listening process is systemd-managed (fast, no subprocess per PID). Kill endpoint validates cgroup before allowing kill.
- **Quick Controls**: Two sections — running apps (with sortable CPU/RAM/Disk columns) and inactive apps (dimmed, below). Client-side JS sorting, no server calls.
- **Port Reference**: Port field (`json:"port"`) in App struct, sorted client-side by port number. Non-numeric ports (nginx, static) pushed to bottom.

## UI Theme — Royal Off-White (applied 2026-04-07)

Replaced the original dark navy theme (#1a1a2e/#16213e) with a warm, readable light theme. Designed for mobile readability.

| Element | Color | Hex |
|---------|-------|-----|
| Page background | Warm off-white | `#f5f3ef` |
| Cards | White + subtle border/shadow | `#fff` / border `#e8e4de` |
| Inner elements (stats, metrics) | Light warm gray | `#f0ede8` |
| Primary text | Dark charcoal | `#2c2c2c` |
| Page title / accent | Saddle brown | `#8b4513` |
| App names / links | Royal blue | `#2c5f8a` |
| Ports / orange accent | Warm brown | `#b8700d` |
| Purple accent (workers, PIDs) | Muted purple | `#7b5ea7` |
| Running status | Deep green | `#1a7a5a` |
| Stopped status / errors | Muted red | `#c0392b` |
| Warning / yellow | Dark goldenrod | `#b8860b` |
| Muted text | Gray | `#777` / `#888` / `#999` |
| Font | Georgia, Times New Roman, serif | — |

Design principles:
- **Warm tones** — off-white background avoids clinical feel, like aged paper
- **Serif font** (Georgia) — gives a traditional, refined dashboard look
- **Subtle shadows** — `box-shadow: 0 1px 3px rgba(0,0,0,.06)` on cards, no harsh borders
- **Darker status colors** — greens/reds darkened for readability on light background (not neon)
- **Consistent accent system** — brown for ports/warnings, blue for app names, purple for technical details

## Performance Notes

- **Page load timeline** (as of 2026-04-18):
  - TTFB: **0.6ms** (loading screen delivered instantly via HTTP streaming)
  - Full page (warm cache): **~1.4s** (bottleneck: slowest parallel app, typically security_metrics.sh at ~600ms)
  - Full page (cold): **~1.7s**
  - Previous: **7.4s** blocking TTFB (sequential app status, no streaming)
- **Key optimizations applied 2026-04-07**:
  - Parallelized `getAppStatus()` — 21 goroutines run concurrently (was sequential loop)
  - HTTP chunked streaming — loading screen sent before data gathering begins
  - Security metrics script parallelized (5 background jobs + cgroup-based orphan detection) — 2.3s → 0.65s
- **Key optimizations applied 2026-04-18**:
  - `nginx_metrics.sh`: Rewrote 8-pass grep/wc/awk into single-pass awk — **550ms → 73ms** (7.5x faster)
  - `security_metrics.sh`: Replaced `journalctl -u ssh` (417ms) with `grep` on auth.log (11ms); converted nginx log section to single-pass awk — **670ms → 600ms**
- **Subprocess budget per page load**: ~35 calls (all run in parallel)
  - 1x `ps aux` (cached 60s) — serves all apps' CPU/RAM
  - 1x batched `pm2 pid` (cached 60s) — one command gets all PM2 PIDs (replaced `pm2 jlist` which caused CPU spikes)
  - 1x `du -sh` (cached 24h) — serves all disk sizes
  - 1x `df` — system disk metrics
  - ~21x `StatusCmd` — one per app (run in parallel goroutines)
  - ~11x `MetricsCmd` — one per app with metrics (run in parallel goroutines)
  - ~3x `WorkerCountCmd` — apps with worker management
- **Page auto-refresh**: every 30 seconds via `<meta http-equiv="refresh">`
- **Heavy apps by RAM**: hetalkamdar.com (WordPress stack ~2.2G), Netra (7.5G disk), Olistic (2.4G disk)
- **Heavy apps by CPU**: RSS World scraper (burns CPU continuously when running — stop when not needed)

## Known Issues

- **Git divergence**: The server's `/opt/server-control` repo has divergent commits from GitHub. Use `scp` for deploying individual files. A full sync would require force-resetting the server repo.
- **ticket_access_logs**: This table in JSG Seating's SQLite DB is defined in the Flask/SQLAlchemy model (`TicketAccessLog`) but not in the Django project (`jsg1_seat_portal`). Schema: `id, member_code, event_type, ip_address, user_agent, accessed_at`. Fixed 2026-04-02 by recreating with correct schema and adding graceful error handling in `get_metrics_jsg.py`.
- **mgdemo port conflict**: MG Demo's systemd service binds to port 9000, same as Server Control. Currently stopped — would conflict if started.
- **PM2 proc_match**: PM2 apps run as `npm start` so `pgrep -f <app-name>` doesn't match. Fixed by using batched `pm2 pid` lookup as fallback (cached 60s).
- **PM2 pid returns "0" for stopped apps**: `pm2 pid <name>` returns `"0"` (not empty) when stopped, and may return multiple lines. Status commands must use `head -1` and check `!= "0"`. Fixed for all PM2 apps on 2026-04-02.
- **NEVER use `pm2 jlist`**: It loads all PM2 state into memory and can hang at 100%+ CPU. Use `pm2 pid <name>` instead.

## JSG Seating — Drama 2 Large Batch (Apr 8, Nehru Centre, 7:30 PM)

### Current State
- **1,061 total members**: 890 Large Batch + 171 Small Batch
- **890 ticket HTML files LIVE** on jsg1.areakpi.in (Large Batch only)
- **Live marker**: `2:B1` (Drama 2, Large Batch)
- **Batch dates independent**: Large Batch = Apr 8, Small Batch = Apr 5
- **D-15 is vacant** across all upcoming dramas

### Database Sync
- Excel (`Drama2_LargeBatch_Seating.xlsx`) ↔ Database ↔ Tickets: **890 members, 0 differences**
- 11 members added, 8 seats corrected, 10 fixed-seat members propagated to Dramas 3–10
- Excel has 3 sheets: main seating list, groupwise sorting, and "Fixed & Groupwise Sorting" with ticket links

### Bug Fixes Applied
- **Batch date independence**: Drama detail form now shows separate date fields per batch (Large/Small). Previously updating one batch's date affected both.
- **Batch import fix**: Added `Batch` to `ticket_generator.py` imports (was causing `NameError` on Go Live)
- **Daily ticket logs**: Filters out bots/curl/truncated UAs, reads `.gz` log files for 2-days-ago data

### Backups
- `/var/www/jsg-seating/data/jsg_2026.db.bak_20260405`
- `/var/www/jsg-seating/data/jsg_2026.db.bak2_20260405`

## Change Log

- **2026-04-18**: Added JSG Scanner and JSG Superadmin as sidecar apps of JSG Seating. Both share the same gunicorn process on :5050 — status syncs with JSG Seating, start/stop buttons direct operators to parent controls. Scanner metrics: Total Scans, Today, Active Event, Events, Scanners (`scanner_metrics.sh`). Superadmin metrics: Tenants, Active, Admins, Backups (`superadmin_metrics.sh`). Performance: rewrote `nginx_metrics.sh` from 8-pass grep/awk to single-pass awk (550ms → 73ms), replaced `journalctl` with grep on auth.log in `security_metrics.sh` (417ms → 11ms). Overall page load improved from ~2.2s → ~1.7s cold, ~1.7s → ~1.4s warm.
- **2026-04-07**: Added NT Precious Metals app (nt.areakpi.in, port 3020, PM2 `nt-metals`, Next.js + SQLite) with drop-in config (`apps.d/nt-gold.json`) and metrics script (`nt_gold_metrics.sh` — CPU, Memory, Restarts, Uptime, Req/1h). Added `port` field to App struct and all app configs — ports shown in descriptions and new Port Reference section (sorted by port, with process count and status). Added Orphan Process Monitor with cgroup-based detection and Kill button (SIGTERM → SIGKILL with cgroup safety check, `/kill-orphan` endpoint). Major performance overhaul: parallelized `getAppStatus()` via goroutines (7.4s → 1.7s), HTTP chunked streaming for instant loading screen (0.6ms TTFB), optimized `security_metrics.sh` (parallelized 5 sections + replaced `systemctl status` per-PID with `/proc/cgroup` reads, 2.3s → 0.65s). Redesigned UI from dark theme to royal off-white light theme — warm off-white background (#f5f3ef), white cards with subtle borders/shadows, Georgia serif font, saddle brown accents (#8b4513), royal blue app names (#2c5f8a), warm brown for ports (#b8700d), darker muted greens/reds for status indicators.
- **2026-04-05**: Synced DB with Excel for Drama 2 Large Batch (11 members added, 8 seats fixed). Propagated 10 fixed-seat members to Dramas 3–10. Fixed batch date independence bug (drama detail form now has separate date fields per batch). Fixed `Batch` import in ticket_generator.py. Generated 890 Large Batch tickets — all verified against Excel and DB. Added "Fixed & Groupwise Sorting" sheet and ticket links to Excel.
- **2026-04-04**: Replaced "Recent Tickets" with Daily Ticket Logs (Today/Yesterday/2 Days Ago) — grouped by ticket code with ×count, devices, and unique/total hit headers. Cached 5 minutes. Fixed log parsing to exclude bots/curl and read .gz files.
- **2026-04-02**: Fixed `ticket_access_logs` table (wrong schema after manual recreation). Added 5 apps (MMAM, No Ransomware, OSINT, Server Tools, StockWords) + RSS World + Netra Desktop. Extended session cookie to 1 year with rolling refresh. Removed nginx basic auth (single login only). Raised alert thresholds from 50/70/90% to 75/85/95%. Added Quick Controls compact view with sortable CPU/RAM/Disk columns and separate inactive section. Fixed subprocess spawning — cached `ps aux` + batched `pm2 pid` (replaced `pm2 jlist` which caused 128% CPU spikes). Cache TTL increased to 60s. Fixed PM2 status detection (`pm2 pid` returns "0" not empty for stopped apps). Stopped RSS World (CPU hog) and Neo4j (486MB RAM, only used by OSINT). Cleaned up duplicate apps from `apps.d/`.
