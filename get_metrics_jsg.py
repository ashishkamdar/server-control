#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta

DB_PATH = "/var/www/jsg-seating/data/jsg_seating.db"
TICKETS_DIR = "/var/www/jsg-seating/static/tickets"
STATE_FILE = "/var/www/jsg-seating/data/autoscaler_state.txt"
ACTIVE_SCRIPT = "/var/www/jsg-seating/count_active.sh"
NGINX_LOG = "/var/log/nginx/access.log"

def get_metrics():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Ticket count (HTML files in tickets dir)
        ticket_count = 0
        if os.path.exists(TICKETS_DIR):
            ticket_count = len([f for f in os.listdir(TICKETS_DIR)
                               if f.endswith(".html") and "_admin" not in f])

        # Last 24 hours lookups
        yesterday = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("SELECT COUNT(*) FROM ticket_access_logs WHERE accessed_at >= ?", (yesterday,))
        recent_lookups = cur.fetchone()[0]

        conn.close()

        # Get worker PIDs and metrics
        worker_count = 0
        total_cpu_pct = 0.0
        total_cpu_sec = 0
        total_ram_mb = 0.0
        oldest_worker_secs = 0
        worker_pids = []

        try:
            result = subprocess.run(
                ["pgrep", "-f", "jsg-seating.*gunicorn"],
                capture_output=True, text=True
            )
            pids = [p for p in result.stdout.strip().split("\n") if p]
            worker_count = max(0, len(pids) - 1)  # -1 for master

            for pid in pids:
                worker_pids.append(pid)
                # Get CPU %, CPU time, RAM %, and elapsed time
                ps_result = subprocess.run(
                    ["ps", "-p", pid, "-o", "%cpu,cputime,%mem,etimes", "--no-headers"],
                    capture_output=True, text=True
                )
                parts = ps_result.stdout.strip().split()
                if len(parts) >= 4:
                    # CPU %
                    total_cpu_pct += float(parts[0])

                    # Parse CPU time (HH:MM:SS or MM:SS)
                    time_parts = parts[1].split(":")
                    if len(time_parts) == 3:
                        total_cpu_sec += int(time_parts[0]) * 3600 + int(time_parts[1]) * 60 + int(time_parts[2])
                    elif len(time_parts) == 2:
                        total_cpu_sec += int(time_parts[0]) * 60 + int(time_parts[1])

                    # RAM
                    mem_pct = float(parts[2])
                    total_ram_mb += mem_pct / 100 * 8000

                    # Elapsed time (worker age)
                    elapsed_secs = int(parts[3])
                    if elapsed_secs > oldest_worker_secs:
                        oldest_worker_secs = elapsed_secs
        except:
            pass

        # Calculate memory per worker
        mem_per_worker = 0
        if worker_count > 0:
            mem_per_worker = total_ram_mb / worker_count

        # Format worker age nicely
        if oldest_worker_secs >= 86400:
            worker_age_str = f"{oldest_worker_secs // 86400}d {(oldest_worker_secs % 86400) // 3600}h"
        elif oldest_worker_secs >= 3600:
            worker_age_str = f"{oldest_worker_secs // 3600}h {(oldest_worker_secs % 3600) // 60}m"
        elif oldest_worker_secs >= 60:
            worker_age_str = f"{oldest_worker_secs // 60}m"
        else:
            worker_age_str = f"{oldest_worker_secs}s"

        # Format CPU time nicely
        if total_cpu_sec >= 3600:
            cpu_time_str = f"{total_cpu_sec // 3600}h {(total_cpu_sec % 3600) // 60}m"
        elif total_cpu_sec >= 60:
            cpu_time_str = f"{total_cpu_sec // 60}m {total_cpu_sec % 60}s"
        else:
            cpu_time_str = f"{total_cpu_sec}s"

        # CPU value with time in smaller font (using HTML)
        cpu_display = f"{total_cpu_pct:.1f}% <small style=\"font-size:0.7em;color:#888\">({cpu_time_str})</small>"

        # Get ACTIVE visitors from Nginx logs (last 5 min) via helper script
        active_users = 0
        try:
            result = subprocess.run([ACTIVE_SCRIPT], capture_output=True, text=True)
            active_users = int(result.stdout.strip() or 0)
        except:
            pass

        # Get avg response time from nginx logs (last 100 requests to jsg1.areakpi.in)
        avg_response_ms = 0
        try:
            # Parse nginx logs for request_time (last field in log format)
            result = subprocess.run(
                ["bash", "-c", f"grep 'jsg1.areakpi.in' {NGINX_LOG} 2>/dev/null | tail -100 | awk '{{print $NF}}' | grep -E '^[0-9.]+$'"],
                capture_output=True, text=True
            )
            times = [float(t) for t in result.stdout.strip().split("\n") if t and re.match(r'^[0-9.]+$', t)]
            if times:
                avg_response_ms = int(sum(times) / len(times) * 1000)
        except:
            pass

        # Get autoscaler state
        autoscale_status = "off"
        req_per_min = 0
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "jsg-autoscaler"],
                capture_output=True, text=True
            )
            if result.stdout.strip() == "active":
                autoscale_status = "on"
                if os.path.exists(STATE_FILE):
                    with open(STATE_FILE) as f:
                        parts = f.read().strip().split("|")
                        if len(parts) >= 3:
                            last_action = parts[1]
                            req_per_min = int(parts[2])
                            if last_action == "scaled_up":
                                autoscale_status = "↑"
                            elif last_action == "scaled_down":
                                autoscale_status = "↓"
                            else:
                                autoscale_status = "auto"
        except:
            pass

        metrics = [
            {"label": "Workers", "value": worker_count, "color": "#9b59b6"},
            {"label": "CPU", "value": cpu_display, "color": "#3498db"},
            {"label": "RAM", "value": f"{int(total_ram_mb)}MB", "color": "#9b59b6"},
            {"label": "Req/min", "value": req_per_min, "color": "#3498db"},
            {"label": "Active 5m", "value": active_users, "color": "#00b894"},
            {"label": "Lookups 24h", "value": recent_lookups},
            {"label": "Avg Resp", "value": f"{avg_response_ms}ms", "color": "#e74c3c"},
            {"label": "MB/Worker", "value": f"{int(mem_per_worker)}", "color": "#f39c12"},
            {"label": "Worker Age", "value": worker_age_str, "color": "#1abc9c"},
        ]

        print(json.dumps(metrics))

    except Exception as e:
        print(json.dumps([{"label": "Error", "value": str(e)[:30]}]))

if __name__ == "__main__":
    get_metrics()
