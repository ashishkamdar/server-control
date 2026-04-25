#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta

DB_PATH = "/var/www/jsg-seating/data/jsg_seating.db"
TICKETS_DIR = "/var/www/jsg-seating/static/tickets"
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

        # Last 24 hours ticket views from nginx logs
        recent_lookups = 0
        unique_lookups = 0
        try:
            today_str = datetime.now().strftime("%d/%b/%Y")
            yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%d/%b/%Y")
            date_filter = f"grep '/seats/' {NGINX_LOG} 2>/dev/null | grep -E '({today_str}|{yesterday_str})' | grep -E '\" (200|304) ' | grep -v 'bot' | grep -v 'Bot' | grep -v 'curl/' | grep -v 'spider' | grep -v 'crawler' | grep -E '(Safari/|Chrome/|Firefox/)'"
            result = subprocess.run(
                ["bash", "-c", f"{date_filter} | wc -l"],
                capture_output=True, text=True
            )
            recent_lookups = int(result.stdout.strip() or 0)
            result = subprocess.run(
                ["bash", "-c", f"{date_filter} | grep -oP '/seats/\\K[A-Z]+-[0-9]+' | sort -u | wc -l"],
                capture_output=True, text=True
            )
            unique_lookups = int(result.stdout.strip() or 0)
        except:
            pass

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

        # Requests per minute from nginx (last 5 min average)
        req_per_min = 0
        try:
            result = subprocess.run(
                ["bash", "-c", f"awk -v cutoff=\"$(date -d '5 minutes ago' '+%d/%b/%Y:%H:%M')\" '$0 ~ /jsg1.areakpi.in/ && $4 >= \"[\"cutoff' {NGINX_LOG} 2>/dev/null | wc -l"],
                capture_output=True, text=True
            )
            count_5m = int(result.stdout.strip() or 0)
            req_per_min = count_5m // 5
        except:
            pass

        metrics = [
            {"label": "Workers", "value": worker_count, "color": "#9b59b6"},
            {"label": "CPU", "value": cpu_display, "color": "#3498db"},
            {"label": "RAM", "value": f"{int(total_ram_mb)}MB", "color": "#9b59b6"},
            {"label": "Req/min", "value": req_per_min, "color": "#3498db"},
            {"label": "Active 5m", "value": active_users, "color": "#00b894"},
            {"label": "Lookups 24h", "value": f"{recent_lookups} ({unique_lookups}u)"},
            {"label": "Avg Resp", "value": f"{avg_response_ms}ms", "color": "#e74c3c"},
            {"label": "MB/Worker", "value": f"{int(mem_per_worker)}", "color": "#f39c12"},
            {"label": "Worker Age", "value": worker_age_str, "color": "#1abc9c"},
        ]

        print(json.dumps(metrics))

    except Exception as e:
        print(json.dumps([{"label": "Error", "value": str(e)[:30]}]))

if __name__ == "__main__":
    get_metrics()
