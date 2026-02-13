#\!/bin/bash
# Metrics script for Olistic (PM2 app)
export HOME=/root
export PM2_HOME=/root/.pm2

/usr/bin/pm2 jlist 2>/dev/null | python3 -c '
import sys, json
try:
    apps = json.load(sys.stdin)
    for app in apps:
        if app.get("name") == "olistic":
            cpu = app.get("monit", {}).get("cpu", 0)
            mem = app.get("monit", {}).get("memory", 0) // 1024 // 1024
            restarts = app.get("pm2_env", {}).get("restart_time", 0)
            uptime = app.get("pm2_env", {}).get("pm_uptime", 0)
            import time
            if uptime:
                uptime_sec = (time.time() * 1000 - uptime) / 1000
                days = int(uptime_sec // 86400)
                hours = int((uptime_sec % 86400) // 3600)
                if days > 0:
                    uptime_str = f"{days}d {hours}h"
                else:
                    uptime_str = f"{hours}h"
            else:
                uptime_str = "N/A"
            metrics = [
                {"label": "CPU", "value": f"{cpu:.1f}%", "color": "#3498db"},
                {"label": "Memory", "value": f"{mem}MB", "color": "#9b59b6"},
                {"label": "Restarts", "value": str(restarts), "color": "#e67e22"},
                {"label": "Uptime", "value": uptime_str, "color": "#27ae60"}
            ]
            print(json.dumps(metrics))
            break
except Exception as e:
    print("[]")
'
