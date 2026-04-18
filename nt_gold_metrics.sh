#!/bin/bash
# Metrics script for NT Precious Metals (PM2 app)
export HOME=/root
export PM2_HOME=/root/.pm2

/usr/bin/pm2 pid nt-metals 2>/dev/null | head -1 | while read PID; do
  if [ -z "$PID" ] || [ "$PID" = "0" ]; then
    echo '[]'
    exit 0
  fi

  # Get CPU and memory from ps
  CPU=$(ps -p "$PID" -o %cpu= 2>/dev/null | tr -d ' ')
  MEM_KB=$(ps -p "$PID" -o rss= 2>/dev/null | tr -d ' ')
  MEM_MB=$((${MEM_KB:-0} / 1024))

  # Get restarts and uptime from PM2 (using pm2 show, not jlist)
  # Strip ANSI codes, then split on UTF-8 box char │ (\xe2\x94\x82)
  PM2_SHOW=$(/usr/bin/pm2 show nt-metals 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
  SEP=$'\xe2\x94\x82'
  RESTARTS=$(echo "$PM2_SHOW" | grep "restarts" | grep -v "unstable" | awk -F"$SEP" '{gsub(/^ +| +$/,"",$3); print $3}' | head -1)
  UPTIME=$(echo "$PM2_SHOW" | grep "uptime" | awk -F"$SEP" '{gsub(/^ +| +$/,"",$3); print $3}' | head -1)

  # Request count from nginx logs (last 1 hour)
  REQ_1H=$(awk -v d="$(date -d '1 hour ago' '+%d/%b/%Y:%H:%M:%S' 2>/dev/null || date -d '-1 hour' '+%d/%b/%Y:%H:%M:%S' 2>/dev/null)" '$0 ~ /nt\.areakpi\.in/ && $4 > "["d' /var/log/nginx/access.log 2>/dev/null | wc -l | tr -d ' ')

  cat <<EOF
[
  {"label": "CPU", "value": "${CPU:-0}%", "color": "#3498db"},
  {"label": "Memory", "value": "${MEM_MB}MB", "color": "#9b59b6"},
  {"label": "Restarts", "value": "${RESTARTS:-0}", "color": "#e67e22"},
  {"label": "Uptime", "value": "${UPTIME:-N/A}", "color": "#27ae60"},
  {"label": "Req/1h", "value": "${REQ_1H:-0}", "color": "#1abc9c"}
]
EOF
done
