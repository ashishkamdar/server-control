#!/bin/bash
# Security Dashboard Metrics - Optimized: parallel sections + fast cgroup-based orphan detection

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# === PARALLEL: Launch all independent data gathering ===

# 1. fail2ban stats
(
    banned=0; total_banned=0
    if command -v fail2ban-client &>/dev/null; then
        status_out=$(fail2ban-client status 2>/dev/null)
        banned=$(echo "$status_out" | grep -oP "Currently banned:\s*\K\d+" | awk "{s+=\$1} END {print s+0}" 2>/dev/null || echo 0)
        for jail in $(echo "$status_out" | grep "Jail list:" | sed "s/.*://;s/,//g"); do
            jban=$(fail2ban-client status "$jail" 2>/dev/null | grep -oP "Total banned:\s*\K\d+" || echo 0)
            total_banned=$((total_banned + jban))
        done
    fi
    echo "$banned|$total_banned" > "$TMPDIR/f2b"
) &

# 2. SSH fails (24h) — grep auth.log directly (much faster than journalctl)
(
    today_auth=$(date +"%b %d")
    today_auth2=$(date +"%b  %-d")
    yesterday_auth=$(date -d "yesterday" +"%b %d" 2>/dev/null || date -v-1d +"%b %d")
    yesterday_auth2=$(date -d "yesterday" +"%b  %-d" 2>/dev/null || date -v-1d +"%b  %-d")
    count=$(grep -cE "($today_auth|$today_auth2|$yesterday_auth|$yesterday_auth2).*(Failed password|Invalid user)" /var/log/auth.log 2>/dev/null) || count=0
    echo "${count:-0}" > "$TMPDIR/ssh"
) &

# 3. Nginx log analysis — single-pass awk for probes, attackers, blocked, last_attack
(
    today=$(date +"%d/%b/%Y")
    yesterday=$(date -d "yesterday" +"%d/%b/%Y" 2>/dev/null || date -v-1d +"%d/%b/%Y")
    awk -v today="$today" -v yesterday="$yesterday" '
    {
        if (!index($0, today) && !index($0, yesterday)) next

        is_probe = (index($0, ".env") || index($0, "wp-login") || index($0, "phpMyAdmin") || \
                    index($0, ".git") || index($0, "xmlrpc") || index($0, "/admin") || index($0, "/config"))
        if (is_probe) {
            probes++
            attackers[$1] = 1
            match($0, /\[([^\]]+)\]/, m)
            if (m[1]) last_attack = m[1]
        }
        if (index($0, "\" 444 ") || index($0, "\" 403 ")) {
            blocked++
            attackers[$1] = 1
        }
    }
    END {
        a = 0; for (ip in attackers) a++
        la = (last_attack ? last_attack : "None")
        printf "%d|%d|%d|%s\n", probes+0, a, blocked+0, la
    }' /var/log/nginx/access.log 2>/dev/null > "$TMPDIR/nginx"
) &

# 4. Entry points
(
    nginx_status="stopped"; ssh_status="running"; fail2ban_status="stopped"
    systemctl is-active nginx &>/dev/null && nginx_status="running"
    systemctl is-active ssh &>/dev/null && ssh_status="running"
    systemctl is-active fail2ban &>/dev/null && fail2ban_status="running"
    echo "$nginx_status|$ssh_status|$fail2ban_status" > "$TMPDIR/entry"
) &

# 5. Orphan process detection — fast cgroup check instead of systemctl per-pid
(
    first=true
    result="["
    while IFS= read -r line; do
        pid=$(echo "$line" | grep -oP 'pid=\K\d+' | head -1)
        [ -z "$pid" ] && continue
        [ "$pid" -eq 1 ] 2>/dev/null && continue

        # Fast: read cgroup to check if systemd-managed
        cgroup=$(cat /proc/$pid/cgroup 2>/dev/null | head -1)
        echo "$cgroup" | grep -q "system.slice\|user.slice\|init.scope" && continue

        name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        port=$(echo "$line" | awk '{print $5}' | grep -oP ':\K[^:]+$' || echo "?")
        user=$(ps -p "$pid" -o user= 2>/dev/null || echo "?")
        mem=$(ps -p "$pid" -o rss= 2>/dev/null || echo "0")
        mem=$((mem / 1024))
        elapsed=$(ps -p "$pid" -o etimes= 2>/dev/null | tr -d ' ' || echo "0")
        if [ "$elapsed" -gt 86400 ] 2>/dev/null; then
            uptime_str="$((elapsed / 86400))d $((elapsed % 86400 / 3600))h"
        elif [ "$elapsed" -gt 3600 ] 2>/dev/null; then
            uptime_str="$((elapsed / 3600))h $((elapsed % 3600 / 60))m"
        else
            uptime_str="$((elapsed / 60))m"
        fi
        [ "$first" = true ] && first=false || result="$result,"
        result="$result{\"pid\":$pid,\"name\":\"$name\",\"port\":\"$port\",\"user\":\"$user\",\"memory\":\"${mem} MB\",\"uptime\":\"$uptime_str\"}"
    done < <(ss -tlnp 2>/dev/null | tail -n +2)

    # Zombie check
    while IFS= read -r line; do
        zpid=$(echo "$line" | awk '{print $2}')
        zname=$(echo "$line" | awk '{print $11}')
        [ -z "$zpid" ] && continue
        [ "$first" = true ] && first=false || result="$result,"
        result="$result{\"pid\":$zpid,\"name\":\"$zname [zombie]\",\"port\":\"-\",\"user\":\"$(echo "$line" | awk '{print $1}')\",\"memory\":\"0 MB\",\"uptime\":\"-\"}"
    done < <(ps aux 2>/dev/null | awk '$8 ~ /^Z/ {print}')

    result="$result]"
    echo "$result" > "$TMPDIR/orphans"
) &

# === WAIT ===
wait

# === READ results ===
f2b=$(cat "$TMPDIR/f2b" 2>/dev/null || echo "0|0")
banned=$(echo "$f2b" | cut -d"|" -f1)
total_banned=$(echo "$f2b" | cut -d"|" -f2)

ssh_fails=$(cat "$TMPDIR/ssh" 2>/dev/null || echo "0")

nginx_data=$(cat "$TMPDIR/nginx" 2>/dev/null || echo "0|0|0|None")
probes=$(echo "$nginx_data" | cut -d"|" -f1)
attackers=$(echo "$nginx_data" | cut -d"|" -f2)
blocked=$(echo "$nginx_data" | cut -d"|" -f3)
last_attack=$(echo "$nginx_data" | cut -d"|" -f4)

entry=$(cat "$TMPDIR/entry" 2>/dev/null || echo "stopped|running|stopped")
nginx_status=$(echo "$entry" | cut -d"|" -f1)
ssh_status=$(echo "$entry" | cut -d"|" -f2)
fail2ban_status=$(echo "$entry" | cut -d"|" -f3)

orphan_processes=$(cat "$TMPDIR/orphans" 2>/dev/null || echo "[]")
orphan_count=$(echo "$orphan_processes" | grep -o '"pid"' | wc -l)

# Safety score
score=10
[ "$fail2ban_status" != "running" ] && score=$((score - 2))
[ "$banned" -gt 0 ] && score=$((score - 1))
[ "$ssh_fails" -gt 50 ] && score=$((score - 1))
[ "$ssh_fails" -gt 200 ] && score=$((score - 1))
[ "$probes" -gt 100 ] && score=$((score - 1))
[ "$probes" -gt 500 ] && score=$((score - 1))
[ "$attackers" -gt 10 ] && score=$((score - 1))
[ "$orphan_count" -gt 0 ] 2>/dev/null && score=$((score - 1))
[ "$orphan_count" -gt 3 ] 2>/dev/null && score=$((score - 1))
[ "$score" -lt 1 ] && score=1
[ "$score" -gt 10 ] && score=10

cat << EOF
{
    "safety_score": $score,
    "banned_now": $banned,
    "banned_total": $total_banned,
    "ssh_fails_24h": $ssh_fails,
    "probes_24h": $probes,
    "blocked_24h": $blocked,
    "unique_attackers": $attackers,
    "last_attack": "$last_attack",
    "entry_points": {
        "nginx": "$nginx_status",
        "ssh": "$ssh_status",
        "fail2ban": "$fail2ban_status"
    },
    "orphan_processes": $orphan_processes
}
EOF
