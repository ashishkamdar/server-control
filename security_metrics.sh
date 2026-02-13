#!/bin/bash
# Security Dashboard Metrics - Lightweight security status

# Get fail2ban stats
get_fail2ban() {
    local banned=0 total_banned=0
    if command -v fail2ban-client &>/dev/null; then
        banned=$(fail2ban-client status 2>/dev/null | grep -oP "Currently banned:\s*\K\d+" | awk "{s+=\$1} END {print s+0}" 2>/dev/null || echo 0)
        # Get total from all jails
        for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed "s/.*://;s/,//g"); do
            jban=$(fail2ban-client status "$jail" 2>/dev/null | grep -oP "Total banned:\s*\K\d+" || echo 0)
            total_banned=$((total_banned + jban))
        done
    fi
    echo "$banned|$total_banned"
}

# Get SSH failed attempts (last 24h)
get_ssh_fails() {
    local count=0
    if [ -f /var/log/auth.log ]; then
        # Count failures from last 24 hours using journalctl
        count=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password\|Invalid user" || grep "$(date +%Y-%m-%d)" /var/log/auth.log 2>/dev/null | grep -c "Failed password\|Invalid user" || echo 0)
    fi
    echo "$count"
}

# Get nginx probe attempts (last 24h) - quick scan
get_nginx_probes() {
    local today=$(date +"%d/%b/%Y")
    local yesterday=$(date -d "yesterday" +"%d/%b/%Y" 2>/dev/null || date -v-1d +"%d/%b/%Y")
    local count=0
    
    # Quick grep for common probe patterns
    if [ -f /var/log/nginx/access.log ]; then
        count=$(grep -E "($today|$yesterday).*(\\.env|wp-login|phpMyAdmin|\\.git|xmlrpc|/admin|/config)" /var/log/nginx/access.log 2>/dev/null | wc -l || echo 0)
    fi
    echo "$count"
}

# Get entry point status
get_entry_points() {
    local nginx_status="stopped"
    local ssh_status="running"
    local fail2ban_status="stopped"
    
    systemctl is-active nginx &>/dev/null && nginx_status="running"
    systemctl is-active ssh &>/dev/null && ssh_status="running"
    systemctl is-active fail2ban &>/dev/null && fail2ban_status="running"
    
    echo "$nginx_status|$ssh_status|$fail2ban_status"
}

# Get unique attacker IPs (last 24h)
get_attacker_ips() {
    local count=0
    local today=$(date +"%d/%b/%Y")
    local yesterday=$(date -d "yesterday" +"%d/%b/%Y" 2>/dev/null || date -v-1d +"%d/%b/%Y")
    
    # From nginx 403/suspicious patterns
    if [ -f /var/log/nginx/access.log ]; then
        count=$(grep -E "($today|$yesterday).*(\" 403 |\" 444 |\\.env|\\.git|wp-login|phpMyAdmin)" /var/log/nginx/access.log 2>/dev/null | awk "{print \$1}" | sort -u | wc -l || echo 0)
    fi
    echo "$count"
}

# Get blocked requests (nginx 444/403)
get_blocked() {
    local today=$(date +"%d/%b/%Y")
    local yesterday=$(date -d "yesterday" +"%d/%b/%Y" 2>/dev/null || date -v-1d +"%d/%b/%Y")
    local count=0
    
    if [ -f /var/log/nginx/access.log ]; then
        count=$(grep -E "($today|$yesterday).*(\" 444 |\" 403 )" /var/log/nginx/access.log 2>/dev/null | wc -l || echo 0)
    fi
    echo "$count"
}

# Get last attack time
get_last_attack() {
    local last=""
    if [ -f /var/log/nginx/access.log ]; then
        last=$(grep -E "(\\.env|\\.git|wp-login|phpMyAdmin|xmlrpc)" /var/log/nginx/access.log 2>/dev/null | tail -1 | grep -oP "\[\K[^\]]+(?=\])" || echo "")
    fi
    [ -z "$last" ] && last="None"
    echo "$last"
}

# Calculate safety score (1-10)
calc_safety_score() {
    local score=10
    local banned=$1
    local ssh_fails=$2
    local probes=$3
    local attackers=$4
    local fail2ban_status=$5
    
    # Deductions
    [ "$fail2ban_status" != "running" ] && score=$((score - 2))  # -2 if fail2ban not running
    [ "$banned" -gt 0 ] && score=$((score - 1))  # -1 if actively banning (means active attack)
    [ "$ssh_fails" -gt 50 ] && score=$((score - 1))  # -1 if many SSH failures
    [ "$ssh_fails" -gt 200 ] && score=$((score - 1))  # -1 more if excessive
    [ "$probes" -gt 100 ] && score=$((score - 1))  # -1 if many probes
    [ "$probes" -gt 500 ] && score=$((score - 1))  # -1 more if excessive
    [ "$attackers" -gt 10 ] && score=$((score - 1))  # -1 if many unique attackers
    
    # Ensure 1-10 range
    [ "$score" -lt 1 ] && score=1
    [ "$score" -gt 10 ] && score=10
    
    echo "$score"
}

# Main
fail2ban_data=$(get_fail2ban)
banned=$(echo "$fail2ban_data" | cut -d"|" -f1)
total_banned=$(echo "$fail2ban_data" | cut -d"|" -f2)

entry_points=$(get_entry_points)
nginx_status=$(echo "$entry_points" | cut -d"|" -f1)
ssh_status=$(echo "$entry_points" | cut -d"|" -f2)
fail2ban_status=$(echo "$entry_points" | cut -d"|" -f3)

ssh_fails=$(get_ssh_fails)
probes=$(get_nginx_probes)
attackers=$(get_attacker_ips)
blocked=$(get_blocked)
last_attack=$(get_last_attack)

safety_score=$(calc_safety_score "$banned" "$ssh_fails" "$probes" "$attackers" "$fail2ban_status")

# Output JSON
cat << EOF
{
    "safety_score": $safety_score,
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
    }
}
EOF
