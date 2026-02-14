#!/bin/bash
# Metrics for hetalkamdar.com (Traffic + Security)

# Last 1 hour
HOUR_NOW=$(date +"%d/%b/%Y:%H")
HOUR_PREV=$(date -d "1 hour ago" +"%d/%b/%Y:%H")
HETAL_1H=$(grep -hE "$HOUR_NOW|$HOUR_PREV" /var/log/nginx/access.log 2>/dev/null | grep -i hetalkamdar)
REQ_1H=$(echo "$HETAL_1H" | grep -c . || echo 0)

# Get logs from last 24 hours
YESTERDAY=$(date -d "yesterday" +"%d/%b/%Y")
TODAY=$(date +"%d/%b/%Y")
HETAL_LOGS=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/access.log.1 2>/dev/null | grep -i hetalkamdar)

# Unique visitors in last 24h
VISITORS=$(echo "$HETAL_LOGS" | awk "{print \$1}" | sort -u | wc -l)

# Cache ratio
REQUESTS=$(echo "$HETAL_LOGS" | wc -l)
STATIC=$(echo "$HETAL_LOGS" | grep -cE "\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)(\?|\s|\")" 2>/dev/null || echo 0)
if [ "$REQUESTS" -gt 0 ]; then
    CACHE_RATIO=$(echo "scale=0; $STATIC * 100 / $REQUESTS" | bc)
else
    CACHE_RATIO=0
fi

# Security Metrics
wp_attacks=$(grep -E "wp-login|wp-admin|xmlrpc" /var/log/nginx/access.log 2>/dev/null | wc -l)
errors_5xx=$(grep "hetalkamdar" /var/log/nginx/access.log 2>/dev/null | awk "\$9 ~ /^5/" | wc -l)
blocked_403=$(grep "hetalkamdar" /var/log/nginx/access.log 2>/dev/null | awk "\$9 == 403" | wc -l)
wp_banned=$(fail2ban-client status wordpress 2>/dev/null | grep "Currently banned" | awk "{print \$4}" || echo "0")

# Color coding for security
wp_color="#e74c3c"
[ "$wp_attacks" -lt 10 ] && wp_color="#f39c12"
[ "$wp_attacks" -lt 3 ] && wp_color="#00b894"

err_color="#00b894"
[ "$errors_5xx" -gt 0 ] && err_color="#f39c12"
[ "$errors_5xx" -gt 10 ] && err_color="#e74c3c"

echo "[{\"label\":\"Req/1h\",\"value\":\"$REQ_1H\"},{\"label\":\"Visitors\",\"value\":\"$VISITORS\"},{\"label\":\"Cache %\",\"value\":\"${CACHE_RATIO}%\",\"color\":\"#00b894\"},{\"label\":\"WP Attacks\",\"value\":\"$wp_attacks\",\"color\":\"$wp_color\"},{\"label\":\"5xx Err\",\"value\":\"$errors_5xx\",\"color\":\"$err_color\"},{\"label\":\"Blocked\",\"value\":\"$blocked_403\",\"color\":\"#9b59b6\"},{\"label\":\"Banned\",\"value\":\"$wp_banned\",\"color\":\"#e74c3c\"}]"
