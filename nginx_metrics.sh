#!/bin/bash
# Nginx metrics

# Last 1 hour (current + previous hour for ~1h coverage)
HOUR_NOW=$(date +"%d/%b/%Y:%H")
HOUR_PREV=$(date -d "1 hour ago" +"%d/%b/%Y:%H")
REQ_1H=$(grep -hE "$HOUR_NOW|$HOUR_PREV" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | wc -l)

# Last 24 hours
TODAY=$(date +"%d/%b/%Y")
YESTERDAY=$(date -d "yesterday" +"%d/%b/%Y")

# Main access.log 
MAIN_REQ=$(grep -cE "$TODAY|$YESTERDAY" /var/log/nginx/access.log 2>/dev/null || echo 0)

# Change Requests log
CR_REQ=$(grep -cE "$TODAY|$YESTERDAY" /var/log/nginx/change-requests-access.log 2>/dev/null || echo 0)

# Total requests
TOTAL_REQ=$((MAIN_REQ + CR_REQ))

# Unique visitors
VISITORS=$(cat /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | grep -E "$TODAY|$YESTERDAY" | awk '{print $1}' | sort -u | wc -l)

# Count response codes
STATUS_2XX=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | grep -c '" 2[0-9][0-9] ' || echo 0)
STATUS_4XX=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | grep -c '" 4[0-9][0-9] ' || echo 0)
STATUS_5XX=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | grep -c '" 5[0-9][0-9] ' || echo 0)

# Format numbers
format_num() {
    local num=$1
    if [ "$num" -ge 1000000 ]; then
        echo "$(echo "scale=1; $num/1000000" | bc)M"
    elif [ "$num" -ge 1000 ]; then
        echo "$(echo "scale=1; $num/1000" | bc)K"
    else
        echo "$num"
    fi
}

TOTAL_FMT=$(format_num $TOTAL_REQ)
OK_FMT=$(format_num $STATUS_2XX)

# Color for 5xx errors
ERR_COLOR="#888"
[ "$STATUS_5XX" -gt 0 ] && ERR_COLOR="#e74c3c"

echo "[{\"label\":\"Req/1h\",\"value\":\"$REQ_1H\"},{\"label\":\"Requests 24h\",\"value\":\"$TOTAL_FMT\"},{\"label\":\"Visitors 24h\",\"value\":\"$VISITORS\"},{\"label\":\"2xx OK\",\"value\":\"$OK_FMT\",\"color\":\"#00b894\"},{\"label\":\"4xx Err\",\"value\":\"$STATUS_4XX\"},{\"label\":\"5xx Err\",\"value\":\"$STATUS_5XX\",\"color\":\"$ERR_COLOR\"}]"
