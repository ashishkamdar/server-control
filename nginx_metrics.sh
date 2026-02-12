#!/bin/bash
# Nginx metrics

# Last 1 hour (current + previous hour for ~1h coverage)
HOUR_NOW=$(date +"%d/%b/%Y:%H")
HOUR_PREV=$(date -d "1 hour ago" +"%d/%b/%Y:%H")
REQ_1H=$(grep -hE "$HOUR_NOW|$HOUR_PREV" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | wc -l)

# Last 24 hours
TODAY=$(date +"%d/%b/%Y")
YESTERDAY=$(date -d "yesterday" +"%d/%b/%Y")

# All logs for today/yesterday
ALL_LOGS=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null)

# Total requests
TOTAL_REQ=$(echo "$ALL_LOGS" | wc -l)

# Unique visitors
VISITORS=$(echo "$ALL_LOGS" | awk '{print $1}' | sort -u | wc -l)

# Count response codes
STATUS_2XX=$(echo "$ALL_LOGS" | grep -c '" 2[0-9][0-9] ' || echo 0)
STATUS_403=$(echo "$ALL_LOGS" | grep -c '" 403 ' || echo 0)
STATUS_404=$(echo "$ALL_LOGS" | grep -c '" 404 ' || echo 0)
STATUS_5XX=$(echo "$ALL_LOGS" | grep -c '" 50[0-5] ' || echo 0)

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

# Extract error details: URL(count)time - top 3
get_error_details() {
    local pattern="$1"
    echo "$ALL_LOGS" | grep "$pattern" | \
    awk '{
        gsub(/\[/, "", $4)
        split($4, ts, ":")
        time = ts[2]":"ts[3]
        url = $7
        gsub(/\?.*$/, "", url)
        if (length(url) > 40) url = substr(url, 1, 40)
        count[url]++
        last[url] = time
    }
    END {
        n = 0
        for (url in count) {
            urls[n] = url; counts[n] = count[url]; times[n] = last[url]; n++
        }
        for (i = 0; i < n-1; i++) {
            for (j = i+1; j < n; j++) {
                if (counts[j] > counts[i]) {
                    tmp = urls[i]; urls[i] = urls[j]; urls[j] = tmp
                    tmp = counts[i]; counts[i] = counts[j]; counts[j] = tmp
                    tmp = times[i]; times[i] = times[j]; times[j] = tmp
                }
            }
        }
        for (i = 0; i < 3 && i < n; i++) {
            if (i > 0) printf " | "
            printf "%s (%d) @%s", urls[i], counts[i], times[i]
        }
    }'
}

TOTAL_FMT=$(format_num $TOTAL_REQ)
OK_FMT=$(format_num $STATUS_2XX)

# Get error details
ERR_5XX_DETAILS=$(get_error_details '" 50[0-5] ')
ERR_404_DETAILS=$(get_error_details '" 404 ')
ERR_403_DETAILS=$(get_error_details '" 403 ')

# Build JSON output
OUTPUT="["
OUTPUT+="{\"label\":\"Req/1h\",\"value\":\"$REQ_1H\"},"
OUTPUT+="{\"label\":\"Requests 24h\",\"value\":\"$TOTAL_FMT\"},"
OUTPUT+="{\"label\":\"Visitors 24h\",\"value\":\"$VISITORS\"},"
OUTPUT+="{\"label\":\"2xx OK\",\"value\":\"$OK_FMT\",\"color\":\"#00b894\"},"

# 5xx errors
if [ "$STATUS_5XX" -gt 0 ]; then
    OUTPUT+="{\"label\":\"5xx Err\",\"value\":\"$STATUS_5XX\",\"color\":\"#e74c3c\"},"
    OUTPUT+="{\"label\":\"5xx URLs\",\"value\":\"$ERR_5XX_DETAILS\",\"color\":\"#e74c3c; font-weight:300; font-size:0.8em\"},"
else
    OUTPUT+="{\"label\":\"5xx Err\",\"value\":\"0\",\"color\":\"#888\"},"
fi

# 404 errors
if [ "$STATUS_404" -gt 0 ]; then
    OUTPUT+="{\"label\":\"404 Err\",\"value\":\"$STATUS_404\",\"color\":\"#f39c12\"},"
    OUTPUT+="{\"label\":\"404 URLs\",\"value\":\"$ERR_404_DETAILS\",\"color\":\"#f39c12; font-weight:300; font-size:0.8em\"},"
else
    OUTPUT+="{\"label\":\"404 Err\",\"value\":\"0\",\"color\":\"#888\"},"
fi

# 403 errors
if [ "$STATUS_403" -gt 0 ]; then
    OUTPUT+="{\"label\":\"403 Err\",\"value\":\"$STATUS_403\",\"color\":\"#9b59b6\"},"
    OUTPUT+="{\"label\":\"403 URLs\",\"value\":\"$ERR_403_DETAILS\",\"color\":\"#9b59b6; font-weight:300; font-size:0.8em\"}"
else
    OUTPUT+="{\"label\":\"403 Err\",\"value\":\"0\",\"color\":\"#888\"}"
fi

OUTPUT+="]"
echo "$OUTPUT"
