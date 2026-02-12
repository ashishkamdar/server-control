#!/bin/bash
# Metrics for hetalkamdar.com

# Last 1 hour (current + previous hour)
HOUR_NOW=$(date +"%d/%b/%Y:%H")
HOUR_PREV=$(date -d "1 hour ago" +"%d/%b/%Y:%H")
HETAL_1H=$(grep -hE "$HOUR_NOW|$HOUR_PREV" /var/log/nginx/access.log 2>/dev/null | grep -i hetalkamdar)
REQ_1H=$(echo "$HETAL_1H" | grep -c . || echo 0)

# Get logs from last 24 hours (use Nginx logs - the frontend)
YESTERDAY=$(date -d "yesterday" +"%d/%b/%Y")
TODAY=$(date +"%d/%b/%Y")

# Filter for hetalkamdar.com requests only
HETAL_LOGS=$(grep -hE "$TODAY|$YESTERDAY" /var/log/nginx/access.log /var/log/nginx/access.log.1 2>/dev/null | grep -i hetalkamdar)

# Unique visitors in last 24h
VISITORS=$(echo "$HETAL_LOGS" | awk '{print $1}' | sort -u | wc -l)

# Total requests in last 24h
REQUESTS=$(echo "$HETAL_LOGS" | wc -l)

# Static/Cached requests (images, css, js, cached html)
STATIC=$(echo "$HETAL_LOGS" | grep -cE '\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|woff|woff2|ttf|eot)(\?|\s|")' 2>/dev/null || echo 0)

# Dynamic requests (PHP or non-static pages)
DYNAMIC=$((REQUESTS - STATIC))
if [ $DYNAMIC -lt 0 ]; then DYNAMIC=0; fi

# Calculate cache ratio (static vs total)
if [ "$REQUESTS" -gt 0 ]; then
    CACHE_RATIO=$(echo "scale=0; $STATIC * 100 / $REQUESTS" | bc)
else
    CACHE_RATIO=0
fi

# WP Super Cache - cached pages count  
CACHED_PAGES=$(find /var/www/html/wp-content/cache/supercache -name "*.html" 2>/dev/null | wc -l)

# Redis stats
REDIS_INFO=$(redis-cli INFO stats 2>/dev/null)
HITS=$(echo "$REDIS_INFO" | grep "keyspace_hits:" | cut -d: -f2 | tr -d "\r")
MISSES=$(echo "$REDIS_INFO" | grep "keyspace_misses:" | cut -d: -f2 | tr -d "\r")

# Calculate Redis hit ratio
if [ -n "$HITS" ] && [ -n "$MISSES" ]; then
    TOTAL_REDIS=$((HITS + MISSES))
    if [ "$TOTAL_REDIS" -gt 0 ]; then
        REDIS_RATIO=$(echo "scale=1; $HITS * 100 / $TOTAL_REDIS" | bc)
    else
        REDIS_RATIO="0"
    fi
else
    HITS="0"
    REDIS_RATIO="0"
fi

# Format large numbers
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

HITS_FMT=$(format_num ${HITS:-0})
STATIC_FMT=$(format_num ${STATIC:-0})
DYNAMIC_FMT=$(format_num ${DYNAMIC:-0})

# Top 3 content pages (home, recipes, travel, blog only)
TOP_PAGES=$(echo "$HETAL_LOGS" | \
    awk '{print $7}' | \
    sed 's/\?.*$//' | \
    grep -E '^/$|^/(recipe|travel|blog)/' | \
    sort | uniq -c | sort -rn | head -3 | \
    awk '{
        path=$2
        if (path == "/") { name = "home" }
        else {
            gsub(/\/$/, "", path)
            n = split(path, parts, "/")
            name = parts[n]
            gsub(/-/, " ", name)
            if (length(name) > 12) name = substr(name, 1, 12)
            gsub(/ +$/, "", name)
        }
        printf "%s:%d ", name, $1
    }' | sed 's/ $//')
TOP_PAGES=${TOP_PAGES:-"no data"}

echo "[{\"label\":\"Req/1h\",\"value\":\"$REQ_1H\"},{\"label\":\"Visitors 24h\",\"value\":\"$VISITORS\"},{\"label\":\"Top Pages\",\"value\":\"$TOP_PAGES\",\"color\":\"#8ab4d4; font-weight: 300; font-size: 0.9em\"},{\"label\":\"Cached\",\"value\":\"$STATIC_FMT\",\"color\":\"#00b894\"},{\"label\":\"Dynamic\",\"value\":\"$DYNAMIC_FMT\",\"color\":\"#fdcb6e\"},{\"label\":\"Cache %\",\"value\":\"${CACHE_RATIO}%\",\"color\":\"#00b894\"},{\"label\":\"Redis Hit%\",\"value\":\"${REDIS_RATIO}%\",\"color\":\"#00b894\"}]"
