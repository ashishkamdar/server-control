#!/bin/bash
# Nginx metrics — single-pass awk for all counters + error details

TODAY=$(date +"%d/%b/%Y")
YESTERDAY=$(date -d "yesterday" +"%d/%b/%Y")
HOUR_NOW=$(date +"%d/%b/%Y:%H")
HOUR_PREV=$(date -d "1 hour ago" +"%d/%b/%Y:%H")

# Single awk pass: counts, visitors, and top-3 error URLs per category
cat /var/log/nginx/access.log /var/log/nginx/change-requests-access.log 2>/dev/null | \
awk -v today="$TODAY" -v yesterday="$YESTERDAY" -v hour_now="$HOUR_NOW" -v hour_prev="$HOUR_PREV" '
{
    # Check if line is in last 24h
    is_24h = (index($0, today) || index($0, yesterday))
    if (!is_24h) next

    total++
    visitors[$1] = 1

    # Check if in last hour
    if (index($4, hour_now) || index($4, hour_prev)) req_1h++

    # Extract status code — find pattern: " NNN "
    status = ""
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9][0-9][0-9]$/ && $(i-1) ~ /"$/) { status = $i; break }
    }
    if (status == "") next

    if (status ~ /^2/) { s2xx++ }
    else if (status == "404") {
        s404++
        url = $7; gsub(/\?.*$/, "", url)
        if (length(url) > 40) url = substr(url, 1, 40)
        e404_c[url]++
        gsub(/\[/, "", $4); split($4, ts, ":"); e404_t[url] = ts[2]":"ts[3]
    }
    else if (status == "403") {
        s403++
        url = $7; gsub(/\?.*$/, "", url)
        if (length(url) > 40) url = substr(url, 1, 40)
        e403_c[url]++
        gsub(/\[/, "", $4); split($4, ts, ":"); e403_t[url] = ts[2]":"ts[3]
    }
    else if (status ~ /^5/) {
        s5xx++
        url = $7; gsub(/\?.*$/, "", url)
        if (length(url) > 40) url = substr(url, 1, 40)
        e5xx_c[url]++
        gsub(/\[/, "", $4); split($4, ts, ":"); e5xx_t[url] = ts[2]":"ts[3]
    }
}

function format_num(n) {
    if (n >= 1000000) return sprintf("%.1fM", n/1000000)
    if (n >= 1000) return sprintf("%.1fK", n/1000)
    return n+0
}

function top3(counts, times,    n, i, j, tmp, urls, cnts, tms, result) {
    n = 0
    for (u in counts) { urls[n] = u; cnts[n] = counts[u]; tms[n] = times[u]; n++ }
    for (i = 0; i < n-1; i++)
        for (j = i+1; j < n; j++)
            if (cnts[j] > cnts[i]) {
                tmp=urls[i]; urls[i]=urls[j]; urls[j]=tmp
                tmp=cnts[i]; cnts[i]=cnts[j]; cnts[j]=tmp
                tmp=tms[i]; tms[i]=tms[j]; tms[j]=tmp
            }
    result = ""
    for (i = 0; i < 3 && i < n; i++) {
        if (i > 0) result = result " | "
        result = result urls[i] " (" cnts[i] ") @" tms[i]
    }
    return result
}

END {
    vis = 0; for (v in visitors) vis++
    printf "["
    printf "{\"label\":\"Req/1h\",\"value\":\"%s\"},", format_num(req_1h+0)
    printf "{\"label\":\"Requests 24h\",\"value\":\"%s\"},", format_num(total+0)
    printf "{\"label\":\"Visitors 24h\",\"value\":\"%d\"},", vis
    printf "{\"label\":\"2xx OK\",\"value\":\"%s\",\"color\":\"#00b894\"},", format_num(s2xx+0)

    if (s5xx > 0) {
        printf "{\"label\":\"5xx Err\",\"value\":\"%d\",\"color\":\"#e74c3c\"},", s5xx
        d = top3(e5xx_c, e5xx_t)
        gsub(/"/, "\\\"", d)
        printf "{\"label\":\"5xx URLs\",\"value\":\"%s\",\"color\":\"#e74c3c; font-weight:300; font-size:0.8em\"},", d
    } else {
        printf "{\"label\":\"5xx Err\",\"value\":\"0\",\"color\":\"#888\"},"
    }

    if (s404 > 0) {
        printf "{\"label\":\"404 Err\",\"value\":\"%d\",\"color\":\"#f39c12\"},", s404
        d = top3(e404_c, e404_t)
        gsub(/"/, "\\\"", d)
        printf "{\"label\":\"404 URLs\",\"value\":\"%s\",\"color\":\"#f39c12; font-weight:300; font-size:0.8em\"},", d
    } else {
        printf "{\"label\":\"404 Err\",\"value\":\"0\",\"color\":\"#888\"},"
    }

    if (s403 > 0) {
        printf "{\"label\":\"403 Err\",\"value\":\"%d\",\"color\":\"#9b59b6\"},", s403
        d = top3(e403_c, e403_t)
        gsub(/"/, "\\\"", d)
        printf "{\"label\":\"403 URLs\",\"value\":\"%s\",\"color\":\"#9b59b6; font-weight:300; font-size:0.8em\"}", d
    } else {
        printf "{\"label\":\"403 Err\",\"value\":\"0\",\"color\":\"#888\"}"
    }

    printf "]\n"
}'
