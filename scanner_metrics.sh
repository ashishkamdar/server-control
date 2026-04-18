#!/bin/bash
# JSG Scanner metrics — scan counts from scan_records table
DB="/var/www/jsg-seating/data/jsg_seating.db"

if [ ! -f "$DB" ]; then
    echo '[]'
    exit 0
fi

# Total scans (all time)
TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM scan_records;" 2>/dev/null || echo 0)

# Today's scans
TODAY=$(sqlite3 "$DB" "SELECT COUNT(*) FROM scan_records WHERE date(scanned_at)=date('now');" 2>/dev/null || echo 0)

# Active event name + its scan count
ACTIVE_EVENT=$(sqlite3 "$DB" "SELECT e.name FROM events e WHERE e.is_active=1 ORDER BY e.created_at DESC LIMIT 1;" 2>/dev/null)
ACTIVE_SCANS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM scan_records sr JOIN events e ON sr.event_id=e.id WHERE e.is_active=1 ORDER BY e.created_at DESC LIMIT 1;" 2>/dev/null || echo 0)

# Total events
EVENTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo 0)

# Scanner users (admin users with scanner role)
SCANNERS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM admin_users WHERE role='scanner';" 2>/dev/null || echo 0)

cat <<EOF
[
  {"label": "Total Scans", "value": "$TOTAL", "color": "#2c5f8a"},
  {"label": "Today", "value": "$TODAY", "color": "#1a7a5a"},
  {"label": "Active Event", "value": "$ACTIVE_SCANS", "color": "#b8700d"},
  {"label": "Events", "value": "$EVENTS", "color": "#7b5ea7"},
  {"label": "Scanners", "value": "$SCANNERS", "color": "#9b59b6"}
]
EOF
