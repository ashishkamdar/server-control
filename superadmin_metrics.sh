#!/bin/bash
# JSG Superadmin metrics — tenant counts from master DB
DB="/var/www/jsg-seating/data/jsg_master.db"

if [ ! -f "$DB" ]; then
    echo '[]'
    exit 0
fi

# Total tenants
TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM tenants;" 2>/dev/null || echo 0)

# Active tenants
ACTIVE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM tenants WHERE is_active=1;" 2>/dev/null || echo 0)

# Total tenant admins
ADMINS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM tenant_admins;" 2>/dev/null || echo 0)

# Total backups
BACKUPS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM tenant_backups;" 2>/dev/null || echo 0)

cat <<EOF
[
  {"label": "Tenants", "value": "$TOTAL", "color": "#2c5f8a"},
  {"label": "Active", "value": "$ACTIVE", "color": "#1a7a5a"},
  {"label": "Admins", "value": "$ADMINS", "color": "#7b5ea7"},
  {"label": "Backups", "value": "$BACKUPS", "color": "#b8700d"}
]
EOF
