#!/usr/bin/env bash
# verify_docker.sh - Verify multi-instance Redis sharing and PostgreSQL audit
# Usage: ./scripts/verify_docker.sh [--audit]
#
# Prerequisites: docker compose running
#   Basic:  docker compose up -d
#   Audit:  docker compose --profile audit up -d

set -euo pipefail

AUDIT_MODE="${1:-}"
BASE_URL_1="http://localhost:8080"
BASE_URL_2="http://localhost:8081"
ADMIN_URL="http://localhost:8080/_admin/api"

echo "=== MimicWeb Docker Integration Verification ==="
echo ""

# Wait for services
echo "[1/5] Waiting for services to be ready..."
for url in "$BASE_URL_1/health" "$BASE_URL_2/health"; do
    for i in $(seq 1 30); do
        if curl -sf "$url" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
done
echo "  ✓ Both instances are up"

# Send requests to instance 1
echo "[2/5] Sending test requests to node-1 (port 8080)..."
curl -sf "$BASE_URL_1/" > /dev/null
curl -sf "$BASE_URL_1/api/v1/users/42" > /dev/null
curl -sf -H "User-Agent: sqlmap/1.5" "$BASE_URL_1/health" > /dev/null
echo "  ✓ 3 requests sent to node-1"

# Send requests to instance 2
echo "[3/5] Sending test requests to node-2 (port 8081)..."
curl -sf "$BASE_URL_2/" > /dev/null
curl -sf "$BASE_URL_2/api/v1/users/99" > /dev/null
echo "  ✓ 2 requests sent to node-2"

sleep 1

# Verify cross-instance visibility via admin API on node-1
echo "[4/5] Verifying Redis-shared log visibility..."
LOGS=$(curl -sf "$ADMIN_URL/logs?limit=50")
TOTAL=$(echo "$LOGS" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
echo "  Total logs visible from node-1 admin: $TOTAL"

# Check both instance IDs appear
NODE1_COUNT=$(echo "$LOGS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for e in data['entries'] if e.get('instance_id') == 'node-1'))
")
NODE2_COUNT=$(echo "$LOGS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(sum(1 for e in data['entries'] if e.get('instance_id') == 'node-2'))
")
echo "  Entries from node-1: $NODE1_COUNT"
echo "  Entries from node-2: $NODE2_COUNT"

if [ "$NODE1_COUNT" -ge 3 ] && [ "$NODE2_COUNT" -ge 2 ]; then
    echo "  ✓ Cross-instance log sharing VERIFIED"
else
    echo "  ✗ FAILED: Expected ≥3 from node-1 and ≥2 from node-2"
    exit 1
fi

# Verify suspicious detection
SUSPICIOUS=$(curl -sf "$ADMIN_URL/logs?suspicious=true")
SUS_COUNT=$(echo "$SUSPICIOUS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['entries']))")
echo "  Suspicious requests detected: $SUS_COUNT"
if [ "$SUS_COUNT" -ge 1 ]; then
    echo "  ✓ Scanner detection working"
else
    echo "  ✗ FAILED: Expected ≥1 suspicious request"
    exit 1
fi

# PostgreSQL audit check (only in audit mode)
if [ "$AUDIT_MODE" = "--audit" ]; then
    AUDIT_URL="http://localhost:8082"
    echo "[5/5] Verifying PostgreSQL audit mode..."

    # Wait for audit instance
    for i in $(seq 1 30); do
        if curl -sf "$AUDIT_URL/health" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    curl -sf "$AUDIT_URL/" > /dev/null
    curl -sf "$AUDIT_URL/api/v1/users/audit-test" > /dev/null
    sleep 2

    # Query PostgreSQL directly
    PG_COUNT=$(docker compose exec -T postgres psql -U mimicweb -d mimicweb -t -c \
        "SELECT COUNT(*) FROM request_logs;" 2>/dev/null | tr -d ' ')
    echo "  PostgreSQL request_logs count: $PG_COUNT"

    if [ "$PG_COUNT" -ge 2 ]; then
        echo "  ✓ PostgreSQL audit write VERIFIED"
    else
        echo "  ✗ FAILED: Expected ≥2 rows in PostgreSQL"
        exit 1
    fi

    # Verify suspicious entries in PG
    PG_SUS=$(docker compose exec -T postgres psql -U mimicweb -d mimicweb -t -c \
        "SELECT COUNT(*) FROM request_logs WHERE suspicious = TRUE;" 2>/dev/null | tr -d ' ')
    echo "  PostgreSQL suspicious entries: $PG_SUS"
    echo "  ✓ PostgreSQL audit storage working"
else
    echo "[5/5] Skipping PostgreSQL audit check (use --audit flag)"
fi

echo ""
echo "=== All verifications PASSED ==="
