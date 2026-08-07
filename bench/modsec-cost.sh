#!/usr/bin/env bash
#
# What does turning ModSecurity on cost?
#
# Five configurations, one binary difference between the first two and one
# configuration difference between the rest, so each number is attributable:
#
#   plain         default build            — the baseline everything else moves from
#   compiled-off  --features modsecurity, no directives
#                                          — the cost of the code merely being present
#   minimal       two hand-written rules   — the engine's fixed per-request cost
#   crs           OWASP CRS 4.x            — what an actual deployment pays
#   crs+body      CRS with phase 4 on      — response-body inspection on top
#
# Fairness follows bench/run.sh: same worker count, same fixtures, same client,
# servers pinned away from the load generator, warmup discarded, median of N.
# The server gets cores 0-1 and wrk gets 2-5, so the thing being measured is
# the server rather than a contended scheduler.
#
# Usage:  bench/modsec-cost.sh [duration] [connections] [rounds]
set -euo pipefail

DURATION="${1:-10}"
CONNS="${2:-128}"
ROUNDS="${3:-5}"
PORT=8901

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/bench/work/modsec"
CRS="${CRS_DIR:-$WORK/crs}"

command -v wrk >/dev/null || { echo "missing: wrk" >&2; exit 1; }
command -v taskset >/dev/null || { echo "missing: taskset (Linux only)" >&2; exit 1; }
[ "$(nproc)" -ge 6 ] || { echo "needs >= 6 cores to keep client and server apart" >&2; exit 1; }

mkdir -p "$WORK/html"
head -c 1024 /dev/zero | tr '\0' 'x' > "$WORK/html/1k.bin"
printf 'ok\n' > "$WORK/html/index.html"

if [ ! -d "$CRS" ]; then
    echo "==> fetching OWASP CRS"
    curl -fsSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.7.0.tar.gz \
        | tar -xz -C "$WORK"
    mv "$WORK/coreruleset-4.7.0" "$CRS"
    cp "$CRS/crs-setup.conf.example" "$CRS/crs-setup.conf"
fi

# ---- configurations -------------------------------------------------------
# Everything outside the modsecurity lines is identical, including worker
# count and logging, so a difference between two runs is the rules and nothing
# else.
common() {
    cat <<EOF
worker_processes 2;
error_log /dev/null crit;
events { worker_connections 4096; }
http {
    access_log off;
    sendfile on;
    keepalive_timeout 65s;
    keepalive_requests 100000;
$1
    server {
        listen $PORT reuseport;
        location / { root $WORK/html; }
    }
}
EOF
}

crs_rules() {
    local body="$1"
    printf '    modsecurity on;\n'
    [ "$body" = "on" ] && printf '    modsecurity_response_body on;\n'
    printf "    modsecurity_rules 'SecRuleEngine On\\nSecRequestBodyAccess On';\n"
    printf '    modsecurity_rules_file %s/crs-setup.conf;\n' "$CRS"
    for f in "$CRS"/rules/*.conf; do
        case "$f" in *RESPONSE-980*|*RESPONSE-99*) ;; esac
        printf '    modsecurity_rules_file %s;\n' "$f"
    done
}

common ""                                                        > "$WORK/plain.conf"
common ""                                                        > "$WORK/compiled-off.conf"
common "    modsecurity on;
    modsecurity_rules '
        SecRuleEngine On
        SecRule ARGS \"@rx (?i)union[[:space:]]+select\" \"id:1,phase:2,deny,status:403\"
        SecRule REQUEST_HEADERS:User-Agent \"@rx (?i)sqlmap\" \"id:2,phase:1,deny,status:403\"
    ';"                                                          > "$WORK/minimal.conf"
common "$(crs_rules off)"                                        > "$WORK/crs.conf"
common "$(crs_rules on)"                                         > "$WORK/crs+body.conf"

# ---- run ------------------------------------------------------------------
# wrk's bare request trips CRS rules that have nothing to do with the workload:
# a numeric Host matches 920350, and a missing Accept or User-Agent matches
# 920300 and 920320. Measuring those would be measuring the logging path, not
# the inspection cost of ordinary traffic, so the client looks like a browser.
WRK_HDRS=(
    -H "Host: example.com"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    -H "Accept-Language: en-US,en;q=0.9"
)

run_one() {
    local bin="$1" conf="$2"
    taskset -c 0,1 "$bin" -c "$conf" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    if ! kill -0 $pid 2>/dev/null; then
        echo "server failed to start for $conf" >&2
        return 1
    fi
    # Warmup, discarded: the first pass populates open_file_cache and lets the
    # runtime settle, and including it would flatter whichever ran second.
    taskset -c 2-5 wrk "${WRK_HDRS[@]}" -t4 -c"$CONNS" -d3s "http://127.0.0.1:$PORT/1k.bin" >/dev/null 2>&1
    local out
    out=$(taskset -c 2-5 wrk "${WRK_HDRS[@]}" -t4 -c"$CONNS" -d"${DURATION}s" "http://127.0.0.1:$PORT/1k.bin" 2>/dev/null)
    # A run where the rules fired is not the run being asked about: this is the
    # cost of *clean* traffic. Non-2xx would mean CRS blocked the fixture.
    if echo "$out" | grep -q 'Non-2xx'; then
        echo "WARNING: non-2xx responses during $conf — rules are blocking the fixture" >&2
    fi
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    sleep 1
    echo "$out" | awk '/Requests\/sec/ {print $2}'
}

median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }

declare -A RESULT
bench() {
    local name="$1" bin="$2" conf="$3"
    local runs=()
    for _ in $(seq "$ROUNDS"); do
        runs+=("$(run_one "$bin" "$conf")")
    done
    RESULT[$name]=$(median "${runs[@]}")
    printf '%-14s %12s req/s   (runs: %s)\n' "$name" "${RESULT[$name]}" "${runs[*]}"
}

PLAIN_BIN="$ROOT/target/plain/release/oxiserve"
MODSEC_BIN="$ROOT/target/modsec/release/oxiserve"
for b in "$PLAIN_BIN" "$MODSEC_BIN"; do
    [ -x "$b" ] || { echo "missing binary: $b — see the build lines in this script's header" >&2; exit 1; }
done

echo "==> ${DURATION}s x ${ROUNDS} rounds, ${CONNS} connections, 1 KiB file"
echo "    server on cores 0-1, wrk on cores 2-5"
echo
bench plain        "$PLAIN_BIN"  "$WORK/plain.conf"
bench compiled-off "$MODSEC_BIN" "$WORK/compiled-off.conf"
bench minimal      "$MODSEC_BIN" "$WORK/minimal.conf"
bench crs          "$MODSEC_BIN" "$WORK/crs.conf"
bench crs+body     "$MODSEC_BIN" "$WORK/crs+body.conf"

echo
base="${RESULT[plain]}"
printf '%-14s %10s %10s\n' config req/s 'vs plain'
for k in plain compiled-off minimal crs crs+body; do
    printf '%-14s %10s %9s%%\n' "$k" "${RESULT[$k]}" \
        "$(awk -v a="${RESULT[$k]}" -v b="$base" 'BEGIN{printf "%+.1f", (a-b)/b*100}')"
done
