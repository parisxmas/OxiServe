#!/usr/bin/env bash
#
# Head-to-head benchmark: OxiServe vs nginx, same config, same document root.
#
# The point of this harness is that it is *fair*. Both servers get the same
# worker count, the same keepalive settings, the same files, and the same
# client. Anything that would flatter one of them (logging on for one and off
# for the other, different sendfile settings, a warm cache for the second run)
# is either matched or eliminated.
#
# Platform note: on macOS, nginx's `sendfile on` path collapses to ~100 MB/s
# (a Darwin sendfile pathology, not an nginx characteristic). Benchmarking
# against it would produce a flattering-but-meaningless 60x win, so the harness
# sets `sendfile off` on BOTH servers here and reports that it did. On Linux,
# re-run with SENDFILE=on for the configuration people actually deploy.
#
# Usage:  bench/run.sh [duration] [connections]
set -euo pipefail

DURATION="${1:-15}"
CONNS="${2:-256}"
THREADS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
# Default off: see the platform note above.
SENDFILE="${SENDFILE:-off}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/bench/work"
RESULTS="$ROOT/bench/results"
OXI_PORT=8801
NGX_PORT=8802

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; return 1; }; }

LOADGEN=""
for c in wrk oha bombardier; do
    if command -v "$c" >/dev/null 2>&1; then LOADGEN="$c"; break; fi
done
if [ -z "$LOADGEN" ]; then
    echo "No load generator found. Install one:" >&2
    echo "  brew install wrk      # or: cargo install oha" >&2
    exit 1
fi
need nginx || { echo "  brew install nginx" >&2; exit 1; }

mkdir -p "$WORK/html" "$WORK/logs" "$RESULTS"

# ---- fixtures -------------------------------------------------------------
# Sizes chosen to exercise different paths: the 0-byte and 1 KiB cases measure
# per-request overhead, 100 KiB measures the mapped-file path, 10 MiB the
# streaming path.
python3 - "$WORK/html" <<'PY'
import os, sys
d = sys.argv[1]
for name, size in [("0b.bin", 0), ("1k.bin", 1024), ("100k.bin", 100*1024), ("10m.bin", 10*1024*1024)]:
    p = os.path.join(d, name)
    if not os.path.exists(p) or os.path.getsize(p) != size:
        with open(p, "wb") as f:
            f.write(b"x" * size)
PY

# ---- configs --------------------------------------------------------------
# Identical semantics on both sides: access logging off (it is not what we are
# measuring), keepalive on, same worker count.
cat > "$WORK/oxiserve.conf" <<EOF
worker_processes  $THREADS;
error_log         $WORK/logs/oxi-error.log crit;
events { worker_connections 16384; }
http {
    access_log off;
    sendfile   $SENDFILE;
    tcp_nodelay on;
    keepalive_timeout  65;
    keepalive_requests 100000;
    server {
        listen $OXI_PORT reuseport;
        server_name _;
        root $WORK/html;
    }
}
EOF

cat > "$WORK/nginx.conf" <<EOF
worker_processes  $THREADS;
error_log         $WORK/logs/ngx-error.log crit;
pid               $WORK/nginx.pid;
daemon            on;
events { worker_connections 16384; }
http {
    access_log off;
    sendfile   $SENDFILE;
    tcp_nodelay on;
    keepalive_timeout  65;
    keepalive_requests 100000;
    client_body_temp_path $WORK/logs/body;
    proxy_temp_path       $WORK/logs/proxy;
    fastcgi_temp_path     $WORK/logs/fastcgi;
    uwsgi_temp_path       $WORK/logs/uwsgi;
    scgi_temp_path        $WORK/logs/scgi;
    server {
        listen $NGX_PORT reuseport;
        server_name _;
        root $WORK/html;
    }
}
EOF

cleanup() {
    [ -n "${OXI_PID:-}" ] && kill "$OXI_PID" 2>/dev/null || true
    nginx -c "$WORK/nginx.conf" -s quit 2>/dev/null || true
    sleep 0.3
    pkill -f "nginx: .*$WORK" 2>/dev/null || true
}
trap cleanup EXIT

hammer() { # url -> "rps latency_p99"
    case "$LOADGEN" in
        wrk)  wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --timeout 10s --latency "$1" 2>/dev/null ;;
        oha)  oha -c "$CONNS" -z "${DURATION}s" --no-tui "$1" 2>/dev/null ;;
        bombardier) bombardier -c "$CONNS" -d "${DURATION}s" -l "$1" 2>/dev/null ;;
    esac
}

run_suite() { # name port
    local name="$1" port="$2"
    for f in 0b.bin 1k.bin 100k.bin 10m.bin; do
        local url="http://127.0.0.1:$port/$f"
        # Warm the page cache and the accept queues before measuring, so the
        # first server tested is not penalised for cold state.
        curl -s -o /dev/null "$url" || true
        hammer "$url" > "$RESULTS/$name-$f.txt"
        echo "  $f: $(grep -iE 'requests/sec|Requests/sec|Success rate|Reqs/sec' "$RESULTS/$name-$f.txt" | head -1)"
    done
}

echo "load generator: $LOADGEN   workers: $THREADS   conns: $CONNS   duration: ${DURATION}s   sendfile: $SENDFILE"
echo

echo "== OxiServe =="
"$ROOT/target/release/oxiserve" -c "$WORK/oxiserve.conf" > "$WORK/logs/oxi.out" 2>&1 &
OXI_PID=$!
sleep 1
run_suite oxiserve "$OXI_PORT"
kill "$OXI_PID" 2>/dev/null || true
wait "$OXI_PID" 2>/dev/null || true
OXI_PID=""

echo
echo "== nginx ($(nginx -v 2>&1 | sed 's/.*nginx\///')) =="
nginx -c "$WORK/nginx.conf"
sleep 1
run_suite nginx "$NGX_PORT"

echo
echo "raw output in $RESULTS/"
