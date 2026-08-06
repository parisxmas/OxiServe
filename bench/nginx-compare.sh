#!/bin/bash
# Compares OxiServe against nginx on Linux, with the fairness checks this
# project has already had to learn the hard way:
#
#   * Equal worker counts, verified at run time by counting what actually
#     serves traffic on each side. nginx forks worker *processes*; OxiServe
#     runs worker *threads* inside one process, so counting processes for both
#     reports 3 against 1 and calls an unfair run fair.
#   * Neither server is re-pinned by this script. `worker_cpu_affinity auto`
#     and OxiServe's own pinning already put worker i on core i; a `taskset`
#     over them would REMOVE that and hand us a win that is really cache
#     migration on nginx's side.
#   * The load generator gets more cores than the servers, so it is never the
#     ceiling. When both sides saturate, every scenario reads ~1.00x and the
#     numbers mean nothing.
#   * Rounds alternate which server runs first, and the result is the median,
#     because drift over a run otherwise favours whoever went first.
#
# Requires: nginx, wrk, h2load (nghttp2-client), openssl.
set -u

D=${D:-/tmp/oxi-bench}
OXISERVE=${OXISERVE:-$(cd "$(dirname "$0")/.." && pwd)/target/release/oxiserve}
WORKERS=${WORKERS:-2}
SRV_CPUS=${SRV_CPUS:-0-1}
GEN_CPUS=${GEN_CPUS:-2-5}
DUR=${DUR:-10}
CONNS=${CONNS:-200}
ROUNDS=${ROUNDS:-5}
NG_PORT=8081; NG_TLS=8443
OX_PORT=8082; OX_TLS=8444

# ---------------------------------------------------------------- fixtures --
setup() {
    mkdir -p "$D/www" "$D/logs"
    [ -f "$D/www/small.html" ] || head -c 100 /dev/urandom | base64 | head -c 100 > "$D/www/small.html"
    [ -f "$D/www/medium.html" ] || head -c 10240 /dev/urandom | base64 | head -c 10240 > "$D/www/medium.html"
    [ -f "$D/www/large.bin" ] || head -c 1048576 /dev/urandom > "$D/www/large.bin"
    [ -f "$D/cert.pem" ] || openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$D/key.pem" -out "$D/cert.pem" -days 3 -subj "/CN=localhost" 2>/dev/null

    cat > "$D/nginx.conf" <<EOF
worker_processes $WORKERS;
worker_cpu_affinity auto;
error_log $D/logs/nginx-error.log crit;
pid $D/nginx.pid;
events { worker_connections 4096; multi_accept on; }
http {
    access_log off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100000;
    gzip off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server {
        listen $NG_PORT reuseport backlog=4096;
        listen $NG_TLS ssl http2 reuseport backlog=4096;
        ssl_certificate $D/cert.pem;
        ssl_certificate_key $D/key.pem;
        root $D/www;
        location / { }
    }
}
EOF

    cat > "$D/oxiserve.conf" <<EOF
worker_processes $WORKERS;
error_log $D/logs/oxi-error.log crit;
events { worker_connections 4096; }
http {
    access_log off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100000;
    gzip off;
    server {
        listen $OX_PORT reuseport backlog=4096;
        listen $OX_TLS ssl http2 reuseport backlog=4096;
        ssl_certificate $D/cert.pem;
        ssl_certificate_key $D/key.pem;
        root $D/www;
        location / { }
    }
}
EOF
}

# ------------------------------------------------------------- server ctl --
start_nginx() { sudo nginx -c "$D/nginx.conf" 2>/dev/null; sleep 1.2; }
stop_nginx() {
    sudo nginx -c "$D/nginx.conf" -s quit >/dev/null 2>&1
    sleep 1; sudo pkill -f "nginx:" >/dev/null 2>&1; sleep 0.6
}
start_oxi() { "$OXISERVE" -c "$D/oxiserve.conf" >/dev/null 2>&1 & sleep 1.5; }
stop_oxi() { pkill -f "oxiserve -c $D" >/dev/null 2>&1; sleep 0.8; }

verify() {
    local out=""
    case "$1" in
      nginx)
        for p in $(pgrep -f "nginx: worker"); do
            out="$out cpu$(taskset -pc "$p" 2>/dev/null | sed 's/.*: //')"
        done
        echo "  nginx    $(echo $out | wc -w) workers on:$out" ;;
      oxiserve)
        for p in $(pgrep -f "oxiserve -c"); do
            for t in /proc/"$p"/task/*; do
                case "$(cat "$t/comm" 2>/dev/null)" in
                    *worker*) out="$out cpu$(taskset -pc "$(basename "$t")" 2>/dev/null | sed 's/.*: //')" ;;
                esac
            done
        done
        echo "  oxiserve $(echo $out | wc -w) workers on:$out" ;;
    esac
}

# ------------------------------------------------------------------ loads --
wrk_rps()  { taskset -c "$GEN_CPUS" wrk -t4 -c"$CONNS" -d"${DUR}s" "$@" 2>/dev/null | awk '/Requests\/sec/{print $2}'; }
h2_rps()   { taskset -c "$GEN_CPUS" h2load -n150000 -c100 -m32 -t4 "$1" 2>/dev/null | awk '/finished in/{print $4}'; }

median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }

# Runs one scenario ROUNDS times, alternating which server goes first.
compare() {
    local label="$1" ngcmd="$2" oxcmd="$3"
    local ng=() ox=()
    for i in $(seq 1 "$ROUNDS"); do
        if [ $((i % 2)) -eq 1 ]; then
            start_nginx; ng+=("$(eval "$ngcmd")"); stop_nginx
            start_oxi;   ox+=("$(eval "$oxcmd")"); stop_oxi
        else
            start_oxi;   ox+=("$(eval "$oxcmd")"); stop_oxi
            start_nginx; ng+=("$(eval "$ngcmd")"); stop_nginx
        fi
    done
    local a b
    a=$(median "${ng[@]}"); b=$(median "${ox[@]}")
    awk -v l="$label" -v a="$a" -v b="$b" 'BEGIN{
        printf "  %-34s nginx=%-11.0f oxiserve=%-11.0f %.3fx %s\n",
               l, a, b, b/a, (b>a ? "(we win)" : "(we lose)")
    }'
}

# -------------------------------------------------------------------- main --
setup
case "${1:-all}" in
  verify)
    start_nginx; verify nginx; stop_nginx
    start_oxi;   verify oxiserve; stop_oxi
    ;;
  *)
    echo "== workers=$WORKERS on cpu$SRV_CPUS, generator on cpu$GEN_CPUS, ${DUR}s x $ROUNDS rounds, median =="
    start_nginx; verify nginx; stop_nginx
    start_oxi;   verify oxiserve; stop_oxi
    echo
    compare "HTTP/1.1 keepalive 100 B" \
        "wrk_rps http://127.0.0.1:$NG_PORT/small.html" \
        "wrk_rps http://127.0.0.1:$OX_PORT/small.html"
    compare "HTTP/1.1 keepalive 10 KB" \
        "wrk_rps http://127.0.0.1:$NG_PORT/medium.html" \
        "wrk_rps http://127.0.0.1:$OX_PORT/medium.html"
    compare "HTTP/1.1 keepalive 1 MB" \
        "wrk_rps http://127.0.0.1:$NG_PORT/large.bin" \
        "wrk_rps http://127.0.0.1:$OX_PORT/large.bin"
    compare "HTTP/1.1 new connection/request" \
        "wrk_rps -H 'Connection: close' http://127.0.0.1:$NG_PORT/small.html" \
        "wrk_rps -H 'Connection: close' http://127.0.0.1:$OX_PORT/small.html"
    compare "HTTPS/1.1 keepalive 100 B" \
        "wrk_rps https://127.0.0.1:$NG_TLS/small.html" \
        "wrk_rps https://127.0.0.1:$OX_TLS/small.html"
    compare "HTTP/2 over TLS" \
        "h2_rps https://127.0.0.1:$NG_TLS/small.html" \
        "h2_rps https://127.0.0.1:$OX_TLS/small.html"
    ;;
esac
