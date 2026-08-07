# Example configurations

Four configs covering the shapes most deployments actually take. Every one of
them passes `oxiserve -t` with **no warnings** — meaning every directive used
is genuinely implemented, not parsed and ignored.

| File | What it shows |
|---|---|
| [`ssl-site.conf`](ssl-site.conf) | A public site on HTTPS: cleartext redirect, ACME, HTTP/2 and HTTP/3, HSTS, `open_file_cache`, SPA `try_files` |
| [`reverse-proxy.conf`](reverse-proxy.conf) | One app behind the edge: `proxy_pass`, WebSockets, `proxy_cache` with lock and stale-while-revalidate |
| [`load-balancer.conf`](load-balancer.conf) | A pool that survives a backend dying: active and passive health, `least_conn`, `ip_hash`, `backup`, `proxy_next_upstream`, plus L4 `stream` and SNI routing |
| [`api-gateway.conf`](api-gateway.conf) | `auth_request`, tiered `limit_req`, `limit_conn`, per-path service routing, CORS preflight, JSON error pages |

## Checking one

```console
$ oxiserve -t -c conf/examples/api-gateway.conf
oxiserve: the configuration file conf/examples/api-gateway.conf syntax is ok
oxiserve: configuration file conf/examples/api-gateway.conf test is successful
```

`-t` distinguishes "not implemented yet" from "unknown directive", so running
it against **your** config is the fastest way to find out what OxiServe does
with it. `-T` additionally dumps the parsed configuration.

Two of these create directories when the config loads, exactly as nginx does:
`proxy_cache_path` in `reverse-proxy.conf`, and the `logs/` directory. The
cache path is deliberately relative so the file tests as an unprivileged
user; production usually wants an absolute one.

## Before running any of them

The certificate paths, upstream addresses and `server_name`s are placeholders.
Nothing here will start as-is — substitute your own, or point
`ssl_certificate` at a self-signed pair for a local trial:

```console
$ openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

## Two behaviours worth knowing

**`return 444`.** nginx treats it as "close without responding". OxiServe has
no special case and will send it as a literal status line, so `ssl-site.conf`
uses `421 Misdirected Request` for the catch-all server instead.

**`allow` / `deny`.** IP-based access control is not implemented. `oxiserve -t`
reports both as unknown directives — except inside a `limit_except` block,
where the contents are currently ignored without a warning. The method
restriction on the `limit_except` line itself *is* enforced (405), so the
common `limit_except POST { deny all; }` idiom still does the right thing.
