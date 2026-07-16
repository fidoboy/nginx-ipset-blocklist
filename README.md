> [!IMPORTANT]
> ## About this fork
>
> This repository is a security-hardened fork of the original **nginx_ipset_access_module**.
>
> The original functionality has been preserved, but several security, robustness and performance improvements have been implemented:
>
> - Replaced shell-based `system()` execution with a direct `fork()` + `exec()` implementation to eliminate shell command injection risks.
> - Added support for both **IPv4** and **IPv6** lookups.
> - The RPC daemon now binds **only to localhost (127.0.0.1)** instead of listening on all network interfaces.
> - `rpcbind` can therefore be safely configured to listen only on localhost, preventing any remote access to the RPC service.
> - Added proper TCP socket initialization (`listen()`) to avoid busy-loop conditions caused by invalid `accept()` calls under libtirpc.
> - Added graceful shutdown handling (SIGINT/SIGTERM), unregistering the RPC program from `rpcbind` before exit.
> - Improved error handling and logging throughout the RPC server.
> - Added configurable `IPSET_PATH` compile-time option instead of relying on the executable being present in `$PATH`.
> - Added a lightweight in-memory TTL cache to the RPC daemon to avoid repeated `ipset test` process creation for identical queries, reducing unnecessary `fork()` + `exec()` overhead under high request rates.
> - The RPC cache can be configured at daemon startup with optional parameters:
>   - `-t <seconds>` sets the cache lifetime (default: **5 seconds**). Use `-t 0` to disable the cache.
>   - `-n <entries>` sets the maximum number of cached entries (default: **256**).
> - Improved compatibility with modern Linux distributions and current libtirpc implementations.
>
> These changes are intended to reduce the attack surface and runtime overhead of the helper daemon while maintaining full compatibility with the original nginx module.

# JarvIPs

<h5 align="center">JarvIPs – an nginx module for dynamic IP access control using Linux netfilter ipsets as a blacklists/whitelists.</h5>

<h4 align="center">
  <a href="https://github.com/kraloveckey/nginx-ipset-blocklist"><img src=".assets/jarvips.png" width=250 lt="JarvIPs"></a>
</h4>

Unlike nginx's built-in `allow`/`deny` directives — which require `nginx -s reload` on every IP list change — `nginx-ipset-blocklist` checks the ipset kernel table on every request.

You can add or remove IPs from the set and the change takes effect **instantly**, with zero nginx restarts and zero dropped connections.

---

## Overview
- [JarvIPs](#jarvips)
  - [Overview](#overview)
  - [Why RPC? Why not query ipset directly from nginx?](#why-rpc-why-not-query-ipset-directly-from-nginx)
  - [Architecture](#architecture)
  - [Repository structure](#repository-structure)
  - [Features](#features)
  - [Configuration syntax](#configuration-syntax)
  - [Inheritance rules](#inheritance-rules)
  - [Configuration examples](#configuration-examples)
    - [Global blacklist for all servers](#global-blacklist-for-all-servers)
    - [Whitelist a restricted admin area](#whitelist-a-restricted-admin-area)
    - [Simultaneous blacklist + whitelist](#simultaneous-blacklist--whitelist)
    - [Per-location overrides](#per-location-overrides)
    - [Check order with ipset\_priority](#check-order-with-ipset_priority)
  - [Dynamic updates — no nginx reload required](#dynamic-updates--no-nginx-reload-required)
  - [Startup order](#startup-order)
  - [Error log messages](#error-log-messages)
  - [Caveats](#caveats)
- [Build and install guide](#build-and-install-guide)
  - [System requirements](#system-requirements)
  - [Part 1 — Build and install `ipset_test_server`](#part-1--build-and-install-ipset_test_server)
    - [1.1 Build](#11-build)
    - [1.2 Verify rpcbind is running](#12-verify-rpcbind-is-running)
    - [1.3 Install as a systemd service (recommended for production)](#13-install-as-a-systemd-service-recommended-for-production)
    - [1.4 Manual start (for development / testing)](#14-manual-start-for-development--testing)
  - [Part 2 — Build the nginx module](#part-2--build-the-nginx-module)
    - [Option A — Dynamic module (recommended)](#option-a--dynamic-module-recommended)
      - [Step 1 — Configure](#step-1--configure)
      - [Step 2 — Build only the module](#step-2--build-only-the-module)
      - [Step 3 — Find where nginx expects modules](#step-3--find-where-nginx-expects-modules)
      - [Step 4 — Install the module](#step-4--install-the-module)
      - [Step 5 — Enable in nginx.conf](#step-5--enable-in-nginxconf)
      - [Step 6 — Validate and reload](#step-6--validate-and-reload)
      - [Updating the module later (no downtime)](#updating-the-module-later-no-downtime)
    - [Option B — Static module (baked into the nginx binary)](#option-b--static-module-baked-into-the-nginx-binary)
      - [Step 1 — Check your current nginx compile flags](#step-1--check-your-current-nginx-compile-flags)
      - [Step 2 — Configure with the module](#step-2--configure-with-the-module)
      - [Step 3 — Build](#step-3--build)
      - [Step 4 — Install](#step-4--install)
      - [Updating the module later](#updating-the-module-later)
  - [Part 3 — Create ipsets](#part-3--create-ipsets)
  - [Part 4 — Verify everything works](#part-4--verify-everything-works)
    - [4.1 Minimal test config](#41-minimal-test-config)
    - [4.2 Run the test sequence](#42-run-the-test-sequence)
    - [4.3 Check the logs](#43-check-the-logs)
    - [4.4 Cleanup after testing](#44-cleanup-after-testing)
  - [Startup order summary](#startup-order-summary)
  - [Troubleshooting](#troubleshooting)

---

## Why RPC? Why not query ipset directly from nginx?

**[`^        back to top        ^`](#overview)**

This is the first question everyone asks.

nginx worker processes run as an unprivileged user (`www-data`, `nobody`, etc.) and cannot call `libipset` or touch netfilter directly — that requires root or `CAP_NET_ADMIN`. Spawning a privileged subprocess on every HTTP request is too slow.

The solution used here is a small **root-owned daemon** (`ipset_test_server`) that holds the privileged connection. nginx workers communicate with it over **ONC RPC** (a lightweight binary IPC mechanism, part of the standard C library) via a local UDP socket. The round-trip is a single UDP packet each way and takes under 1 ms on localhost.

**ONC RPC** (also called Sun RPC) uses a system service called **rpcbind** as a "port directory". When `ipset_test_server` starts, it registers its UDP port with rpcbind. When an nginx worker starts, it asks rpcbind "where is program 0x200000f1?" and gets back the port. After that, all communication is direct, UDP, localhost. rpcbind is a standard Linux service — it is already present on any server that runs NFS or NIS, and it is trivially installed with `apt install rpcbind` everywhere else.

---

## Architecture

**[`^        back to top        ^`](#overview)**

```shell
                    HTTP request arrives
                           │
                           ▼
                    nginx master process (root)
                           │ fork
                    ┌──────┴───────┐
                    │              │  ... N worker processes (www-data)
                    ▼              ▼
             nginx worker    nginx worker
                    │
                    │  on every request that hits a location
                    │  with blacklist/whitelist configured:
                    │
                    │  [ACCESS phase]
                    │  ngx_ipset_blocklist.c   – module logic
                    │  └─ ipset_test.c              – RPC client wrapper
                    │     └─ ipset_test_rpc_clnt.c  – auto-generated RPC stub
                    │
                    │  UDP packet (localhost, ~0.1 ms)
                    │  "Is 1.2.3.4 in set 'myblacklist'?"
                    │
                    ▼
             ipset_test_server                     (runs as root)
             ipset_test_server.c
             └─ ipset_test_rpc_xdr.c  — serialisation (auto-generated)
             └─ system("ipset test myblacklist 1.2.3.4")
                    │
                    ▼
             Linux kernel — netfilter ipset table   (in-memory hash)
                    │
                    └─ answer: IN_SET / NOT_IN_SET
                    │
                    ▼  UDP reply
             nginx worker
             └─ IPADDR_IN_IPSET    → return HTTP 403
             └─ IPADDR_NOT_IN_SET  → pass request to content handler
             └─ RPC error          → log warning, pass request (fail-open)


             rpcbind                               (standard system service)
             └─ "phone book": maps program IDs to UDP/TCP ports
             └─ ipset_test_server registers here at startup
             └─ nginx worker asks here for the port, once per worker start
```

---

## Repository structure

**[`^        back to top        ^`](#overview)**

```shell
`nginx-ipset-blocklist`/
├── ngx_ipset_blocklist.c        nginx module: config parsing, request handler
├── ipset_test.c                 RPC client: builds request, calls RPC stub
├── ipset_test.h                 public API: init / test / deinit
├── ipset_test_rpc.h             RPC interface definition (auto-generated by rpcgen)
├── ipset_test_rpc_clnt.c        RPC client stub          (auto-generated by rpcgen)
├── ipset_test_rpc_xdr.c         XDR serialisation        (auto-generated by rpcgen)
├── ipset_test_server.c          RPC daemon: receives queries, calls ipset
├── Makefile                     builds ipset_test_server only (no nginx needed)
├── ipset_test_server.service    systemd unit for the daemon
└── config                       nginx build system integration
```

The three `*_rpc_*.{c,h}` files were generated with `rpcgen` from a `.x` interface definition file and should not be edited manually.

---

## Features

**[`^        back to top        ^`](#overview)**

- **Blacklist** – return HTTP 403 if the client IP *is in* the named ipset.
- **Whitelist** — return HTTP 403 if the client IP *is not in* the named ipset.
- Both can be active **simultaneously** in the same context; check order is controlled by `ipset_priority` (blacklist first by default).
- Configurable at **`http {}`**, **`server {}`**, and **`location {}`** level.
- Child contexts **inherit** from parents; any level can override or disable with `off`.
- One ipset name for both address families, **or** separate names for IPv4 / IPv6.
- **Fail-open** on RPC errors: logs a warning and passes the request through.
- Works with nginx **1.9.11+** as a dynamic module, or any modern nginx as static.

---

## Configuration syntax

**[`^        back to top        ^`](#overview)**

```nginx
blacklist "setname";                  # one ipset for both IPv4 and IPv6
blacklist "setname4" "setname6";      # separate ipsets per address family
blacklist off;                        # disable blacklist at this level (not inherited down)

whitelist "setname";
whitelist "setname4" "setname6";
whitelist off;

ipset_priority blacklist;             # check blacklist first (default)
ipset_priority whitelist;             # check whitelist first — a whitelisted IP
                                      # always passes, regardless of blacklist
```

**Valid in:** `http {}`, `server {}`, `location {}`

> [!IMPORTANT]
> ⚠️ Do **not** combine `blacklist`/`whitelist` with `return` in the same `location {}` block. 
> 
> Nginx processes requests in phases:
> 1. **REWRITE Phase** (`return`, `rewrite`)
> 2. **ACCESS Phase** (this module, `allow`, `deny`)
> 3. **CONTENT Phase** (`try_files`, `proxy_pass`, static files)
> 
> Because `return` executes in the REWRITE phase, it will answer the request and terminate processing *before* the module's access check is ever reached. Use `try_files` or a proxy backend instead:
>
> ```nginx
> # WRONG — return fires before the module
> location /api/ {
>     blacklist "bad_ips";
>     return 200 "ok";       # ← this wins, module is bypassed
> }
>
> # CORRECT — try_files runs in CONTENT phase, after ACCESS
> location /api/ {
>     blacklist "bad_ips";
>     try_files /index.html =503;   # module runs first, then this
> }
> ```

---

## Inheritance rules

**[`^        back to top        ^`](#overview)**

A context that does not mention `blacklist` or `whitelist` inherits its parent's setting. Using `off` at any level disables that list for the current context and prevents it from being inherited by child contexts.

```nginx
http { blacklist "global"; }          ← set at top level
  server { ... }                      ← inherits "global"
  server {
    blacklist off;                    ← disabled for this server
    location /a { ... }               ← also disabled (inherited "off")
    location /b { blacklist "x"; }    ← re-enabled with a different set
  }
```

When both blacklist and whitelist are active, the check order is controlled by `ipset_priority`:

- `ipset_priority blacklist` *(default)* — blacklist is checked first. A blacklisted IP is denied even if it is also whitelisted. Use this when "deny overrides allow" — for example, to block a compromised corporate server that is still in the whitelist.
- `ipset_priority whitelist` — whitelist is checked first. A whitelisted IP always passes, regardless of the blacklist. Use this when "allow overrides deny" — for example, to guarantee VIP clients are never accidentally blocked.

`ipset_priority` is inherited from parent contexts the same way `blacklist` and `whitelist` are.

---

## Configuration examples

**[`^        back to top        ^`](#overview)**

### Global blacklist for all servers

```nginx
http {
    blacklist "bad_ips" "bad_ips6";

    server {
        listen 80;
        server_name app.example.com;
        # inherits the global blacklist automatically
    }

    server {
        listen 80;
        server_name internal.example.com;
        blacklist off;   # this server is exempt from the global blacklist
    }
}
```

### Whitelist a restricted admin area

**[`^        back to top        ^`](#overview)**

```nginx
server {
    listen 443 ssl;

    location /admin/ {
        whitelist "office_ips";   # only office IPs; everyone else gets 403
        try_files $uri $uri/ =404;
    }

    location / {
        # public — no restrictions
    }
}
```

### Simultaneous blacklist + whitelist

**[`^        back to top        ^`](#overview)**

Both conditions apply: the IP must not be in the blacklist AND must be in the
whitelist. Blacklist is checked first.

```nginx
location /api/ {
    blacklist "known_bots"    "known_bots6";
    whitelist "api_clients"   "api_clients6";
    proxy_pass http://backend;
}
```

### Per-location overrides

**[`^        back to top        ^`](#overview)**

```nginx
http {
    blacklist "global_bl" "global_bl6";   # active by default everywhere

    server {
        location /public/ {
            blacklist off;   # anyone can access this path
            whitelist off;
            try_files $uri =404;
        }

        location /secure/ {
            blacklist "strict_bl";   # tighter list overrides the global one
            whitelist "vpn_users";
            proxy_pass http://secure_backend;
        }
    }
}
```

### Check order with ipset_priority

**[`^        back to top        ^`](#overview)**

```nginx
http {
    blacklist "bad_ips";
    whitelist "vip_clients";
    ipset_priority whitelist;   # VIP always pass, even if in blacklist

    location /api/ {
        ipset_priority blacklist;   # stricter: blacklist wins here
    }
}
```

---

## Dynamic updates — no nginx reload required

**[`^        back to top        ^`](#overview)**

This is the main advantage over nginx's built-in `allow`/`deny`:

```bash
# Block a new IP — takes effect on the very next request
sudo ipset add myblacklist 1.2.3.4

# Unblock
sudo ipset del myblacklist 1.2.3.4

# Block a subnet
sudo ipset add myblacklist 10.0.0.0/8

# View current contents
sudo ipset list myblacklist

# Persist sets across reboots
sudo ipset save > /etc/ipset.rules
# Restore: sudo ipset restore < /etc/ipset.rules
# (add this to a systemd unit or rc.local to auto-restore on boot)

# On Debian/Ubuntu systems, the easiest way to restore ipsets automatically 
# on boot is to install the persistence package:
sudo apt install ipset-persistent
sudo netfilter-persistent save
```

---

## Startup order

**[`^        back to top        ^`](#overview)**

All three services must be running, in this order:

```
1. rpcbind            ← system service; start it with systemctl
2. ipset_test_server  ← our daemon; must be up before nginx workers fork
3. nginx              ← workers connect to the daemon during init_process
```

**Important distinction:** If `ipset_test_server` is not running **when nginx starts or reloads**, the worker processes will fail to initialize the RPC client and will exit immediately with an `[emerg]` error. Nginx will refuse to start.
However, if the daemon crashes **after** nginx is already running, the active workers will not crash. They will safely fall back to the "fail-open" state, logging a `[warn]` and allowing the HTTP requests through until the daemon is restarted.

With `make install` the provided systemd unit sets `Before=nginx.service` and `After=network.target`, so the boot order is handled automatically.

---

## Error log messages

**[`^        back to top        ^`](#overview)**

```shell
# Request denied by blacklist
[notice] ipset_blacklist: access denied by blacklist "myblacklist"

# Request denied by whitelist (IP was not in the set)
[notice] ipset_blacklist: access denied by whitelist "office_ips" (IP not in set)

# RPC daemon unreachable — request passed through (fail-open)
[warn]   ipset_blacklist: RPC error querying blacklist "myblacklist" — request passed through

# Daemon not running when nginx started — worker exits
[emerg]  ipset_blacklist: failed to connect to ipset RPC server on localhost
```

---

## Caveats

**[`^        back to top        ^`](#overview)**

- **Fail-open:** when `ipset_test_server` is unreachable, requests are passed through rather than blocked. This is intentional — a crashed daemon should not take down your site. Monitor the daemon and restart nginx workers if it crashes for an extended period.
- **Rename or delete an ipset:** restart `ipset_test_server` and reload nginx. Changing ipset *contents* (add/del) never requires any restart.
- **UDP transport:** the default is UDP with a 25-second timeout. For very high request rates with many workers, switching to TCP (`"udp"` → `"tcp"` in `ipset_test.c`) can reduce port exhaustion.
- **`return` directive:** see the warning in the [Configuration](#configuration-syntax) section above.

---

# Build and install guide

**[`^        back to top        ^`](#overview)**

The project produces **two independent binaries**. Both must be built and running for the module to work.

| What | How to build | Needs nginx source? |
|------|-------------|-------------------|
| `ipset_test_server` | plain `make` | **No** |
| nginx module (`.so` or baked in) | nginx `./configure` + `make` | **Yes** |

Build the daemon first — it does not depend on nginx at all. Then build the nginx module.

---

## System requirements

**[`^        back to top        ^`](#build-and-install-guide)**

| Component | Minimum version | Install |
|-----------|----------------|---------|
| Linux kernel | 3.0+ | — |
| gcc | any modern | `apt install build-essential` |
| ipset utility | 7.x | `apt install ipset` |
| rpcbind | any | `apt install rpcbind` |
| libtirpc | any | `apt install libtirpc-dev` |
| libpcre3 | any | `apt install libpcre3-dev` |
| zlib | any | `apt install zlib1g-dev` |
| libssl | any | `apt install libssl-dev` |
| nginx source | 1.30.0+ for dynamic; any modern for static | download below |

Install all build dependencies at once:

```bash
sudo apt update
sudo apt install build-essential ipset rpcbind libtirpc-dev \
                 libpcre3-dev zlib1g-dev libssl-dev
```

> [!NOTE]
> **libtirpc vs libnsl:** Modern distros (Debian 11+, Ubuntu 22.04+, Kali 2022+) use `libtirpc`. 
> 
> The project's `config` script and `Makefile` detect which one is present automatically — you do not need to change anything manually.

---

## Part 1 — Build and install `ipset_test_server`

**[`^        back to top        ^`](#build-and-install-guide)**

### 1.1 Build

**[`^        back to top        ^`](#part-1--build-and-install-ipset_test_server)**

```bash
cd /path/to/nginx-ipset-blocklist

make
# Output: ./ipset_test_server
```

If the build succeeds you will see:

```shell
Built: ipset_test_server
Run:   sudo ./ipset_test_server
       (must run before nginx starts)
```

### 1.2 Verify rpcbind is running

**[`^        back to top        ^`](#part-1--build-and-install-ipset_test_server)**

`rpcbind` must be active before the daemon can register itself:

```bash
sudo systemctl enable rpcbind
sudo systemctl start rpcbind
sudo systemctl status rpcbind --no-pager  # must show: Active: active (running)
```

### 1.3 Install as a systemd service (recommended for production)

**[`^        back to top        ^`](#part-1--build-and-install-ipset_test_server)**

```bash
sudo make install
# This does:
#   cp ipset_test_server /usr/local/sbin/
#   cp ipset_test_server.service /etc/systemd/system/
#   systemctl daemon-reload
#   systemctl enable ipset_test_server
#   systemctl start  ipset_test_server
```

Verify the daemon is registered with rpcbind:

```bash
rpcinfo -p localhost | grep 536871153
# Expected output — two lines, one for UDP and one for TCP:
# 536871153    1   udp  XXXXX
# 536871153    1   tcp  XXXXX
```

If you see those two lines, the daemon is running correctly and nginx workers will be able to connect to it.

### 1.4 Manual start (for development / testing)

**[`^        back to top        ^`](#part-1--build-and-install-ipset_test_server)**

```bash
# Start in foreground so you can see output
sudo ./ipset_test_server

# Or in background:
sudo ./ipset_test_server &

# Check registration:
rpcinfo -p localhost | grep 536871153
```

---

## Part 2 — Build the nginx module

**[`^        back to top        ^`](#build-and-install-guide)**

Both options (dynamic `.so` and static) require the **nginx source tree**.

The source is a build-time dependency only — the resulting binary or `.so` has no source dependency and can be deployed anywhere.

**The nginx source version must match the nginx binary you will run.**

```bash
# Check the version of your currently installed nginx:
nginx -v
# Example: nginx version: nginx/1.30.1

# Download the matching source:
export NGX_VER=1.30.1
wget https://nginx.org/download/nginx-${NGX_VER}.tar.gz
tar xf nginx-${NGX_VER}.tar.gz
cd nginx-${NGX_VER}
```

> [!NOTE]
> If you are building a **static** module and will replace the system nginx binary anyway, the version just needs to be a recent stable release — it does not have to match anything.

---

### Option A — Dynamic module (recommended)

**[`^        back to top        ^`](#build-and-install-guide)**

A dynamic module is a `.so` shared library that nginx loads at startup.

Your existing nginx binary is **not modified or replaced**. To update the module, replace the `.so` and run `nginx -s reload` — no downtime.

#### Step 1 — Configure

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

Run this inside the nginx source directory:

```bash
cd nginx-${NGX_VER}

./configure \
    --add-dynamic-module=/path/to/nginx-ipset-blocklist \
    --with-compat
```

`--with-compat` makes the `.so` ABI-compatible with any nginx built with the same flag, including distro-packaged nginx binaries. Always include it for dynamic modules.

You should see near the end of the output:

```shell
adding module in /path/to/nginx-ipset-blocklist
 + ngx_ipset_blocklist was configured
```

#### Step 2 — Build only the module

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

```bash
make modules
# Takes about 10-30 seconds — compiles only the module, not nginx itself
# Output: objs/ngx_ipset_blocklist.so
```

#### Step 3 — Find where nginx expects modules

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

```bash
nginx -V 2>&1 | grep modules-path
# Example output:
# --modules-path=/usr/lib/nginx/modules
# or
# --modules-path=/usr/share/nginx/modules
```

#### Step 4 — Install the module

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

```bash
# Replace the path with what you found in step 3:
sudo cp objs/ngx_ipset_blocklist.so /usr/lib/nginx/modules/

# Verify it landed there:
ls -la /usr/lib/nginx/modules/ | grep ipset
```

#### Step 5 — Enable in nginx.conf

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

Open `/etc/nginx/nginx.conf` and add the following as the **very first line**, before `events {}` and `http {}`:

```nginx
load_module modules/ngx_ipset_blocklist.so;

events {
    ...
}

http {
    ...
}
```

#### Step 6 — Validate and reload

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

```bash
sudo nginx -t
# Must print: configuration file /etc/nginx/nginx.conf test is successful

sudo nginx -s reload
# Graceful reload — no dropped connections, no downtime
```

#### Updating the module later (no downtime)

**[`^        back to top        ^`](#option-a--dynamic-module-recommended)**

```bash
cd nginx-${NGX_VER}
make modules
sudo cp objs/ngx_ipset_blocklist.so /usr/lib/nginx/modules/
sudo nginx -s reload
```

---

### Option B — Static module (baked into the nginx binary)

**[`^        back to top        ^`](#build-and-install-guide)**

The module is compiled directly into the nginx binary. No `.so` file, no `load_module` directive needed. To update the module you must recompile nginx and replace the binary.

Use this option when:
- You are building nginx from scratch anyway.
- You want the simplest possible deployment (single binary, no external files).
- You are building a container image or custom package.

#### Step 1 — Check your current nginx compile flags

**[`^        back to top        ^`](#option-b--static-module-baked-into-the-nginx-binary)**

If you are replacing an existing nginx installation, copy its compile flags so you preserve all currently active modules:

```bash
nginx -V 2>&1
# Look for the long list of --with-* flags in "configure arguments"
```

#### Step 2 — Configure with the module

**[`^        back to top        ^`](#option-b--static-module-baked-into-the-nginx-binary)**

```bash
cd nginx-${NGX_VER}

./configure \
    --add-module=/path/to/nginx-ipset-blocklist \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/run/nginx.pid \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_realip_module
    # paste any other --with-* flags from nginx -V here
```

#### Step 3 — Build

**[`^        back to top        ^`](#option-b--static-module-baked-into-the-nginx-binary)**

```bash
make -j$(nproc)
# Takes 2-5 minutes depending on your CPU
# Output: objs/nginx
```

#### Step 4 — Install

**[`^        back to top        ^`](#option-b--static-module-baked-into-the-nginx-binary)**

```bash
# Stop nginx, back up the old binary, replace it
sudo systemctl stop nginx
sudo cp /usr/sbin/nginx /usr/sbin/nginx.bak
sudo cp objs/nginx /usr/sbin/nginx

# Verify the new binary works:
sudo nginx -t

# Start nginx
sudo systemctl start nginx
nginx -v
```

No `load_module` line is needed in `nginx.conf` — the module is always present in this binary.

#### Updating the module later

**[`^        back to top        ^`](#option-b--static-module-baked-into-the-nginx-binary)**

```bash
make -j$(nproc)
sudo cp objs/nginx /usr/sbin/nginx
sudo nginx -t
sudo systemctl restart nginx   # full restart required when replacing the binary
```

---

## Part 3 — Create ipsets

**[`^        back to top        ^`](#build-and-install-guide)**

ipsets must exist before nginx starts. If nginx starts and an ipset named in the config does not exist, the first RPC query to that set will fail (logged as a warning) and the request will be passed through.

```bash
# Create sets for IPv4
sudo ipset create myblacklist hash:ip family inet
sudo ipset create mywhitelist hash:ip family inet

# Create sets for IPv6
sudo ipset create myblacklist6 hash:ip family inet6
sudo ipset create mywhitelist6 hash:ip family inet6

# Add some IPs
sudo ipset add myblacklist 1.2.3.4
sudo ipset add myblacklist 10.0.0.0/8   # subnets work too

# Persist across reboots
sudo ipset save > /etc/ipset.rules

# To restore on boot, add this to a systemd unit or /etc/rc.local:
# ipset restore < /etc/ipset.rules
```

---

## Part 4 — Verify everything works

**[`^        back to top        ^`](#build-and-install-guide)**

### 4.1 Minimal test config

**[`^        back to top        ^`](#part-4--verify-everything-works)**

Create `/etc/nginx/conf.d/ngx_test.conf`:

```nginx
server {
    listen 8080;
    server_name _;

    root /var/www/html;
    default_type text/plain;

    # Sanity check — no module involved, always 200
    location = /ping {
        return 200 "pong\n";
    }

    # Blacklist test — use try_files, NOT return
    # (return runs before the access check and would bypass the module)
    location = /test {
        blacklist "myblacklist" "myblacklist6";
        try_files /index.html =503;
    }
}
```

```bash
sudo mkdir -p /var/www/html
sudo touch /var/www/html/index.html
echo "it works" | sudo tee /var/www/html/index.html

sudo nginx -t && sudo nginx -s reload
```

### 4.2 Run the test sequence

**[`^        back to top        ^`](#part-4--verify-everything-works)**

```bash
# Add a second loopback address to simulate a "bad" IP
sudo ip addr add 127.0.0.2/8 dev lo

# Add it to the blacklist
sudo ipset add myblacklist 127.0.0.2

# 1. Sanity: nginx itself works
curl -s -o /dev/null -w "ping:          %{http_code}\n" http://127.0.0.1:8080/ping
# Expected: 200

# 2. Clean IP is allowed
curl -s -o /dev/null -w "clean IP:      %{http_code}\n" http://127.0.0.1:8080/test
# Expected: 200

# 3. Blacklisted IP is blocked
curl -s -o /dev/null -w "blacklisted:   %{http_code}\n" \
    --interface 127.0.0.2 http://127.0.0.1:8080/test
# Expected: 403

# 4. Dynamic update — remove from blacklist, NO nginx reload
sudo ipset del myblacklist 127.0.0.2
curl -s -o /dev/null -w "after del:     %{http_code}\n" \
    --interface 127.0.0.2 http://127.0.0.1:8080/test
# Expected: 200  ← instant, no reload needed

# 5. Dynamic update — add back
sudo ipset add myblacklist 127.0.0.2
curl -s -o /dev/null -w "after add:     %{http_code}\n" \
    --interface 127.0.0.2 http://127.0.0.1:8080/test
# Expected: 403  ← instant again
```

### 4.3 Check the logs

**[`^        back to top        ^`](#part-4--verify-everything-works)**

```bash
sudo tail -f /var/log/nginx/error.log | grep -i ipset
# [notice] ipset_blacklist: access denied by blacklist "myblacklist"
```

### 4.4 Cleanup after testing

**[`^        back to top        ^`](#part-4--verify-everything-works)**

```bash
sudo ip addr del 127.0.0.2/8 dev lo
sudo ipset del myblacklist 127.0.0.2
sudo rm /etc/nginx/conf.d/ngx_test.conf
sudo nginx -s reload
```

---

## Startup order summary

**[`^        back to top        ^`](#build-and-install-guide)**

```shell
boot
 │
 ├─► rpcbind starts            (system service, usually automatic)
 │
 ├─► ipset_test_server starts  (Before=nginx.service in the .service file)
 │       └─ registers with rpcbind: "I am 0x200000f1, UDP port XXXXX"
 │
 └─► nginx starts
         └─ each worker calls init_ipset_test_clnt()
                └─ asks rpcbind: "where is 0x200000f1?"
                └─ gets back the UDP port
                └─ worker is ready to handle requests
```

---

## Troubleshooting

**[`^        back to top        ^`](#build-and-install-guide)**

1. Workers crash on startup: `worker process exited with fatal code 2`.

`ipset_test_server` is not running or rpcbind is not running.

```bash
sudo systemctl status rpcbind
sudo systemctl status ipset_test_server

# Fix:
sudo systemctl start rpcbind
sudo systemctl start ipset_test_server
sudo systemctl restart nginx
```

2. Module has no effect — all requests return 200 regardless of ipset contents.

You are using `return` in the same `location {}` block as `blacklist`/`whitelist`.

The `return` directive runs in the REWRITE phase, before the ACCESS phase where the module runs. Replace `return 200 "..."` with `try_files`:

```nginx
# Wrong:
location /x { blacklist "bl"; return 200 "ok"; }

# Correct:
location /x { blacklist "bl"; try_files $uri =503; }
```

3. Build fails: `rpc/rpc.h: No such file or directory`.

```bash
sudo apt install libtirpc-dev
# The project config script will detect it automatically — no other changes needed
```

4. Build fails: `ngx_ipset_blocklist.so` ABI error when loading.

The nginx source version used to compile the `.so` does not match the running nginx binary. Recompile using the matching source version (check `nginx -v`).

5. `rpcinfo -p localhost` shows nothing for program 536871153.

The daemon is not running or failed to register. Check:

```bash
sudo systemctl status ipset_test_server
sudo journalctl -t ipset_test_server -n 30
```

6. Daemon is running but nginx workers still cannot connect.

Check that rpcbind is listening:

```bash
ss -ulnp | grep rpcbind   # UDP
ss -tlnp | grep rpcbind   # TCP
```

Also verify the daemon's UDP port is reachable from localhost:

```bash
rpcinfo -u localhost 536871153 1
# Expected: program 536871153 version 1 ready and waiting
```
