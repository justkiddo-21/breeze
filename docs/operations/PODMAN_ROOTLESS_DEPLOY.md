# Rootless Podman Deploy (Simple Self-Host Path)

This documents deploying Breeze with **rootless Podman** instead of Docker, using the
"Simple self-host" path (`docker-compose.yml` + `docker-compose.override.yml.ghcr`, see
[DEPLOY_PRODUCTION.md](DEPLOY_PRODUCTION.md#which-deploy-path)), fronted by a **Cloudflare
Tunnel** run as a host systemd service. There is no podman-specific guidance elsewhere in
the repo — this is the first time this combination was set up, and it hit four distinct
compatibility issues that a plain `docker compose` deploy never surfaces. Keep this note
with the repo; it's meant to travel to the next server.

Everything below assumes SELinux **enforcing** (Fedora/RHEL-family host). On a host without
SELinux, skip the `:z` mount fixes — they're no-ops there but harmless to leave in.

## Prerequisites

- `podman` + the `docker-compose` CLI plugin (`podman compose` shells out to it —
  confirm with `podman compose version`; if it prints a Compose version, you're set)
- `/etc/subuid` / `/etc/subgid` entries for the deploying user (rootless container UID
  remapping): `grep "^$(whoami):" /etc/subuid /etc/subgid`
- GHCR access: `podman login ghcr.io` with a token that has `read:packages` (needed
  because `ghcr.io/lanternops/breeze/*` images are private)
- A `.env` copied from `.env.example` with every value actually filled in — **do not
  trust "no empty keys" as "ready to deploy"**; see the placeholder-secrets issue below,
  which passed that check and still failed to boot.

## Deploy commands

`scripts/deploy-podman-rootless.sh` automates every step below (secret sanity checks,
image-existence verification, the redis secret file, the `$`-escaping check, bringing the
stack up, health-polling, and a smoke test) — it's the encoded version of this whole doc.
Run it instead of the raw commands by hand:

```bash
podman login ghcr.io -u x-access-token --password-stdin   # paste token via stdin, never as a CLI arg

scripts/deploy-podman-rootless.sh --behind-cloudflare-tunnel-http-origin   # omit the flag if not applicable — see §8
```

Manual equivalent, if you need to run compose directly (e.g. to bring up a single service):

```bash
podman compose \
  -f docker-compose.yml \
  -f docker-compose.override.yml.ghcr \
  -f docker-compose.override.yml.podman \
  up -d
```

`docker-compose.override.yml.podman` is a new file (not present before this deploy) that
holds every podman-specific fix below. It's meant to be layered on top of the existing
`.ghcr` override, not to replace it.

## Issues hit, in the order they appeared

### 1. `BREEZE_VERSION` was 25 releases stale, and the newest git tag had no published image

`.env` had `BREEZE_VERSION=0.81.0`; the newest git tag was `v0.106.0`. Bumping straight to
`0.106.0` failed: `podman pull ghcr.io/lanternops/breeze/api:0.106.0` → `manifest unknown`.
`v0.105.2` and `v0.106.0` are tagged in git but no GHCR image was ever published for them
(release pipeline lag, or a tag-only release). **Don't trust the newest git tag — verify
the image actually exists** (`podman pull` the exact tag for all four images: `api`,
`web`, `portal`, `binaries`) before writing `BREEZE_VERSION` into `.env`. `0.105.1` was the
newest tag with all four images actually present.

### 2. `.env` had multiple placeholder/corrupted secrets that only fail at API boot, not at compose-up

The API's own config validator (`apps/api/src/config/validate.ts`) caught these — compose
itself doesn't validate secret *content*, only presence:

- `ENROLLMENT_KEY_PEPPER` and `MFA_RECOVERY_CODE_PEPPER` were both still the literal
  `generate-a-random-hex-string-for-production` string copied verbatim from
  `.env.example` (confirmed via matching sha256 of both values) — never actually
  generated. Fixed with `openssl rand -base64 32` per key (must differ between the two).
- `MFA_ENCRYPTION_KEY` was 256 hex chars instead of the required 64 (32 raw bytes) —
  some other garbage value, not the example placeholder. Fixed with `openssl rand -hex 32`.
- `JWT_ACTIVE_KID` held a full sample JWT string (`eyJhbGci...`) instead of a short `kid`
  label matching a key in `JWT_SIGNING_KEYRING`. The keyring itself was fine — parsing it
  as JSON showed two valid entries (`2026-08`, `2026-09`). Fixed by setting
  `JWT_ACTIVE_KID=2026-08` to match an existing keyring entry instead of inventing a new one.
- `METRICS_SCRAPE_TOKEN` was also the unmodified `.env.example` placeholder (warning only,
  not a hard boot failure). Fixed with `openssl rand -hex 32`.

**Lesson: a "no empty/missing keys vs .env.example" diff is not sufficient readiness
proof.** Boot the API once and read its own validator output before trusting `.env`.

### 3. `DATABASE_URL_APP` had a stale `localhost` host, silently overriding the correct value

API startup got past config validation, ran migrations, then failed with
`ECONNREFUSED 127.0.0.1:5432`. `docker-compose.yml` constructs `DATABASE_URL` itself with
the correct in-network host (`postgres:5432`), but `DATABASE_URL_APP` — which "takes
precedence... required for multi-host/HA URLs" per the compose file's own comment — is
passed through from `.env` verbatim, unreconstructed. `.env` had it left over from local
dev: `postgresql://breeze_app:${POSTGRES_PASSWORD}@localhost:5432/breeze`. Fixed by
changing `localhost` → `postgres` in that one value. **If `DATABASE_URL_APP` is set at
all, its host must independently match the compose network — it does not inherit
`DATABASE_URL`'s correctness.**

### 4. Podman's Docker-API emulation doesn't materialize `secrets.<name>.environment`

`docker-compose.yml` defines `redis_password` as an `environment`-sourced Compose secret
(`environment: REDIS_PASSWORD`). Under real Docker this writes `/run/secrets/redis_password`
into the container. Under podman (`podman compose`, backed by `/usr/libexec/docker/cli-plugins/docker-compose`
talking to podman's Docker-API-compatible socket), that file never appears —
`podman inspect <container> --format '{{json .Mounts}}'` showed **zero mounts** for it,
and redis exited 1 with `cat: can't open '/run/secrets/redis_password'`.

`file:` and `environment:` secret sources are mutually exclusive on the same named secret
(`secrets.redis_password: file|environment attributes are mutually exclusive` if you try
to redefine both in an override) — so the fix isn't overriding the top-level secret. It's
adding a plain bind-mount volume at the same in-container path, which works because the
`secrets:` block is otherwise a no-op under podman anyway:

```bash
mkdir -p podman-secrets && chmod 700 podman-secrets
grep '^REDIS_PASSWORD=' .env | cut -d= -f2- > podman-secrets/redis_password
chmod 644 podman-secrets/redis_password   # see SELinux note below for why 644, not 600
```

```yaml
services:
  redis:
    volumes:
      - ./podman-secrets/redis_password:/run/secrets/redis_password:ro,z
  api:
    volumes:
      - ./podman-secrets/redis_password:/run/secrets/redis_password:ro,z
```

`podman-secrets/` is gitignored — it's regenerated from `.env` on each new host, never
committed.

### 5. SELinux blocks reads on bind-mounted host files without a relabel

Two separate instances of the same root cause:

- The `podman-secrets/redis_password` bind mount above: even after fixing the mount itself,
  redis still got `Permission denied` reading it. `ls -Z` showed the file labeled
  `user_home_t` (default for anything under `$HOME`), not a label containers can read.
  Rootless podman remaps the host UID to root *inside* the container's user namespace, so
  a `600`-mode file owned by the host user isn't readable by a differently-mapped in-container
  UID even where DAC permissions look fine — hence `644`, not `600`, above.
- `docker-compose.yml`'s existing `./docker/Caddyfile.prod:/etc/caddy/Caddyfile:ro` bind
  mount hit the identical failure: Caddy looped forever on
  `Error: reading config from file: open /etc/caddy/Caddyfile: permission denied`.

Fix for both: add the `z` mount option (shared SELinux relabel to `container_file_t`).
Compose merges list-type keys (`volumes:`, `ports:`) by **appending**, not replacing, so
overriding the Caddy volumes list needs the `!override` YAML tag (Compose Spec ≥ 2.24) to
fully replace the base list instead of duplicating it:

```yaml
services:
  caddy:
    volumes: !override
      - ./docker/Caddyfile.prod:/etc/caddy/Caddyfile:ro,z
      - caddy_data:/data
      - caddy_config:/config
```

Confirm the actual merged config resolves the way you expect before running `up`:
`podman compose -f ... -f ... config` and check the relevant service block — this catches
an accidental `ports:` duplication (see next section) before it wastes a container-cycle.

### 6. Rootless podman can't bind ports < 1024 — and it's an SELinux domain restriction, not a plain capability gap

Caddy failed to start: `rootlessport cannot expose privileged port 80 ... choose a larger
port number (>= 1024)`. The two usual rootless-podman fixes for this were both dead ends
here:

- `setcap cap_net_bind_service=+ep` on `/usr/libexec/podman/rootlessport` did nothing —
  this podman instance's `rootlessNetworkCmd` is **`pasta`** (`podman info` →
  `rootlessNetworkCmd: pasta`), a different binary from the classic `rootlessport` helper.
- Re-targeting the `setcap` to `/usr/bin/pasta` (the actual binary in use) *also* did
  nothing — confirmed via `getcap` that the file capability was correctly set, yet the
  bind still failed identically, including in a bare `podman run -p 80:80 alpine sleep 3`
  reproduction with no compose involved.
- Root cause, found via `sudo ausearch -m avc -ts recent`: pasta runs confined under the
  SELinux domain `pasta_t`. That domain's policy has **no `cap_net_bind_service` allow
  rule** — SELinux polices capability *use* per-domain independently of whether the Linux
  capability itself is granted at the file level. `setcap` changes what the kernel's DAC
  capability check allows; it cannot override an SELinux type-enforcement denial. This is
  a known limitation of rootless podman + pasta + SELinux on Fedora, not something fixable
  with a file capability.

That leaves two real options: lower `net.ipv4.ip_unprivileged_port_start`, or publish on a
high port instead. This deployment chose the high-port route:

```yaml
services:
  caddy:
    ports: !override
      - '8080:80'
```

(`!override` matters here too — without it, Compose appends `8080:80` to the base file's
existing `80:80`/`443:443`, which still fails to bind and looks like the fix didn't work.)

### 7. Caddy's own ACME conflicts with a Cloudflare Tunnel front — infinite redirect loop

With the port remapped to 8080 and `BREEZE_DOMAIN=kreslab.dev` still set, `CADDY_SITE_ADDRESS`
(which defaults to `${BREEZE_DOMAIN:-:80}`) became the real domain, so Caddy tried its own
ACME (`tls-alpn-01`, then `http-01`) — which failed anyway, independent of everything else
here, because `kreslab.dev`'s DNS had no A/AAAA record at the time.

Once the Cloudflare Tunnel (systemd `cloudflared`, origin service `http://localhost:8080`)
was pointed at the deploy, requests came back with an **infinite 308 redirect loop**
(`location: https://breeze.kreslab.dev/` repeating). Cause: Caddy's automatic-HTTPS feature
force-redirects any HTTP request to HTTPS *on itself* whenever `CADDY_SITE_ADDRESS` is a
domain — but Cloudflare had already terminated TLS at its edge and was forwarding plain
HTTP to Caddy internally, so every redirect just produced another HTTP request that got
redirected again.

`docker/Caddyfile.prod`'s own header comment documents the correct topology for this case
("Internet -> cloudflared -> Caddy -> API") and says `CADDY_SITE_ADDRESS` should default to
`:80` (plain HTTP) — **Cloudflare Tunnel deployments must not set `CADDY_SITE_ADDRESS` to
a domain**, regardless of what `BREEZE_DOMAIN` is set to for other purposes (CORS,
`PUBLIC_APP_URL`, etc. — those should still be the real `https://` domain). Fix:

```yaml
services:
  caddy:
    environment:
      CADDY_SITE_ADDRESS: ':80'
```

With `CADDY_SITE_ADDRESS=:80`, Caddy never opens 443 internally, so the `8443:443` port
mapping from the previous section's fix is also dead weight — dropped it, only `8080:80`
remains.

### 8. Second, API-level redirect loop — `FORCE_HTTPS` doesn't trust Caddy's own scheme

Fixing #7 got the web UI and static pages loading, but every `/api/v1/*` call in the
browser failed with `ERR_TOO_MANY_REDIRECTS` (login page, config, login-context, MCP
discovery — anything hitting the `api` container). `TRUSTED_PROXY_CIDRS=172.31.0.10/32`
in `.env` correctly matched Caddy's actual fixed IP on the `breeze` network (confirmed via
`podman inspect breeze-caddy --format '{{json .NetworkSettings.Networks}}'`), and
`PUBLIC_API_URL=https://breeze.kreslab.dev` correctly matched the tunnel hostname — so the
proxy-trust config itself (`apps/api/src/services/clientIp.ts`) was right. The redirect was
coming from a different layer: `apps/api/src/middleware/security.ts`'s `FORCE_HTTPS`
HTTP→HTTPS redirect (`TRANSPORT-001`), which only trusts `X-Forwarded-Proto` from a
trusted-CIDR peer — and Caddy's `reverse_proxy` sets that header from **its own listener's
scheme**, not from whatever Cloudflare originally terminated. With `CADDY_SITE_ADDRESS=:80`
(section 7's fix), Caddy's own listener is plain HTTP, so it stamps every proxied request
`X-Forwarded-Proto: http`, always — regardless of the fact that the original browser↔Cloudflare
hop was HTTPS. The API sees `http`, redirects to the canonical `https://` URL per
`PUBLIC_API_URL`, the client re-requests, Caddy stamps `http` again — infinite loop. `/`
and `/login` never hit this because those routes are served by `web`, which has no
`FORCE_HTTPS` middleware; only `api` paths did.

This is a real gap for the "Cloudflare Tunnel with a plain-HTTP origin" topology
specifically — `docker/Caddyfile.prod` has no `header_up X-Forwarded-Proto https` override
anywhere, and adding one there would be a shared-file behavior change affecting every
deployment mode (dev, strict-production, this one), which is a bigger decision than a
single deploy warrants. The pragmatic fix for this deployment: Cloudflare's edge already
enforces HTTPS for the public hostname (the Tunnel's public side is HTTPS by construction;
the plain-HTTP hop is only the private cloudflared↔Caddy leg inside the host), so the API's
own redundant enforcement can be turned off here:

```bash
FORCE_HTTPS=false
```

This only downgrades a hard "not enabled" boot-time config warning
(`apps/api/src/config/validate.ts`, non-fatal) — it does not affect `HttpOnly`/`Secure`
cookie flags or any other TLS-dependent behavior, those key off `NODE_ENV`/other vars
independently.

While in there, also fixed a related (non-blocking) warning: `TRUST_CF_CONNECTING_IP=false`
in `.env` despite this being a genuine Cloudflare-fronted deployment — left off, client IPs
for rate limiting/audit logs/IP allowlists would have resolved from `X-Forwarded-For`
instead of the real Cloudflare edge IP. Set `TRUST_CF_CONNECTING_IP=true`.

**If a future deploy needs `FORCE_HTTPS=true` kept on with this exact topology** (Cloudflare
Tunnel + plain-HTTP Caddy origin), the correct fix is at the Caddy layer, not the API layer:
add `header_up X-Forwarded-Proto https` to the API `reverse_proxy` blocks in
`docker/Caddyfile.prod`, gated so it doesn't regress the strict-production path where Caddy
really does terminate TLS itself. That's a shared-file change and wasn't made here — treat
it as a follow-up, not something to copy-paste into a hotfix.

### 9. A literal `$` in a `.env` value silently truncates itself via Compose interpolation

Not podman-specific — this would break under real Docker Compose too — but it surfaced
during this deploy and is worth catching for the next one. `BREEZE_BOOTSTRAP_ADMIN_PASSWORD`
was `$$$Fk21102003$$$` in `.env`, an attempt to escape a password containing literal `$`
characters that got the escaping wrong. Compose interpolates `.env` VALUES themselves (not
just the YAML) wherever they're substituted into a `${VAR}` placeholder in the compose file
(here, `docker-compose.yml`'s `BREEZE_BOOTSTRAP_ADMIN_PASSWORD: ${BREEZE_BOOTSTRAP_ADMIN_PASSWORD:-}`),
and `$$` is the only way to get a literal `$` through that — a bare `$Word` is read as a
variable reference. `$Fk21102003` doesn't match any real variable, so Compose silently
substitutes an empty string and prints `The "Fk21102003" variable is not set. Defaulting to
a blank string.` — a warning easy to miss since it prints *before* the container-status
lines, and gets scrolled past by any `| tail -N`. The container then failed with a
downstream, seemingly-unrelated error: `BREEZE_BOOTSTRAP_ADMIN_PASSWORD must be at least 16
characters in production` — the mangled runtime value was shorter than what's actually
written in the file, so reading `.env` by eye looked fine.

This value only matters for the very first boot (seeding the initial admin when the users
table is empty) — by the time this bug was found, that boot had already happened
successfully, so the fix was simply regenerating a fresh value with no `$` in it at all
(`openssl rand -base64 24`), since the old one no longer serves any purpose.
`scripts/deploy-podman-rootless.sh` now runs `podman compose ... config` before `up -d` and
fails fast on any `variable is not set` warning, naming the exact dangling reference instead
of letting it surface as a mystifying container-exited-1 later. If you must put a literal
`$` in any `.env` value, double it (`$$`).

## Final `docker-compose.override.yml.podman`

```yaml
services:
  redis:
    volumes:
      - ./podman-secrets/redis_password:/run/secrets/redis_password:ro,z
  api:
    volumes:
      - ./podman-secrets/redis_password:/run/secrets/redis_password:ro,z

  caddy:
    ports: !override
      - '8080:80'
    environment:
      CADDY_SITE_ADDRESS: ':80'
    volumes: !override
      - ./docker/Caddyfile.prod:/etc/caddy/Caddyfile:ro,z
      - caddy_data:/data
      - caddy_config:/config
```

## Checklist for the next server

1. `podman login ghcr.io` (token piped via stdin, never as a CLI arg or pasted into chat —
   rotate immediately if it ever is)
2. Verify `subuid`/`subgid` entries exist for the deploying user
3. Copy `.env.example` → `.env`, fill in every value, **then boot the API once locally and
   read its own config-validator output** before trusting it — don't rely on a diff
   against `.env.example` for readiness
4. Confirm the target `BREEZE_VERSION` actually has all four published images
   (`podman pull` each of `api`/`web`/`portal`/`binaries` at that tag) before writing it
   into `.env` — the newest git tag is not guaranteed to have a published image yet
5. Create `podman-secrets/redis_password` from `.env`'s `REDIS_PASSWORD`, mode `644`
   (not `600` — see SELinux/UID-mapping note above)
6. Copy `docker-compose.override.yml.podman` (above) into the new checkout
7. If fronting with a Cloudflare Tunnel: origin service must be `http://` (not `https://`)
   pointing at the published Caddy port, and `CADDY_SITE_ADDRESS` must stay `:80`
8. With a plain-HTTP Caddy origin behind Cloudflare Tunnel, also set in `.env`:
   `FORCE_HTTPS=false` (the API's own HTTPS-redirect can't trust Caddy's stamped
   `X-Forwarded-Proto`, since Caddy fills it from its own — plain-HTTP — listener, not
   from Cloudflare's original scheme) and `TRUST_CF_CONNECTING_IP=true`
9. `podman compose -f docker-compose.yml -f docker-compose.override.yml.ghcr -f docker-compose.override.yml.podman up -d`
10. `podman compose -f ... config` to sanity-check the merged ports/volumes before trusting
    `up -d`'s output, especially after touching any list-type key (`ports:`, `volumes:`)
11. Smoke-test `/api/v1/config` and `/api/v1/auth/login-context` through the public
    hostname, not just `/` — the `web` app has no `FORCE_HTTPS` middleware and will look
    fine even when every `api` route is stuck in a redirect loop
