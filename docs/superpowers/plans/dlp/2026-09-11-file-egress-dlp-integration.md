# File-Egress DLP: Breeze Integration Plan

> **For agentic workers:** phases are ordered; within a phase, tasks use checkbox
> (- [ ]) syntax. Boxes already checked (- [x]) are implemented on the branches
> named below but **not yet merged or deployed**. Agent-shipped code is verified
> via CI + a Windows runtime spike (no Go toolchain on the ops box).

**Goal:** Detect and surface files leaving a company-owned machine — copied to
USB/removable or network shares, and (the primary ask) uploaded to an app or
browser (Messenger/Zalo/web) — as first-class, policy-gated, partner-wide-capable
telemetry visible on the Breeze dashboard and wired into alerting. Overt,
off-by-default endpoint DLP.

**Architecture:** A standing agent monitor (mirrors `internal/etwlua`) captures
egress on the endpoint and PUTs batched events to the API; the API stores them
in a device-scoped RLS table and serves them to the web UI; policy is authored in
the UI (org- or partner-owned) and delivered to agents on the heartbeat.
Windows uses ETW (Kernel-File + Kernel-Network); Linux uses fanotify (later
wave). Content-revealing fields (file names, paths, destinations) live only in a
jsonb `details` column classified `excludedOpen`.

**Tech Stack:** Go agent (`0xrawsec/golang-etw`, `golang.org/x/sys/windows`,
CGO_ENABLED=0; fanotify via `x/sys/unix` on Linux later), TypeScript/Hono API,
Drizzle ORM + PostgreSQL (RLS), Astro/React web, Vitest + Go `testing`.

**Global Constraints:** Off by default (`enabled=false`); overt (no stealth);
partner-wide-first ownership (org_id XOR partner_id); RLS shape #5 for the hot
event table; filenames never in top-level columns; upload detection is a
read+connect **heuristic** (no byte-level proof — accepted); the upload
correlation contract (Phase 3) is consequential → advisor quorum before
implementing; agent-shipped changes verified by CI + Windows spike.

**Design refs:** capability audit + independent review captured in session
handoff `internal/ops/handoff/16-file-egress-dlp.md`; agent-shipped code lives in
`agent/internal/fileegress/`.

**Tracking:** feature-lifecycle issue TBD (register on approval of this plan).

## Status snapshot (2026-09-11)

- **Wave 1 — server:** DONE on `feature/file-egress-dlp/wave-1-server` (tsc-clean,
  30 unit tests pass; RLS integration suite needs live DB / CI). Unmerged.
- **Wave 2a — Windows agent (file→removable/network):** DONE on
  `feature/file-egress-dlp/wave-2-agent-windows` (compiles `GOOS=windows`, core
  unit-tested). **Runtime unvalidated.** Unmerged.
- **Phase 1 — dashboard UI:** DONE on `feature/file-egress-dlp/wave-1-server`
  (commit `85cf719e9`): page + policy form + policies list + events table +
  per-device Egress tab + nav + i18n (8 locales). 10 component tests pass, web
  tsc clean, i18n contract tests pass. Unmerged.
- **Wave 2b — read→upload correlation (Zalo/Messenger):** CODE WRITTEN on the
  wave-2 branch (connect-driven, review-refined): correlator core unit-tested,
  Windows Kernel-Network + DNS-Client wiring done. Pending `GOOS=windows` build
  validation + a Windows runtime spike for the ETW event-ID/property specifics.
- **Wave-1 deployed to an isolated test stack** (wt-stack, podman) and validated
  live (migrations, routes, auth, create/list policy); a realistic demo dataset
  (4 karaoke PCs + 10 violations) was seeded there.
- **Prod deploy, alerting, Linux fanotify:** not started.

## File map

Server (exists, wave 1):
- `apps/api/migrations/2026-10-15-140005-file-egress-policies.sql`,
  `…-140006-file-egress-events.sql`
- `apps/api/src/db/schema/fileEgress.ts`
- `apps/api/src/routes/agents/fileEgress.ts` (agent ingest),
  `apps/api/src/routes/fileEgress.ts` (management), mounted in `index.ts`
- `apps/api/src/routes/agents/helpers.ts` (`buildFileEgressConfigUpdate`),
  `apps/api/src/routes/agents/heartbeat.ts` (delivery)
- registrations: `rls-coverage.integration.test.ts`, `services/tenantCascade.ts`,
  `routes/devices/core.ts`, `services/tenantExportPolicyRegistry.ts`,
  `services/orgMergeRegistry.ts`
- tests: `__tests__/integration/fileEgressPoliciesPartnerRls.integration.test.ts`,
  `routes/agents/fileEgress.test.ts`, `routes/fileEgress.test.ts`

Agent (exists, wave 2a):
- `agent/internal/fileegress/{fileegress,dedupe}.go` + tests (core),
  `{monitor,classify}_windows.go` (ETW capture)
- `agent/internal/agentapp/fileegress_start_{windows,other}.go`, `main.go` wiring
- `agent/internal/heartbeat/heartbeat.go` (Poster impl + config apply)

To create (remaining):
- Web: `apps/web/src/…/fileEgress/*` (page, policy form, events table), nav +
  device-detail tab (Phase 1)
- Agent: Kernel-Network capture + FileObject→path correlation (Phase 3);
  `agent/internal/fileegress/*_linux.go` fanotify (Phase 5)
- API: alert-rule/notification wiring for `file_egress.detected` (Phase 4);
  events retention/GC migration (Phase 6)

---

## Phase 0 — Land & validate the foundation

- [ ] Merge `fix/edge-web-image-trivy-scan` → main (turns `test-api` green).
- [ ] `git rebase main` `feature/file-egress-dlp/wave-1-server` (drops the
      pre-rewrite ghBase commit), open PR, merge via queue.
- [ ] Deploy wave-1 server (prod currently runs upstream 0.105.1; the API is not
      live until this ships).
- [ ] Windows runtime spike on a real machine: confirm the Kernel-File CREATE
      callback fires, `classify` maps `\Device\HarddiskVolumeN` → the removable
      letter, network prefixes match a mapped/UNC share, PID→image resolves.
- [ ] After the spike confirms the `golang-etw` Provider keyword field name,
      scope the session to the CREATE keyword (remove the TODO in
      `monitor_windows.go`) to cut event volume.

## Phase 1 — Dashboard UI (make it visible) — DONE (commit `85cf719e9`, branch `feature/file-egress-dlp/wave-1-server`)

- [x] `FileEgressPage` — Policies / Activity tabs.
- [x] `FileEgressPolicyForm` — enable toggle, per-surface toggles
      (removable/network/uploads), `ownerScope` selector + partner-wide badge
      (via `useDefaultOwnerScope`), process watchlist + ignore-globs editors,
      min-file-size. `runAction`-wrapped create/update/delete.
- [x] `FileEgressPoliciesList` — dual-axis list, "All orgs" partner-wide badge.
- [x] `FileEgressEventsTable` — egress type, file/app/destination/process (read
      from `details`), type + date filters, pagination. Reused as the per-device
      **Egress** tab (`DeviceFileEgressTab` on `DeviceDetails`).
- [x] Astro route `/file-egress` + Sidebar nav entry (under Security).
- [x] i18n: `file-egress.json` across all 8 locales + nav/device-detail keys;
      `translationCoverage` baselines updated.
- [x] 10 component tests (Vitest + jsdom); web typecheck clean; i18n contract
      tests pass (94).

## Phase 2 — Wave 2a agent (file→USB/network) — CODE WRITTEN, pending build+spike

- [x] ETW Kernel-File Create capture + NT-path→drive classifier + wiring +
      heartbeat plumbing (`agent/internal/fileegress/`, branch
      `feature/file-egress-dlp/wave-2-agent-windows`). Compiles `GOOS=windows`;
      core unit-tested.
- [ ] `go test ./internal/fileegress/...` + `GOOS=windows go build ./...` (user;
      no Go on the ops box).
- [ ] **Windows runtime spike**: Create fires on a USB copy, drive classified,
      PID→process resolves. Then add CREATE keyword scoping (TODO in
      `monitor_windows.go`) to cut volume.
- [ ] Build + KResLab-sign the agent; pilot on one karaoke PC; enable a policy;
      confirm USB + network-share copies appear in the UI.

## Phase 3 — Wave 2b: read→upload correlation (Messenger/Zalo) — CODE WRITTEN, pending build+spike

Design REVISED after an independent review to **connect-driven** (the original
Read+FileObject-map approach was dropped — high volume + FileObject-reuse bug).

- [x] **Advisor quorum** done (independent review; adopted its refinements).
- [x] Correlator core (`correlate.go`): per-PID recent-open buffer fed by
      Kernel-File **Create** (watchlist-gated), per-PID DNS→domain cache,
      connect-triggered correlation, hard FP gates (user-doc path + extension +
      external-IP + tight window), chat-clients-first watchlist, mutex-safe, gc.
      **Unit-tested** (`correlate_test.go`).
- [x] Windows wiring (`upload_windows.go` + `monitor_windows.go`): SEPARATE
      Kernel-Network + DNS-Client session (avoid file-event starvation),
      Create→noteOpen, process-name cache.
- [ ] `go test` + `GOOS=windows go build` validation (user).
- [ ] **Windows spike** for the `TODO(windows-spike)` runtime unknowns:
      Kernel-Network connect event IDs, `daddr`/`dport` (big-endian) +
      DNS `QueryResults` property names/encodings.
- [ ] Tune FP gates / confidence / watchlist from spike data; consider browsers
      (policy-opt-in) once doc-path gating is proven.

## Phase 4 — Alerting & workflow

- [ ] Wire `file_egress.detected` (already published; `app_upload` = high) into
      alert rules / notification routing so egress raises alerts.
- [ ] Optional: AI brain device-context feed + AI alert verdicts for uploads.
- [ ] Optional: per-policy alert thresholds (e.g. only alert on `app_upload` or
      files > N MB).

## Phase 5 — Linux (fanotify) wave

- [ ] `agent/internal/fileegress/*_linux.go`: fanotify **classic fd-mode**
      (`readlink /proc/self/fd`, NOT open_by_handle_at — fails on cifs),
      `FAN_MARK_MOUNT` per egress mount + `FAN_MARK_FILESYSTEM`+path-filter for
      cloud-sync folders.
- [ ] Mount discovery via `poll(2)` on `/proc/self/mountinfo`; classify
      removable (`/sys/block/*/removable`) / network (cifs/nfs/fuse) / cloud.
- [ ] Wave 2b-equivalent read→connect correlation via fanotify + connection table.
- [ ] Go tests; validate on an RTX-3050 Linux karaoke PC.

## Phase 6 — Hardening

- [ ] `file_egress_events` retention/GC (append-heavy) — batched delete migration
      + scheduled job.
- [ ] Per-org tuning: allowlists, quiet hours, ingest rate limits.
- [ ] Export-policy + erasure roundtrip review for the new tables under real load.
- [ ] Re-run RLS/cascade/merge contract suites after any schema change.

---

## Testing strategy

- Server: unit (Vitest + Drizzle mocks) already in place; RLS/cascade/merge
  contract suites run in **Integration Tests** (need live DB) — run before each
  server PR touching these tables.
- Agent: `go test -race ./internal/fileegress/...` (core is CI-testable on
  Linux); Windows ETW capture validated by `GOOS=windows go build` (done) +
  runtime spike (Phase 0/2/3).
- E2E: pilot machine + Playwright once the UI lands.

## Risks & mitigations

- **ETW volume** (Kernel-File is high-throughput): keyword-scope + callback
  early-Skip + dedupe. (Phase 0)
- **NT-path classification** correctness across volume types: spike-validated;
  network handled by redirector prefixes to cover UNC. (Phase 0/3)
- **Upload heuristic** is correlation, not proof — communicate in UI copy; never
  present as certainty.
- **Tenancy**: contract tests are the guard (RLS/cascade/export/merge) — re-run on
  every schema touch; never hand-review only.
- **Blast radius**: agent-shipped; land behind off-by-default policy and pilot
  before fleet rollout.

## Open decisions

- Nav placement: standalone "DLP / File Egress" vs. under an existing Security
  section. (Product)
- Whether `file_egress_policies` should become a config-policy-linkable feature
  type later (currently standalone). (Design; revisit at Phase 4)
- Retention window / volume budget for `file_egress_events`. (Ops)
