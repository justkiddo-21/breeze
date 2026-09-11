-- File-egress (DLP) events — device-scoped hot agent-write table (Task 2, wave 1).
--
-- One row per detected egress: a file written to a removable/USB volume, to a
-- network share, or the app/browser upload correlation (a process read a local
-- file then made an outbound connection). Written by the agent via
-- PUT /api/v1/agents/:id/file-egress/events.
--
-- Tenancy: RLS shape #5 (device-scoped hot-write). org_id is DENORMALIZED onto
-- the row (NOT NULL) alongside device_id (NOT NULL) so RLS filters on the row's
-- own org_id with no devices join — same shape as peripheral_events
-- (0050-peripheral-control.sql). Each event always carries the reporting
-- DEVICE's own org_id, which is correct even when the governing policy is
-- partner-wide.
--
-- DATA CLASSIFICATION: file names and paths are themselves content-revealing
-- ("patient-list.csv", "Q3-layoffs.xlsx"), so every descriptive/sensitive field
-- (fileName, filePath, destination volume/host/domain, process path) lives in
-- the `details` jsonb, which the tenant-export policy auto-classifies as
-- excludedOpen. Top-level columns are limited to tenant identifiers,
-- coarse classification, and timestamps.
--
-- Idempotent: guarded ENUM create, CREATE TABLE IF NOT EXISTS, index IF NOT
-- EXISTS, DROP POLICY IF EXISTS then CREATE. No inner BEGIN/COMMIT. Pure DDL.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'file_egress_type') THEN
    CREATE TYPE file_egress_type AS ENUM ('removable', 'network_share', 'app_upload');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS file_egress_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organizations(id),
  device_id uuid NOT NULL REFERENCES devices(id),
  -- Agent-side idempotency key; dedupes retried submissions.
  source_event_id varchar(255),
  -- Coarse egress vector; safe (non-content) classification for filtering.
  egress_type file_egress_type NOT NULL,
  -- All content-revealing detail (fileName, filePath, destVolume/destHost/
  -- destDomain, processName/processPath, sizeBytes, confidence) lives here.
  -- jsonb => tenant-export excludedOpen.
  details jsonb,
  occurred_at timestamp NOT NULL,
  created_at timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS file_egress_events_org_device_time_idx
  ON file_egress_events (org_id, device_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS file_egress_events_type_time_idx
  ON file_egress_events (egress_type, occurred_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS file_egress_events_source_event_idx
  ON file_egress_events (org_id, device_id, source_event_id)
  WHERE source_event_id IS NOT NULL;

ALTER TABLE file_egress_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_egress_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS breeze_org_isolation_select ON file_egress_events;
DROP POLICY IF EXISTS breeze_org_isolation_insert ON file_egress_events;
DROP POLICY IF EXISTS breeze_org_isolation_update ON file_egress_events;
DROP POLICY IF EXISTS breeze_org_isolation_delete ON file_egress_events;
CREATE POLICY breeze_org_isolation_select ON file_egress_events
  FOR SELECT USING (public.breeze_has_org_access(org_id));
CREATE POLICY breeze_org_isolation_insert ON file_egress_events
  FOR INSERT WITH CHECK (public.breeze_has_org_access(org_id));
CREATE POLICY breeze_org_isolation_update ON file_egress_events
  FOR UPDATE USING (public.breeze_has_org_access(org_id))
  WITH CHECK (public.breeze_has_org_access(org_id));
CREATE POLICY breeze_org_isolation_delete ON file_egress_events
  FOR DELETE USING (public.breeze_has_org_access(org_id));
