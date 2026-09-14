-- File-egress (DLP) policies — partner-wide config table (Task 2, wave 1).
--
-- Controls the agent's file-egress monitor: whether it runs, and which egress
-- surfaces it watches (removable/USB, network shares, and the app/browser
-- "read-a-file-then-upload" correlation case). Overt, security-department DLP
-- on company-owned machines. DISABLED BY DEFAULT (`enabled = false`): the row
-- must be created AND flipped on before any device starts monitoring.
--
-- Ownership follows the partner-wide-first rule (epic #2135): a policy is owned
-- by EITHER an org (org_id set, partner_id NULL) OR a partner (partner_id set,
-- org_id NULL — "all orgs under this MSP"), enforced by an exactly-one-axis
-- CHECK. Mirrors peripheral_policies (2026-07-01-peripheral-policies-partner-
-- ownership.sql) for the ownership shape and configuration_policies for the
-- partner-wide SELECT branch.
--
-- Idempotent: CREATE ... IF NOT EXISTS, guarded CHECK, DROP POLICY IF EXISTS
-- then CREATE. No inner BEGIN/COMMIT (autoMigrate wraps each file in a txn).
-- Pure DDL — no row writes, so no breeze.scope election is required.

-- ============================================
-- Table
-- ============================================

CREATE TABLE IF NOT EXISTS file_egress_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Exactly one of org_id / partner_id is set (one_owner_chk below).
  org_id uuid REFERENCES organizations(id),
  partner_id uuid REFERENCES partners(id),
  name varchar(200) NOT NULL,
  -- Master switch. OFF by default — see file header.
  enabled boolean NOT NULL DEFAULT false,
  -- Which egress surfaces to watch.
  watch_removable boolean NOT NULL DEFAULT true,
  watch_network_shares boolean NOT NULL DEFAULT true,
  watch_uploads boolean NOT NULL DEFAULT true,
  -- Optional overrides for the upload-correlation case and noise control.
  -- NULL upload_process_watchlist = agent uses its built-in default list
  -- (browsers + common chat apps). ignore_globs = paths/extensions to skip.
  upload_process_watchlist jsonb,
  ignore_globs jsonb NOT NULL DEFAULT '[]'::jsonb,
  min_file_size_bytes bigint NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id),
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'file_egress_policies_one_owner_chk'
      AND conrelid = 'file_egress_policies'::regclass
  ) THEN
    ALTER TABLE file_egress_policies
      ADD CONSTRAINT file_egress_policies_one_owner_chk
      CHECK ((org_id IS NULL) <> (partner_id IS NULL));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS file_egress_policies_org_active_idx
  ON file_egress_policies (org_id, is_active);
CREATE INDEX IF NOT EXISTS file_egress_policies_partner_idx
  ON file_egress_policies (partner_id);

-- ============================================
-- RLS — dual-axis (org OR partner) + system short-circuit
-- ============================================
-- One FOR ALL policy for org/partner/system access, mirroring
-- peripheral_policies_isolation.

ALTER TABLE file_egress_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_egress_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS file_egress_policies_isolation ON file_egress_policies;
CREATE POLICY file_egress_policies_isolation
  ON file_egress_policies
  USING (
    public.breeze_current_scope() = 'system'
    OR (org_id IS NOT NULL AND public.breeze_has_org_access(org_id))
    OR (partner_id IS NOT NULL AND public.breeze_has_partner_access(partner_id))
  )
  WITH CHECK (
    public.breeze_current_scope() = 'system'
    OR (org_id IS NOT NULL AND public.breeze_has_org_access(org_id))
    OR (partner_id IS NOT NULL AND public.breeze_has_partner_access(partner_id))
  );

-- ============================================
-- Partner-wide SELECT branch (LOAD-BEARING on the agent path)
-- ============================================
-- Separate, additive, SELECT-only policy so an org-scoped session (and the
-- agent-auth path, which sets breeze_current_partner_id() = device.partnerId)
-- can READ its partner's partner-wide rows, without widening UPDATE/DELETE
-- targeting. Direct-column form (org_id XOR partner_id on the row itself).
-- Template: 2026-10-05-110000-config-policy-partner-wide-select.sql.

DROP POLICY IF EXISTS file_egress_policies_partner_wide_select ON file_egress_policies;
CREATE POLICY file_egress_policies_partner_wide_select
  ON file_egress_policies
  FOR SELECT
  USING (org_id IS NULL AND partner_id = public.breeze_current_partner_id());
