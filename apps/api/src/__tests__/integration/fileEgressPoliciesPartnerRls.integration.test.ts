/**
 * file_egress_policies RLS — dual-axis (org OR partner) enforcement
 * (Task 2, epic #2135).
 *
 * Migration under test: 2026-10-15-140005-file-egress-policies.sql.
 *
 * A file-egress policy is owned by EITHER an org (org_id set, partner_id
 * NULL) OR a partner (partner_id set, org_id NULL — partner-wide / "all
 * orgs"). file_egress_events stay owned by the reporting DEVICE's own org
 * (denormalized, RLS shape #5) — see fileEgressPoliciesPartnerRls's sibling
 * suites for the ownership-table pattern this mirrors
 * (peripheralPoliciesPartnerRls.integration.test.ts,
 * maintenanceWindowsPartnerRls.integration.test.ts). This functional test
 * through the REAL postgres.js driver (breeze_app role) is the guard that a
 * partner cannot forge a partner_id for another partner.
 *
 * The second describe block proves the config-delivery fan-out (#1724 trap):
 * buildFileEgressConfigUpdate must let an org-owned policy win over a
 * partner-wide one from the SAME partner, and must never apply a FOREIGN
 * partner's partner-wide policy to a device outside that partner.
 */
import './setup';
import { afterEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { db, withDbAccessContext, type DbAccessContext } from '../../db';
import { devices, fileEgressPolicies, sites } from '../../db/schema';
import { buildFileEgressConfigUpdate } from '../../routes/agents/helpers';
import { createOrganization, createPartner } from './db-utils';

const createdPolicies: string[] = [];
const createdDevices: string[] = [];
const createdSites: string[] = [];

const SYSTEM_CTX: DbAccessContext = {
  scope: 'system',
  orgId: null,
  accessibleOrgIds: null,
  accessiblePartnerIds: null,
  userId: null,
};

afterEach(async () => {
  if (createdPolicies.length === 0 && createdDevices.length === 0) return;
  await withDbAccessContext(SYSTEM_CTX, async () => {
    for (const id of createdPolicies) {
      await db.delete(fileEgressPolicies).where(eq(fileEgressPolicies.id, id));
    }
    for (const id of createdDevices) {
      await db.delete(devices).where(eq(devices.id, id));
    }
    for (const id of createdSites) {
      await db.delete(sites).where(eq(sites.id, id));
    }
  });
  createdPolicies.length = 0;
  createdDevices.length = 0;
  createdSites.length = 0;
});

function partnerContext(partnerId: string, orgIds: string[]): DbAccessContext {
  return {
    scope: 'partner',
    orgId: null,
    accessibleOrgIds: orgIds,
    accessiblePartnerIds: [partnerId],
    userId: null,
  };
}

/**
 * An ORG-scoped session. `currentPartnerId` mirrors what
 * `buildDbAccessContext` (middleware/auth.ts) — and, on the agent path,
 * `middleware/agentAuth.ts` (`currentPartnerId: device.partnerId`) — actually
 * puts on an org/agent token: the token's OWN partner, populated for every
 * scope and distinct from `accessiblePartnerIds`, which stays empty for org
 * scope. It is what `file_egress_policies_partner_wide_select` keys on, so a
 * test that omits it is exercising a context with no partner GUC at all, not
 * an org token's, and any "org scope sees nothing" assertion under it is
 * vacuous.
 */
function orgContext(orgId: string, currentPartnerId: string | null = null): DbAccessContext {
  return {
    scope: 'organization',
    orgId,
    accessibleOrgIds: [orgId],
    accessiblePartnerIds: [],
    userId: null,
    currentPartnerId,
  };
}

const BASE_POLICY = {
  name: 'Partner-wide DLP monitor',
  enabled: true,
  watchRemovable: true,
  watchNetworkShares: true,
  watchUploads: true,
  ignoreGlobs: [] as string[],
  minFileSizeBytes: 0,
  isActive: true,
};

async function seedPartnerPolicy(partnerId: string): Promise<string> {
  const rows = await withDbAccessContext(partnerContext(partnerId, []), () =>
    db
      .insert(fileEgressPolicies)
      .values({ ...BASE_POLICY, orgId: null, partnerId })
      .returning(),
  );
  const id = rows[0]!.id;
  createdPolicies.push(id);
  return id;
}

describe('file_egress_policies RLS — dual-axis (2026-10-15 migration)', () => {
  it('partner scope can INSERT a partner-wide policy (org_id NULL, partner_id set)', async () => {
    const partner = await createPartner();

    const rows = await withDbAccessContext(partnerContext(partner.id, []), () =>
      db
        .insert(fileEgressPolicies)
        .values({ ...BASE_POLICY, orgId: null, partnerId: partner.id })
        .returning(),
    );

    expect(rows).toHaveLength(1);
    expect(rows[0]?.orgId).toBeNull();
    expect(rows[0]?.partnerId).toBe(partner.id);
    if (rows[0]) createdPolicies.push(rows[0].id);
  });

  it('a different partner can neither see nor forge a policy attributed to the first partner', async () => {
    const partnerA = await createPartner();
    const partnerB = await createPartner();
    const id = await seedPartnerPolicy(partnerA.id);

    const visibleToB = await withDbAccessContext(partnerContext(partnerB.id, []), () =>
      db.select({ id: fileEgressPolicies.id }).from(fileEgressPolicies).where(eq(fileEgressPolicies.id, id)),
    );
    expect(visibleToB).toEqual([]);

    await expect(
      withDbAccessContext(partnerContext(partnerB.id, []), () =>
        db
          .insert(fileEgressPolicies)
          .values({ ...BASE_POLICY, name: 'Forged partner-wide', orgId: null, partnerId: partnerA.id })
          .returning(),
      ),
    ).rejects.toMatchObject({ cause: { code: '42501' } });
  });

  // `file_egress_policies_partner_wide_select` (2026-10-15-140005 migration,
  // same file that creates the table) grants an org token a SELECT-only view
  // of its OWN partner's partner-wide rows — the branch is LOAD-BEARING on the
  // agent config-delivery path (middleware/agentAuth.ts sets
  // `currentPartnerId: device.partnerId`). Org tokens still never pass
  // `breeze_has_partner_access`, so every WRITE path is exactly as strict as
  // an org-only policy.
  it('an org-scope caller of the owning partner CAN read a partner-wide policy but cannot write it', async () => {
    const partner = await createPartner();
    const org = await createOrganization({ partnerId: partner.id });
    const id = await seedPartnerPolicy(partner.id);

    const visibleToOrg = await withDbAccessContext(orgContext(org.id, partner.id), () =>
      db.select({ id: fileEgressPolicies.id }).from(fileEgressPolicies).where(eq(fileEgressPolicies.id, id)),
    );
    expect(visibleToOrg.map((r) => r.id)).toEqual([id]);

    // The branch is FOR SELECT only: RLS hides the row from the write command
    // rather than raising, so assert the ROW COUNT — "it didn't throw" would be
    // satisfied by a successful hijack.
    const updated = await withDbAccessContext(orgContext(org.id, partner.id), () =>
      db
        .update(fileEgressPolicies)
        .set({ name: 'HIJACKED' })
        .where(eq(fileEgressPolicies.id, id))
        .returning({ id: fileEgressPolicies.id }),
    );
    expect(updated).toEqual([]);
  });

  it('org scope can still INSERT and SELECT an org-scoped policy (unchanged shape)', async () => {
    const partner = await createPartner();
    const org = await createOrganization({ partnerId: partner.id });

    const inserted = await withDbAccessContext(orgContext(org.id), () =>
      db
        .insert(fileEgressPolicies)
        .values({ ...BASE_POLICY, name: 'Org policy', orgId: org.id, partnerId: null })
        .returning(),
    );
    if (inserted[0]) createdPolicies.push(inserted[0].id);

    expect(inserted).toHaveLength(1);
    expect(inserted[0]?.orgId).toBe(org.id);

    const visible = await withDbAccessContext(orgContext(org.id), () =>
      db
        .select({ id: fileEgressPolicies.id })
        .from(fileEgressPolicies)
        .where(eq(fileEgressPolicies.id, inserted[0]!.id)),
    );
    expect(visible.map((r) => r.id)).toContain(inserted[0]?.id);
  });

  it('the one-owner CHECK rejects a policy that sets BOTH axes and one that sets NEITHER', async () => {
    const partner = await createPartner();
    const org = await createOrganization({ partnerId: partner.id });

    await expect(
      withDbAccessContext(SYSTEM_CTX, () =>
        db
          .insert(fileEgressPolicies)
          .values({ ...BASE_POLICY, name: 'Both axes', orgId: org.id, partnerId: partner.id })
          .returning(),
      ),
    ).rejects.toMatchObject({ cause: { code: '23514' } });

    await expect(
      withDbAccessContext(SYSTEM_CTX, () =>
        db
          .insert(fileEgressPolicies)
          .values({ ...BASE_POLICY, name: 'No axis', orgId: null, partnerId: null })
          .returning(),
      ),
    ).rejects.toMatchObject({ cause: { code: '23514' } });
  });

  it('partner scope can UPDATE and DELETE its own partner-wide policy', async () => {
    const partner = await createPartner();
    const id = await seedPartnerPolicy(partner.id);

    const updated = await withDbAccessContext(partnerContext(partner.id, []), () =>
      db
        .update(fileEgressPolicies)
        .set({ name: 'Renamed DLP monitor', enabled: false })
        .where(eq(fileEgressPolicies.id, id))
        .returning(),
    );
    expect(updated).toHaveLength(1);
    expect(updated[0]?.enabled).toBe(false);

    const deleted = await withDbAccessContext(partnerContext(partner.id, []), () =>
      db.delete(fileEgressPolicies).where(eq(fileEgressPolicies.id, id)).returning(),
    );
    expect(deleted).toHaveLength(1);
    createdPolicies.splice(createdPolicies.indexOf(id), 1);
  });
});

// ============================================================
// Config-delivery fan-out (#1724 trap): the load-bearing SQL that makes a
// stored partner-wide policy actually reach agents, and that lets an
// org-owned policy override it. buildFileEgressConfigUpdate runs in the
// CALLER's own db context (not a system escape) — mirror the agent-auth
// shape (orgContext with currentPartnerId set) exactly as
// middleware/agentAuth.ts does for real agent requests.
// ============================================================

describe('buildFileEgressConfigUpdate — partner-wide policy fan-out and org precedence (#1724)', () => {
  async function seedDevice(orgId: string, hostname: string): Promise<string> {
    const [site] = await withDbAccessContext(SYSTEM_CTX, () =>
      db.insert(sites).values({ orgId, name: 'HQ' }).returning(),
    );
    createdSites.push(site!.id);
    const [device] = await withDbAccessContext(SYSTEM_CTX, () =>
      db
        .insert(devices)
        .values({
          orgId,
          siteId: site!.id,
          agentId: `agent-${site!.id.slice(0, 18)}`,
          hostname,
          osType: 'windows',
          osVersion: '10.0',
          architecture: 'x64',
          agentVersion: '1.0.0',
        })
        .returning(),
    );
    createdDevices.push(device!.id);
    return device!.id;
  }

  it("resolves the device org's own policy over a partner-wide policy from the SAME partner", async () => {
    const partner = await createPartner();
    const org = await createOrganization({ partnerId: partner.id });
    const deviceId = await seedDevice(org.id, 'file-egress-precedence');

    await seedPartnerPolicy(partner.id);
    const orgPolicyRows = await withDbAccessContext(orgContext(org.id, partner.id), () =>
      db
        .insert(fileEgressPolicies)
        .values({ ...BASE_POLICY, name: 'Org override', orgId: org.id, partnerId: null, minFileSizeBytes: 4096 })
        .returning(),
    );
    createdPolicies.push(orgPolicyRows[0]!.id);

    const resolved = await withDbAccessContext(orgContext(org.id, partner.id), () =>
      buildFileEgressConfigUpdate(deviceId),
    );
    expect(resolved).not.toBeNull();
    expect(resolved?.min_file_size_bytes).toBe(4096); // org-owned policy won, not the partner-wide one
  });

  it("a FOREIGN partner's partner-wide policy never applies to a device outside that partner", async () => {
    const partnerA = await createPartner();
    const partnerB = await createPartner();
    const orgA = await createOrganization({ partnerId: partnerA.id });
    const deviceA = await seedDevice(orgA.id, 'file-egress-fanout-a');

    await seedPartnerPolicy(partnerB.id); // foreign partner's partner-wide policy

    const resolved = await withDbAccessContext(orgContext(orgA.id, partnerA.id), () =>
      buildFileEgressConfigUpdate(deviceA),
    );
    expect(resolved).toBeNull(); // no policy owned by orgA or partnerA exists
  });

  it("the device org's own partner-wide policy DOES apply when no org-owned policy exists", async () => {
    const partner = await createPartner();
    const org = await createOrganization({ partnerId: partner.id });
    const deviceId = await seedDevice(org.id, 'file-egress-partner-wide-applies');

    await seedPartnerPolicy(partner.id);

    const resolved = await withDbAccessContext(orgContext(org.id, partner.id), () =>
      buildFileEgressConfigUpdate(deviceId),
    );
    expect(resolved).not.toBeNull();
    expect(resolved?.enabled).toBe(true);
  });
});
