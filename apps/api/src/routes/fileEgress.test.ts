import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';

const { permissionGate, mfaGate, permsState } = vi.hoisted(() => ({
  permissionGate: { deny: false },
  mfaGate: { deny: false },
  permsState: { perms: undefined as { allowedSiteIds?: string[] } | undefined }
}));

vi.mock('../db', () => ({
  db: {
    select: vi.fn(),
    insert: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
  },
  runOutsideDbContext: vi.fn(async (fn: () => Promise<unknown>) => fn()),
  withDbAccessContext: vi.fn(async (_ctx: unknown, fn: () => Promise<unknown>) => fn()),
  withSystemDbAccessContext: vi.fn(async (fn: () => Promise<unknown>) => fn()),
}));

vi.mock('../db/schema', () => ({
  fileEgressTypeEnum: { enumValues: ['removable', 'network_share', 'app_upload'] },
  fileEgressEvents: {
    id: 'id',
    orgId: 'orgId',
    deviceId: 'deviceId',
    sourceEventId: 'sourceEventId',
    egressType: 'egressType',
    details: 'details',
    occurredAt: 'occurredAt',
    createdAt: 'createdAt',
  },
  fileEgressPolicies: {
    id: 'id',
    orgId: 'orgId',
    partnerId: 'partnerId',
    name: 'name',
    enabled: 'enabled',
    watchRemovable: 'watchRemovable',
    watchNetworkShares: 'watchNetworkShares',
    watchUploads: 'watchUploads',
    uploadProcessWatchlist: 'uploadProcessWatchlist',
    ignoreGlobs: 'ignoreGlobs',
    minFileSizeBytes: 'minFileSizeBytes',
    isActive: 'isActive',
    createdBy: 'createdBy',
    createdAt: 'createdAt',
    updatedAt: 'updatedAt',
  },
  devices: {
    id: 'id',
    orgId: 'orgId',
    siteId: 'siteId'
  }
}));

vi.mock('../middleware/auth', () => ({
  authMiddleware: vi.fn((c: any, next: any) => {
    c.set('auth', {
      scope: 'organization',
      orgId: '11111111-1111-1111-1111-111111111111',
      accessibleOrgIds: ['11111111-1111-1111-1111-111111111111'],
      canAccessOrg: (orgId: string) => orgId === '11111111-1111-1111-1111-111111111111',
      orgCondition: () => undefined,
      user: { id: 'user-123', email: 'test@example.com' }
    });
    return next();
  }),
  requireScope: vi.fn(() => async (_c: any, next: any) => next()),
  requirePermission: vi.fn(() => async (c: any, next: any) => {
    if (permissionGate.deny) return c.json({ error: 'Forbidden' }, 403);
    // Mirror prod: requirePermission is the gate that populates `permissions`.
    c.set('permissions', permsState.perms);
    return next();
  }),
  requireMfa: vi.fn(() => async (c: any, next: any) => {
    if (mfaGate.deny) return c.json({ error: 'MFA required' }, 403);
    return next();
  })
}));

vi.mock('./softwarePolicies', () => ({
  resolveOrgIdForWrite: vi.fn((auth: { orgId?: string }, orgId?: string) =>
    orgId ? { orgId } : { orgId: auth?.orgId ?? undefined },
  ),
}));

vi.mock('../services/auditEvents', () => ({
  writeRouteAudit: vi.fn()
}));

vi.mock('../services/permissions', () => ({
  PERMISSIONS: {
    ORGS_WRITE: { resource: 'organizations', action: 'write' },
    DEVICES_READ: { resource: 'devices', action: 'read' }
  }
}));

import { db } from '../db';
import { authMiddleware } from '../middleware/auth';
import { PARTNER_WIDE_WRITE_DENIED_MESSAGE } from '../services/partnerWideAccess';
import { fileEgressControlRoutes } from './fileEgress';

const orgId = '11111111-1111-1111-1111-111111111111';
const policyId = '22222222-2222-2222-2222-222222222222';
const partnerId = '66666666-6666-6666-6666-666666666666';

const basePolicy = {
  id: policyId,
  orgId,
  partnerId: null,
  name: 'DLP monitor',
  enabled: true,
  watchRemovable: true,
  watchNetworkShares: true,
  watchUploads: true,
  uploadProcessWatchlist: null,
  ignoreGlobs: [],
  minFileSizeBytes: 0,
  isActive: true,
  createdBy: 'user-123',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
};

describe('fileEgress routes', () => {
  let app: Hono;

  beforeEach(() => {
    vi.clearAllMocks();
    permissionGate.deny = false;
    mfaGate.deny = false;
    permsState.perms = undefined;
    // vi.clearAllMocks() clears call history but NOT a mockImplementation
    // override (e.g. from setPartnerAuth below), so restore the default
    // org-scope auth every test — otherwise a partner-wide test that runs
    // earlier leaks its auth context into unrelated tests.
    vi.mocked(authMiddleware).mockImplementation((c: any, next: any) => {
      c.set('auth', {
        scope: 'organization',
        orgId,
        accessibleOrgIds: [orgId],
        canAccessOrg: (id: string) => id === orgId,
        orgCondition: () => undefined,
        user: { id: 'user-123', email: 'test@example.com' }
      });
      return next();
    });
    app = new Hono();
    app.route('/file-egress', fileEgressControlRoutes);
  });

  it('rejects policy mutation when permission gate fails', async () => {
    permissionGate.deny = true;

    const res = await app.request('/file-egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'DLP monitor' })
    });

    expect(res.status).toBe(403);
  });

  it('rejects policy mutation when MFA gate fails', async () => {
    mfaGate.deny = true;

    const res = await app.request('/file-egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'DLP monitor' })
    });

    expect(res.status).toBe(403);
  });

  it('creates an org-owned policy (happy path)', async () => {
    const created = { ...basePolicy };

    vi.mocked(db.insert).mockReturnValue({
      values: vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue([created])
      })
    } as any);

    const res = await app.request('/file-egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'DLP monitor',
        watchRemovable: true,
        watchNetworkShares: true,
        watchUploads: true
      })
    });

    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.data.id).toBe(policyId);
    expect(body.data.orgId).toBe(orgId);
    expect(body.data.partnerId).toBeNull();
  });

  it('updates a policy (happy path)', async () => {
    const updated = { ...basePolicy, name: 'Renamed DLP monitor', enabled: false };

    // getPolicyWithAccess: db.select().from().where().limit()
    vi.mocked(db.select).mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          limit: vi.fn().mockResolvedValue([basePolicy])
        })
      })
    } as any);

    // db.update().set().where().returning()
    vi.mocked(db.update).mockReturnValue({
      set: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([updated])
        })
      })
    } as any);

    const res = await app.request('/file-egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: policyId,
        name: 'Renamed DLP monitor',
        enabled: false
      })
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.name).toBe('Renamed DLP monitor');
    expect(body.data.enabled).toBe(false);
  });

  it('returns 404 when updating a non-existent policy', async () => {
    vi.mocked(db.select).mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          limit: vi.fn().mockResolvedValue([])
        })
      })
    } as any);

    const res = await app.request('/file-egress/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: policyId,
        name: 'Renamed DLP monitor'
      })
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe('Policy not found');
  });

  it('deletes a policy (happy path)', async () => {
    // getPolicyWithAccess
    vi.mocked(db.select).mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          limit: vi.fn().mockResolvedValue([basePolicy])
        })
      })
    } as any);

    vi.mocked(db.delete).mockReturnValue({
      where: vi.fn().mockResolvedValue(undefined)
    } as any);

    const res = await app.request(`/file-egress/policies/${policyId}`, {
      method: 'DELETE'
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ success: true });
  });

  it('returns 404 when deleting a non-existent policy', async () => {
    vi.mocked(db.select).mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          limit: vi.fn().mockResolvedValue([])
        })
      })
    } as any);

    const res = await app.request(`/file-egress/policies/${policyId}`, {
      method: 'DELETE'
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toBe('Policy not found');
  });

  it('lists policies (dual-axis, happy path)', async () => {
    vi.mocked(db.select).mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          orderBy: vi.fn().mockReturnValue({
            limit: vi.fn().mockReturnValue({
              offset: vi.fn().mockResolvedValue([basePolicy])
            })
          })
        })
      })
    } as any);

    const res = await app.request('/file-egress/policies', { method: 'GET' });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].id).toBe(policyId);
  });

  it('returns 403 on GET /policies?orgId= for an inaccessible org', async () => {
    const res = await app.request(
      '/file-egress/policies?orgId=99999999-9999-9999-9999-999999999999',
      { method: 'GET' }
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('Access denied to this organization');
  });

  it('returns 403 on GET /policies when caller lacks devices.read', async () => {
    permissionGate.deny = true;

    const res = await app.request('/file-egress/policies', { method: 'GET' });

    expect(res.status).toBe(403);
  });

  // ----------------------------------------------------------------
  // Partner-wide dual-ownership gate (epic #2135): a policy with orgId null +
  // partnerId set is only mutable by a caller with
  // canManagePartnerWidePolicies(auth) === true (system scope, or partner
  // scope with partnerOrgAccess 'all'). Mirrors peripheralControl.test.ts's
  // '#2131' partner-wide gate coverage.
  // ----------------------------------------------------------------
  describe('partner-wide ownership gate', () => {
    function setPartnerAuth(partnerOrgAccess: 'all' | 'selected') {
      vi.mocked(authMiddleware).mockImplementation((c: any, next: any) => {
        c.set('auth', {
          scope: 'partner',
          orgId: null,
          partnerId,
          partnerOrgAccess,
          accessibleOrgIds: [orgId],
          canAccessOrg: (id: string) => id === orgId,
          orgCondition: () => undefined,
          user: { id: 'user-partner', email: 'partner@example.com' }
        });
        return next();
      });
    }

    it('returns 403 creating a partner-wide policy when the org caller lacks canManagePartnerWidePolicies', async () => {
      const res = await app.request('/file-egress/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerScope: 'partner',
          name: 'Partner-wide DLP monitor'
        })
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe(PARTNER_WIDE_WRITE_DENIED_MESSAGE);
      expect(db.insert).not.toHaveBeenCalled();
    });

    it('returns 403 creating a partner-wide policy when the partner caller lacks partnerOrgAccess=all', async () => {
      setPartnerAuth('selected');

      const res = await app.request('/file-egress/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerScope: 'partner',
          name: 'Partner-wide DLP monitor'
        })
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe(PARTNER_WIDE_WRITE_DENIED_MESSAGE);
      expect(db.insert).not.toHaveBeenCalled();
    });

    it('creates a partner-wide policy (orgId null, partnerId set) when the partner caller has partnerOrgAccess=all', async () => {
      setPartnerAuth('all');

      const createdPartnerWidePolicy = { ...basePolicy, orgId: null, partnerId };
      const insertValues = vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue([createdPartnerWidePolicy])
      });
      vi.mocked(db.insert).mockReturnValue({ values: insertValues } as any);

      const res = await app.request('/file-egress/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerScope: 'partner',
          name: 'Partner-wide DLP monitor'
        })
      });

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.orgId).toBeNull();
      expect(body.data.partnerId).toBe(partnerId);
      expect(insertValues).toHaveBeenCalledWith(
        expect.objectContaining({ orgId: null, partnerId })
      );
    });

    it('returns 403 updating a partner-wide policy when the caller lacks canManagePartnerWidePolicies', async () => {
      setPartnerAuth('selected');

      const existingPartnerWidePolicy = { ...basePolicy, orgId: null, partnerId };
      vi.mocked(db.select).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            limit: vi.fn().mockResolvedValue([existingPartnerWidePolicy])
          })
        })
      } as any);

      const res = await app.request('/file-egress/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: policyId,
          name: 'Hijacked name'
        })
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe(PARTNER_WIDE_WRITE_DENIED_MESSAGE);
      expect(db.update).not.toHaveBeenCalled();
    });

    it('returns 403 deleting a partner-wide policy when the caller lacks canManagePartnerWidePolicies', async () => {
      setPartnerAuth('selected');

      const existingPartnerWidePolicy = { ...basePolicy, orgId: null, partnerId };
      vi.mocked(db.select).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            limit: vi.fn().mockResolvedValue([existingPartnerWidePolicy])
          })
        })
      } as any);

      const res = await app.request(`/file-egress/policies/${policyId}`, {
        method: 'DELETE'
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe(PARTNER_WIDE_WRITE_DENIED_MESSAGE);
      expect(db.delete).not.toHaveBeenCalled();
    });
  });

  // ----------------------------------------------------------------
  // GET /events — device-scoped, denormalized org_id. RLS defends the org
  // axis; the route's own org-isolation checks are what this suite covers.
  // ----------------------------------------------------------------
  describe('GET /events — org isolation', () => {
    const deviceId = '44444444-4444-4444-4444-444444444444';

    const eventRow = {
      id: '33333333-3333-3333-3333-333333333333',
      orgId,
      deviceId,
      sourceEventId: 'evt-1',
      egressType: 'app_upload',
      details: { fileName: 'report.xlsx' },
      occurredAt: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    it('lists events with pagination (happy path)', async () => {
      const now = new Date();

      // First call: count query. Second call: rows query.
      vi.mocked(db.select)
        .mockReturnValueOnce({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue([{ count: 1 }])
          })
        } as any)
        .mockReturnValueOnce({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              orderBy: vi.fn().mockReturnValue({
                limit: vi.fn().mockReturnValue({
                  offset: vi.fn().mockResolvedValue([eventRow])
                })
              })
            })
          })
        } as any);

      const start = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
      const end = now.toISOString();

      const res = await app.request(
        `/file-egress/events?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&limit=50&offset=0`,
        { method: 'GET' }
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].id).toBe(eventRow.id);
      expect(body.pagination).toEqual({ total: 1, limit: 50, offset: 0 });
    });

    it('returns 403 on GET /events?orgId= for an inaccessible org', async () => {
      const res = await app.request(
        '/file-egress/events?orgId=99999999-9999-9999-9999-999999999999',
        { method: 'GET' }
      );

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe('Access denied to this organization');
    });

    it('returns 400 when the events window exceeds 90 days', async () => {
      const res = await app.request(
        '/file-egress/events?start=2026-01-01T00:00:00.000Z&end=2026-05-01T00:00:00.000Z',
        { method: 'GET' }
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toContain('cannot exceed 90 days');
    });

    it('returns 400 when start is after end', async () => {
      const res = await app.request(
        '/file-egress/events?start=2026-03-01T00:00:00.000Z&end=2026-02-01T00:00:00.000Z',
        { method: 'GET' }
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error).toContain('start must be before or equal to end');
    });

    it('narrows results to in-scope devices for a site-restricted caller', async () => {
      const inScopeSite = 'site-aaaa';
      permsState.perms = { allowedSiteIds: [inScopeSite] };

      // 1. device-resolution select -> devices already filtered to
      //    orgId + siteId IN allowedSiteIds by the route's own WHERE clause
      //    (unlike peripheralControl.ts, fileEgress.ts filters in SQL, not
      //    client-side, so the mocked result is pre-narrowed).
      // 2. count select
      // 3. rows select
      vi.mocked(db.select).mockReset();
      vi.mocked(db.select)
        .mockReturnValueOnce({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue([
              { id: deviceId, siteId: inScopeSite }
            ])
          })
        } as any)
        .mockReturnValueOnce({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockResolvedValue([{ count: 1 }])
          })
        } as any)
        .mockReturnValueOnce({
          from: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              orderBy: vi.fn().mockReturnValue({
                limit: vi.fn().mockReturnValue({
                  offset: vi.fn().mockResolvedValue([eventRow])
                })
              })
            })
          })
        } as any);

      const res = await app.request('/file-egress/events', { method: 'GET' });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      expect(body.data[0].deviceId).toBe(deviceId);
    });

    it('returns 403 when a site-restricted caller requests an out-of-scope deviceId', async () => {
      const inScopeSite = 'site-aaaa';
      const outOfScopeDevice = '55555555-5555-5555-5555-555555555555';
      permsState.perms = { allowedSiteIds: [inScopeSite] };

      // Device-resolution select is pre-filtered to allowedSiteIds in SQL
      // (see note above), so the out-of-scope device never appears here —
      // that's exactly what makes it "not found or access denied" below.
      vi.mocked(db.select).mockReset();
      vi.mocked(db.select).mockReturnValueOnce({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([
            { id: deviceId, siteId: inScopeSite }
          ])
        })
      } as any);

      const res = await app.request(
        `/file-egress/events?deviceId=${outOfScopeDevice}`,
        { method: 'GET' }
      );

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe('Device not found or access denied');
    });

    it('returns 403 on GET /events when caller lacks devices.read', async () => {
      permissionGate.deny = true;

      const res = await app.request('/file-egress/events', { method: 'GET' });

      expect(res.status).toBe(403);
    });
  });
});
