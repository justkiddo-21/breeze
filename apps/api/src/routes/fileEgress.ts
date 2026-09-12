import { Hono } from 'hono';
import { zValidator } from '../lib/validation';
import { and, desc, eq, gte, inArray, isNull, lte, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../db';
import {
  devices,
  fileEgressEvents,
  fileEgressPolicies,
  fileEgressTypeEnum,
} from '../db/schema';
import { authMiddleware, requireMfa, requirePermission, requireScope, type AuthContext } from '../middleware/auth';
import {
  canManagePartnerWidePolicies,
  PARTNER_WIDE_WRITE_DENIED_MESSAGE,
} from '../services/partnerWideAccess';
import { resolveOrgIdForWrite } from './softwarePolicies';
import { writeRouteAudit } from '../services/auditEvents';
import { PERMISSIONS, type UserPermissions } from '../services/permissions';

export const fileEgressControlRoutes = new Hono();
const MAX_ACTIVITY_WINDOW_DAYS = 90;

fileEgressControlRoutes.use('*', authMiddleware);
fileEgressControlRoutes.use('*', requireScope('organization', 'partner', 'system'));

const policySchema = z.object({
  id: z.string().guid().optional(),
  orgId: z.string().guid().optional(),
  // 'partner' creates a partner-wide ("all orgs") policy: orgId NULL,
  // partnerId = caller's partner. Honored on CREATE only — updates never move a
  // policy between ownership axes.
  ownerScope: z.enum(['organization', 'partner']).optional(),
  name: z.string().min(1).max(200),
  enabled: z.boolean().optional(),
  watchRemovable: z.boolean().optional(),
  watchNetworkShares: z.boolean().optional(),
  watchUploads: z.boolean().optional(),
  uploadProcessWatchlist: z.array(z.string().min(1).max(255)).max(500).nullable().optional(),
  ignoreGlobs: z.array(z.string().min(1).max(1024)).max(1000).optional(),
  minFileSizeBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
  isActive: z.boolean().optional(),
});

const listPoliciesQuerySchema = z.object({
  orgId: z.string().guid().optional(),
  isActive: z.enum(['true', 'false']).optional(),
  enabled: z.enum(['true', 'false']).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const listActivityQuerySchema = z.object({
  orgId: z.string().guid().optional(),
  deviceId: z.string().guid().optional(),
  egressType: z.enum(fileEgressTypeEnum.enumValues).optional(),
  start: z.string().datetime({ offset: true }).optional(),
  end: z.string().datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

// Dual-axis read: org-owned rows the caller can reach OR partner-wide rows
// (org_id NULL) owned by the caller's own partner. Gated on partner scope so
// the app layer agrees with the (stricter) RLS partner-wide SELECT branch —
// org tokens carry a partnerId but never pass breeze_has_partner_access.
function policyAccessCondition(auth: AuthContext): SQL | undefined {
  const orgCond = auth.orgCondition(fileEgressPolicies.orgId);
  if (!orgCond) return undefined; // system scope
  if (auth.scope === 'partner' && auth.partnerId) {
    return sql`(${orgCond} OR (${fileEgressPolicies.orgId} IS NULL AND ${fileEgressPolicies.partnerId} = ${auth.partnerId}))`;
  }
  return orgCond;
}

async function getPolicyWithAccess(policyId: string, auth: AuthContext) {
  const cond = policyAccessCondition(auth);
  const [row] = await db
    .select()
    .from(fileEgressPolicies)
    .where(cond ? and(eq(fileEgressPolicies.id, policyId), cond) : eq(fileEgressPolicies.id, policyId))
    .limit(1);
  return row ?? null;
}

// GET /policies — list policies the caller can see.
fileEgressControlRoutes.get(
  '/policies',
  requirePermission(PERMISSIONS.DEVICES_READ.resource, PERMISSIONS.DEVICES_READ.action),
  zValidator('query', listPoliciesQuerySchema),
  async (c) => {
    const auth = c.get('auth');
    const query = c.req.valid('query');

    if (query.orgId && !auth.canAccessOrg(query.orgId)) {
      return c.json({ error: 'Access denied to this organization' }, 403);
    }

    const conditions: SQL[] = [];
    const accessCond = policyAccessCondition(auth);
    if (accessCond) conditions.push(accessCond);
    if (query.orgId) conditions.push(eq(fileEgressPolicies.orgId, query.orgId));
    if (query.isActive) conditions.push(eq(fileEgressPolicies.isActive, query.isActive === 'true'));
    if (query.enabled) conditions.push(eq(fileEgressPolicies.enabled, query.enabled === 'true'));

    const where = conditions.length > 0 ? and(...conditions) : undefined;
    const limit = query.limit ?? 200;
    const offset = query.offset ?? 0;

    const rows = await db
      .select()
      .from(fileEgressPolicies)
      .where(where)
      .orderBy(desc(fileEgressPolicies.updatedAt), desc(fileEgressPolicies.id))
      .limit(limit)
      .offset(offset);

    return c.json({ data: rows, pagination: { limit, offset } });
  }
);

// POST /policies — create (no id) or update (id set).
fileEgressControlRoutes.post(
  '/policies',
  requirePermission(PERMISSIONS.ORGS_WRITE.resource, PERMISSIONS.ORGS_WRITE.action),
  requireMfa(),
  zValidator('json', policySchema),
  async (c) => {
    const auth = c.get('auth');
    const payload = c.req.valid('json');
    const now = new Date();

    if (payload.id) {
      const existing = await getPolicyWithAccess(payload.id, auth);
      if (!existing) {
        return c.json({ error: 'Policy not found' }, 404);
      }
      // Partner-wide templates are administrable only with the capability.
      if (existing.orgId === null && !canManagePartnerWidePolicies(auth)) {
        return c.json({ error: PARTNER_WIDE_WRITE_DENIED_MESSAGE }, 403);
      }

      const [updated] = await db
        .update(fileEgressPolicies)
        .set({
          name: payload.name,
          enabled: payload.enabled ?? existing.enabled,
          watchRemovable: payload.watchRemovable ?? existing.watchRemovable,
          watchNetworkShares: payload.watchNetworkShares ?? existing.watchNetworkShares,
          watchUploads: payload.watchUploads ?? existing.watchUploads,
          uploadProcessWatchlist:
            payload.uploadProcessWatchlist === undefined
              ? existing.uploadProcessWatchlist
              : payload.uploadProcessWatchlist,
          ignoreGlobs: payload.ignoreGlobs ?? existing.ignoreGlobs,
          minFileSizeBytes: payload.minFileSizeBytes ?? existing.minFileSizeBytes,
          isActive: payload.isActive ?? existing.isActive,
          updatedAt: now,
        })
        .where(eq(fileEgressPolicies.id, existing.id))
        .returning();

      if (!updated) {
        return c.json({ error: 'Failed to update policy' }, 500);
      }

      try {
        writeRouteAudit(c, {
          orgId: updated.orgId,
          action: 'file_egress.policy.update',
          resourceType: 'file_egress_policy',
          resourceId: updated.id,
          resourceName: updated.name,
          details: { enabled: updated.enabled },
        });
      } catch (error) {
        console.error(`[fileEgress] Failed to write audit for policy ${updated.id}:`, error);
      }

      return c.json({ data: updated });
    }

    // Create: resolve ownership axis. Partner-wide creation requires the
    // partner-wide capability; the default path stays org-owned.
    let owner: { orgId: string | null; partnerId: string | null };
    if (payload.ownerScope === 'partner') {
      if (!canManagePartnerWidePolicies(auth) || !auth.partnerId) {
        return c.json({ error: PARTNER_WIDE_WRITE_DENIED_MESSAGE }, 403);
      }
      owner = { orgId: null, partnerId: auth.partnerId };
    } else {
      const orgResolution = resolveOrgIdForWrite(auth, payload.orgId);
      if (!orgResolution.orgId) {
        return c.json({ error: orgResolution.error ?? 'Organization resolution failed' }, 400);
      }
      owner = { orgId: orgResolution.orgId, partnerId: null };
    }

    const [created] = await db
      .insert(fileEgressPolicies)
      .values({
        orgId: owner.orgId,
        partnerId: owner.partnerId,
        name: payload.name,
        enabled: payload.enabled ?? false,
        watchRemovable: payload.watchRemovable ?? true,
        watchNetworkShares: payload.watchNetworkShares ?? true,
        watchUploads: payload.watchUploads ?? true,
        uploadProcessWatchlist: payload.uploadProcessWatchlist ?? null,
        ignoreGlobs: payload.ignoreGlobs ?? [],
        minFileSizeBytes: payload.minFileSizeBytes ?? 0,
        isActive: payload.isActive ?? true,
        createdBy: auth.user.id,
      })
      .returning();

    if (!created) {
      return c.json({ error: 'Failed to create policy' }, 500);
    }

    try {
      writeRouteAudit(c, {
        orgId: created.orgId,
        action: 'file_egress.policy.create',
        resourceType: 'file_egress_policy',
        resourceId: created.id,
        resourceName: created.name,
        details: { enabled: created.enabled, ownerScope: payload.ownerScope ?? 'organization' },
      });
    } catch (error) {
      console.error(`[fileEgress] Failed to write audit for policy ${created.id}:`, error);
    }

    return c.json({ data: created }, 201);
  }
);

// DELETE /policies/:id
fileEgressControlRoutes.delete(
  '/policies/:id',
  requirePermission(PERMISSIONS.ORGS_WRITE.resource, PERMISSIONS.ORGS_WRITE.action),
  requireMfa(),
  zValidator('param', z.object({ id: z.string().guid() })),
  async (c) => {
    const auth = c.get('auth');
    const { id } = c.req.valid('param');

    const existing = await getPolicyWithAccess(id, auth);
    if (!existing) {
      return c.json({ error: 'Policy not found' }, 404);
    }
    if (existing.orgId === null && !canManagePartnerWidePolicies(auth)) {
      return c.json({ error: PARTNER_WIDE_WRITE_DENIED_MESSAGE }, 403);
    }

    await db.delete(fileEgressPolicies).where(eq(fileEgressPolicies.id, existing.id));

    try {
      writeRouteAudit(c, {
        orgId: existing.orgId,
        action: 'file_egress.policy.delete',
        resourceType: 'file_egress_policy',
        resourceId: existing.id,
        resourceName: existing.name,
      });
    } catch (error) {
      console.error(`[fileEgress] Failed to write audit for policy ${existing.id}:`, error);
    }

    return c.json({ success: true });
  }
);

// GET /events — file-egress activity. Contains content-revealing detail, so it
// is gated on DEVICES_READ, org-isolated, and narrowed to the caller's
// accessible sites (RLS does not defend the site axis).
fileEgressControlRoutes.get(
  '/events',
  requirePermission(PERMISSIONS.DEVICES_READ.resource, PERMISSIONS.DEVICES_READ.action),
  zValidator('query', listActivityQuerySchema),
  async (c) => {
    const auth = c.get('auth');
    const perms = c.get('permissions') as UserPermissions | undefined;
    const query = c.req.valid('query');

    if (query.orgId && !auth.canAccessOrg(query.orgId)) {
      return c.json({ error: 'Access denied to this organization' }, 403);
    }

    const conditions: SQL[] = [];
    const orgCondition = auth.orgCondition(fileEgressEvents.orgId);
    if (orgCondition) conditions.push(orgCondition);
    if (query.orgId) conditions.push(eq(fileEgressEvents.orgId, query.orgId));
    if (query.deviceId) conditions.push(eq(fileEgressEvents.deviceId, query.deviceId));
    if (query.egressType) conditions.push(eq(fileEgressEvents.egressType, query.egressType));

    const start = query.start ? new Date(query.start) : null;
    const end = query.end ? new Date(query.end) : null;
    const effectiveStart = start ?? new Date(Date.now() - 24 * 60 * 60 * 1000);
    const effectiveEnd = end ?? new Date();
    if (effectiveStart.getTime() > effectiveEnd.getTime()) {
      return c.json({ error: 'start must be before or equal to end' }, 400);
    }
    const maxWindowMs = MAX_ACTIVITY_WINDOW_DAYS * 24 * 60 * 60 * 1000;
    if ((effectiveEnd.getTime() - effectiveStart.getTime()) > maxWindowMs) {
      return c.json({ error: `Time range cannot exceed ${MAX_ACTIVITY_WINDOW_DAYS} days` }, 400);
    }
    conditions.push(gte(fileEgressEvents.occurredAt, effectiveStart));
    conditions.push(lte(fileEgressEvents.occurredAt, effectiveEnd));

    const limit = query.limit ?? 200;
    const offset = query.offset ?? 0;

    // Site-axis narrowing for site-restricted org users. Only org-scope users
    // carry allowedSiteIds, so auth.orgId is present whenever this applies.
    if (perms?.allowedSiteIds && auth.orgId) {
      const allowedDevices = await db
        .select({ id: devices.id })
        .from(devices)
        .where(and(
          eq(devices.orgId, auth.orgId),
          perms.allowedSiteIds.length > 0
            ? inArray(devices.siteId, perms.allowedSiteIds)
            : sql`false`,
        ));
      const allowedDeviceIds = allowedDevices.map((d) => d.id);
      if (query.deviceId && !allowedDeviceIds.includes(query.deviceId)) {
        return c.json({ error: 'Device not found or access denied' }, 403);
      }
      if (allowedDeviceIds.length === 0) {
        return c.json({ data: [], pagination: { total: 0, limit, offset } });
      }
      conditions.push(inArray(fileEgressEvents.deviceId, allowedDeviceIds));
    }

    const where = conditions.length > 0 ? and(...conditions) : undefined;

    const [countRow] = await db
      .select({ count: sql<number>`count(*)` })
      .from(fileEgressEvents)
      .where(where);

    const rows = await db
      .select()
      .from(fileEgressEvents)
      .where(where)
      .orderBy(desc(fileEgressEvents.occurredAt), desc(fileEgressEvents.createdAt), desc(fileEgressEvents.id))
      .limit(limit)
      .offset(offset);

    return c.json({
      data: rows,
      pagination: { total: Number(countRow?.count ?? 0), limit, offset },
    });
  }
);
