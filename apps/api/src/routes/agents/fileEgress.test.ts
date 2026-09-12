import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';

vi.mock('../../db', () => ({
  db: {
    select: vi.fn(),
    insert: vi.fn(),
  },
  runOutsideDbContext: vi.fn(async (fn: () => Promise<unknown>) => fn()),
  withDbAccessContext: vi.fn(async (_ctx: unknown, fn: () => Promise<unknown>) => fn()),
  withSystemDbAccessContext: vi.fn(async (fn: () => Promise<unknown>) => fn()),
}));

vi.mock('../../db/schema', () => ({
  devices: { id: 'id', orgId: 'orgId', hostname: 'hostname', agentId: 'agentId' },
  organizations: { id: 'id', partnerId: 'partnerId' },
  fileEgressTypeEnum: { enumValues: ['removable', 'network_share', 'app_upload'] },
  fileEgressEvents: { id: 'id' }
}));

vi.mock('../../services/auditEvents', () => ({
  writeAuditEvent: vi.fn()
}));

vi.mock('../../services/eventBus', () => ({
  publishEvent: vi.fn()
}));

import { db } from '../../db';
import { writeAuditEvent } from '../../services/auditEvents';
import { publishEvent } from '../../services/eventBus';
import { fileEgressRoutes } from './fileEgress';

function mockDeviceLookup(device: { id: string; orgId: string; hostname: string }) {
  vi.mocked(db.select).mockReturnValueOnce({
    from: vi.fn().mockReturnValue({
      where: vi.fn().mockReturnValue({
        limit: vi.fn().mockResolvedValue([device])
      })
    })
  } as any);
}

function mockDeviceNotFound() {
  vi.mocked(db.select).mockReturnValueOnce({
    from: vi.fn().mockReturnValue({
      where: vi.fn().mockReturnValue({
        limit: vi.fn().mockResolvedValue([])
      })
    })
  } as any);
}

function mockInsert(insertedRows: { id: string }[]) {
  vi.mocked(db.insert).mockReturnValue({
    values: vi.fn().mockReturnValue({
      onConflictDoNothing: vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue(insertedRows)
      })
    })
  } as any);
}

// Every batch "succeeds" (no dedup skips) — returning() echoes back one row
// per value passed in, so callers can assert on batch boundaries (#200 chunk
// size) without hand-maintaining insertedRows arrays per call.
function mockInsertAllSucceed() {
  vi.mocked(db.insert).mockImplementation(() => ({
    values: vi.fn((batch: unknown[]) => ({
      onConflictDoNothing: vi.fn().mockReturnValue({
        returning: vi.fn().mockResolvedValue(batch.map((_, i) => ({ id: `inserted-${i}` })))
      })
    }))
  } as any));
}

function makeEvent(overrides: Record<string, unknown> = {}) {
  return {
    eventId: 'evt-1',
    egressType: 'removable',
    occurredAt: '2026-02-26T12:00:00.000Z',
    ...overrides,
  };
}

describe('agent file-egress ingest', () => {
  let app: Hono;

  beforeEach(() => {
    vi.clearAllMocks();
    // A prior test may have set publishEvent to reject; restore the default
    // resolved behavior so it doesn't leak into unrelated tests (fileEgress
    // publishes for EVERY event, unlike peripherals which only publishes for
    // 'blocked' events, so a leaked rejection is visible here).
    vi.mocked(publishEvent).mockResolvedValue('evt-published');
    app = new Hono();
    app.use('*', async (c: any, next: any) => {
      c.set('agent', { orgId: 'org-1', agentId: 'agent-1', role: 'agent' });
      await next();
    });
    app.route('/agents', fileEgressRoutes);
  });

  it('returns 404 when device is not found', async () => {
    mockDeviceNotFound();

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [makeEvent()]
      })
    });

    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body).toEqual({ error: 'Device not found' });
    expect(db.insert).not.toHaveBeenCalled();
  });

  it('returns 403 on organization mismatch', async () => {
    // Agent has orgId 'org-A' but device belongs to 'org-B'
    const orgMismatchApp = new Hono();
    orgMismatchApp.use('*', async (c: any, next: any) => {
      c.set('agent', { orgId: 'org-A', agentId: 'agent-1', role: 'agent' });
      await next();
    });
    orgMismatchApp.route('/agents', fileEgressRoutes);

    mockDeviceLookup({ id: 'device-1', orgId: 'org-B', hostname: 'host-1' });

    const res = await orgMismatchApp.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [makeEvent()]
      })
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body).toEqual({ error: 'Organization mismatch' });
    expect(db.insert).not.toHaveBeenCalled();
  });

  it('returns a correct happy-path success response', async () => {
    mockDeviceLookup({ id: 'device-1', orgId: 'org-1', hostname: 'host-1' });
    mockInsert([{ id: 'inserted-1' }, { id: 'inserted-2' }]);

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [
          makeEvent({ eventId: 'evt-1', egressType: 'removable' }),
          makeEvent({ eventId: 'evt-2', egressType: 'network_share' }),
        ]
      })
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({
      success: true,
      count: 2,
      deduplicatedCount: 0,
    });
    expect(publishEvent).toHaveBeenCalledTimes(2);
  });

  it('reports deduplicated count when onConflictDoNothing skips duplicates', async () => {
    mockDeviceLookup({ id: 'device-1', orgId: 'org-1', hostname: 'host-1' });
    mockInsert([{ id: 'inserted-1' }]);

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [
          makeEvent({ eventId: 'evt-1', egressType: 'removable', occurredAt: '2026-02-26T12:00:00.000Z' }),
          makeEvent({ eventId: 'evt-1', egressType: 'removable', occurredAt: '2026-02-26T12:00:01.000Z' }),
        ]
      })
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.count).toBe(1);
    expect(body.deduplicatedCount).toBe(1);
  });

  it('batches inserts in chunks of 200', async () => {
    mockDeviceLookup({ id: 'device-1', orgId: 'org-1', hostname: 'host-1' });
    mockInsertAllSucceed();

    const events = Array.from({ length: 250 }, (_, i) => makeEvent({ eventId: `evt-${i}`, egressType: 'app_upload' }));

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events })
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.count).toBe(250);
    expect(body.deduplicatedCount).toBe(0);
    // 250 events at a 200-row chunk size -> two insert() calls (200 + 50)
    expect(db.insert).toHaveBeenCalledTimes(2);
  });

  it('reports publishFailures when publishEvent rejects', async () => {
    mockDeviceLookup({ id: 'device-1', orgId: 'org-1', hostname: 'host-1' });
    mockInsert([{ id: 'inserted-1' }, { id: 'inserted-2' }]);

    vi.mocked(publishEvent).mockRejectedValue(new Error('Redis connection lost'));

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [
          makeEvent({ eventId: 'evt-1', egressType: 'app_upload' }),
          makeEvent({ eventId: 'evt-2', egressType: 'app_upload' }),
        ]
      })
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.publishFailures).toBe(2);
    expect(publishEvent).toHaveBeenCalledTimes(2);
  });

  it('writes an audit event with correct arguments', async () => {
    mockDeviceLookup({ id: 'device-1', orgId: 'org-1', hostname: 'host-1' });
    mockInsert([{ id: 'inserted-1' }]);

    const res = await app.request('/agents/agent-1/file-egress/events', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: [
          makeEvent({ eventId: 'evt-1', egressType: 'removable' }),
        ]
      })
    });

    expect(res.status).toBe(200);
    expect(writeAuditEvent).toHaveBeenCalledTimes(1);
    const [, auditPayload] = vi.mocked(writeAuditEvent).mock.calls[0]!;
    expect(auditPayload).toMatchObject({
      orgId: 'org-1',
      actorType: 'agent',
      actorId: 'agent-1',
      action: 'agent.file_egress_events.submit',
      resourceType: 'device',
      resourceId: 'device-1',
      resourceName: 'host-1',
      details: {
        submittedCount: 1,
        insertedCount: 1,
        deduplicatedCount: 0,
        publishFailures: 0,
      },
    });
  });
});

describe('file-egress-event ingest — requireAgentRole gate (F8)', () => {
  it('rejects a watchdog-role token with 403', async () => {
    const app = new Hono();
    app.use('*', async (c: any, next: any) => {
      c.set('agent', { deviceId: 'dev-1', agentId: 'agent-1', orgId: 'org-1', siteId: 'site-1', role: 'watchdog' });
      await next();
    });
    app.route('/agents', fileEgressRoutes);
    const res = await app.request('/agents/dev-1/file-egress/events', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    expect(res.status).toBe(403);
  });
});
