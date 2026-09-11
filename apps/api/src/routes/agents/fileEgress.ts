import { Hono } from 'hono';
import { zValidator } from '../../lib/validation';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '../../db';
import {
  devices,
  fileEgressEvents,
  fileEgressTypeEnum
} from '../../db/schema';
import { writeAuditEvent } from '../../services/auditEvents';
import { publishEvent } from '../../services/eventBus';
import { requireAgentRole } from '../../middleware/requireAgentRole';

const submitFileEgressEventsSchema = z.object({
  events: z.array(z.object({
    eventId: z.string().min(1).max(255).optional(),
    egressType: z.enum(fileEgressTypeEnum.enumValues),
    // Content-revealing detail (fileName, filePath, destVolume/destHost/
    // destDomain, processName/processPath, sizeBytes, confidence). Stored
    // as-is in the details jsonb column (tenant-export excludedOpen).
    details: z.record(z.string(), z.unknown()).optional(),
    occurredAt: z.string().datetime({ offset: true }),
  })).min(1).max(1000)
});

export const fileEgressRoutes = new Hono();
// File-egress ingest is the main agent's job; reject watchdog-role tokens so a
// weaker credential can't falsify operator-facing DLP posture (mirrors the F8
// hardening on peripheral-event ingest).
fileEgressRoutes.use('*', requireAgentRole);

fileEgressRoutes.put('/:id/file-egress/events', zValidator('json', submitFileEgressEventsSchema), async (c) => {
  const agentId = c.req.param('id');
  const data = c.req.valid('json');
  const agent = c.get('agent') as { orgId?: string; agentId?: string } | undefined;

  const [device] = await db
    .select({
      id: devices.id,
      orgId: devices.orgId,
      hostname: devices.hostname
    })
    .from(devices)
    .where(eq(devices.agentId, agentId))
    .limit(1);

  if (!device) {
    return c.json({ error: 'Device not found' }, 404);
  }

  if (agent?.orgId && agent.orgId !== device.orgId) {
    return c.json({ error: 'Organization mismatch' }, 403);
  }

  const rows = data.events.map((event) => ({
    orgId: device.orgId,
    deviceId: device.id,
    sourceEventId: event.eventId ?? null,
    egressType: event.egressType,
    details: event.details ?? null,
    occurredAt: new Date(event.occurredAt),
  }));

  let inserted = 0;
  let deduplicated = 0;
  for (let i = 0; i < rows.length; i += 200) {
    const batch = rows.slice(i, i + 200);
    const insertedRows = await db
      .insert(fileEgressEvents)
      .values(batch)
      .onConflictDoNothing()
      .returning({ id: fileEgressEvents.id });
    inserted += insertedRows.length;
    deduplicated += batch.length - insertedRows.length;
  }

  // Publish every detected egress so alert routing can act on it. app_upload
  // (a file read then sent to the network) is the higher-signal case.
  let publishFailures = 0;
  const results = await Promise.allSettled(
    rows.map(async (event) => {
      await publishEvent(
        'file_egress.detected',
        device.orgId,
        {
          deviceId: device.id,
          egressType: event.egressType,
          occurredAt: event.occurredAt.toISOString(),
          details: event.details
        },
        'agent-file-egress-events',
        { priority: event.egressType === 'app_upload' ? 'high' : 'normal' }
      );
    })
  );
  for (const result of results) {
    if (result.status === 'rejected') {
      publishFailures++;
      console.error(
        `[fileEgress] Failed to publish file_egress.detected event for device ${device.id}:`,
        result.reason
      );
    }
  }

  try {
    writeAuditEvent(c, {
      orgId: agent?.orgId ?? device.orgId,
      actorType: 'agent',
      actorId: agent?.agentId ?? agentId,
      action: 'agent.file_egress_events.submit',
      resourceType: 'device',
      resourceId: device.id,
      resourceName: device.hostname,
      details: {
        submittedCount: data.events.length,
        insertedCount: inserted,
        deduplicatedCount: deduplicated,
        publishFailures
      },
    });
  } catch (error) {
    console.error(`[fileEgress] Failed to write audit event for device ${device.id}:`, error);
  }

  return c.json({
    success: true,
    count: inserted,
    deduplicatedCount: deduplicated,
    ...(publishFailures > 0 ? { publishFailures } : {})
  });
});
