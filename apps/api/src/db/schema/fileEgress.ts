/**
 * File-egress (DLP) schema — endpoint file-egress monitoring.
 *
 * fileEgressPolicies: controls the agent's file-egress monitor — whether it
 *   runs and which surfaces it watches (removable/USB, network shares, and the
 *   app/browser "read-a-file-then-upload" correlation). Owned by EITHER an org
 *   (orgId set, partnerId NULL) OR a partner (partnerId set, orgId NULL —
 *   "partner-wide / all orgs", epic #2135), enforced by CHECK
 *   `file_egress_policies_one_owner_chk`. DISABLED by default (`enabled = false`).
 *
 * fileEgressEvents: agent-reported telemetry, one row per detected egress.
 *   Deduplicated via sourceEventId unique partial index. Content-revealing
 *   fields (file names, paths, destinations, process paths) live in the
 *   `details` jsonb, NOT in top-level columns — filenames themselves reveal
 *   content, so they are kept out of tenant open-export (jsonb => excludedOpen).
 */
import {
  bigint,
  boolean,
  index,
  jsonb,
  pgEnum,
  pgTable,
  timestamp,
  uniqueIndex,
  uuid,
  varchar
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { devices } from './devices';
import { organizations, partners } from './orgs';
import { users } from './users';

export const fileEgressTypeEnum = pgEnum('file_egress_type', [
  'removable',
  'network_share',
  'app_upload'
]);

export type FileEgressType = typeof fileEgressTypeEnum.enumValues[number];

/** Content-revealing detail for one egress event; stored in the jsonb column. */
export interface FileEgressEventDetails {
  fileName?: string;
  filePath?: string;
  sizeBytes?: number;
  /** Destination for removable/network_share: the volume/mount and its kind. */
  destVolume?: string;
  destVolumeType?: 'removable' | 'network_share';
  /** Destination for app_upload: the process and where it sent bytes. */
  processName?: string;
  processPath?: string;
  destHost?: string;
  destDomain?: string;
  destIp?: string;
  destPort?: number;
  /** Heuristic confidence for the read+connect correlation (0-1). */
  confidence?: number;
}

// A file-egress policy is owned by EITHER an org (orgId set, partnerId NULL) OR
// a partner (partnerId set, orgId NULL — "partner-wide / all orgs"). Exactly one
// axis is set per row; CHECK `file_egress_policies_one_owner_chk` (migration
// 2026-10-15-140005) enforces it. Events stay owned by the reporting device's org.
export const fileEgressPolicies = pgTable('file_egress_policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').references(() => organizations.id),
  partnerId: uuid('partner_id').references(() => partners.id),
  name: varchar('name', { length: 200 }).notNull(),
  enabled: boolean('enabled').notNull().default(false),
  watchRemovable: boolean('watch_removable').notNull().default(true),
  watchNetworkShares: boolean('watch_network_shares').notNull().default(true),
  watchUploads: boolean('watch_uploads').notNull().default(true),
  /** NULL => agent uses its built-in default process list (browsers + chat apps). */
  uploadProcessWatchlist: jsonb('upload_process_watchlist').$type<string[]>(),
  ignoreGlobs: jsonb('ignore_globs').$type<string[]>().notNull().default([]),
  minFileSizeBytes: bigint('min_file_size_bytes', { mode: 'number' }).notNull().default(0),
  isActive: boolean('is_active').notNull().default(true),
  createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
  orgActiveIdx: index('file_egress_policies_org_active_idx').on(table.orgId, table.isActive),
  partnerIdx: index('file_egress_policies_partner_idx').on(table.partnerId),
}));

export const fileEgressEvents = pgTable('file_egress_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  orgId: uuid('org_id').notNull().references(() => organizations.id),
  deviceId: uuid('device_id').notNull().references(() => devices.id),
  sourceEventId: varchar('source_event_id', { length: 255 }),
  egressType: fileEgressTypeEnum('egress_type').notNull(),
  details: jsonb('details').$type<FileEgressEventDetails>(),
  occurredAt: timestamp('occurred_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  orgDeviceTimeIdx: index('file_egress_events_org_device_time_idx').on(table.orgId, table.deviceId, table.occurredAt),
  typeTimeIdx: index('file_egress_events_type_time_idx').on(table.egressType, table.occurredAt),
  sourceEventIdx: uniqueIndex('file_egress_events_source_event_idx')
    .on(table.orgId, table.deviceId, table.sourceEventId)
    .where(sql`source_event_id IS NOT NULL`),
}));
