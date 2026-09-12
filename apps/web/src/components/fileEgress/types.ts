// Shape of a file_egress_policies row as returned by the API.
export interface FileEgressPolicy {
  id: string;
  orgId: string | null;
  partnerId: string | null;
  name: string;
  enabled: boolean;
  watchRemovable: boolean;
  watchNetworkShares: boolean;
  watchUploads: boolean;
  uploadProcessWatchlist: string[] | null;
  ignoreGlobs: string[];
  minFileSizeBytes: number;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export type FileEgressType = "removable" | "network_share" | "app_upload";

// Content-revealing detail carried in the event's jsonb `details` column.
export interface FileEgressEventDetails {
  fileName?: string;
  filePath?: string;
  sizeBytes?: number;
  destVolume?: string;
  destVolumeType?: string;
  processName?: string;
  processPath?: string;
  processId?: number;
  destHost?: string;
  destDomain?: string;
  destIp?: string;
  destPort?: number;
  confidence?: number;
}

export interface FileEgressEvent {
  id: string;
  orgId: string;
  deviceId: string;
  sourceEventId: string | null;
  egressType: FileEgressType;
  details: FileEgressEventDetails | null;
  occurredAt: string;
  createdAt: string;
}
