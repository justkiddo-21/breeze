import "../../lib/i18n";
import FileEgressEventsTable from "../fileEgress/FileEgressEventsTable";

interface Props {
  deviceId: string;
  timezone?: string;
}

// Per-device Egress tab: the shared events table scoped to one device.
export default function DeviceFileEgressTab({ deviceId, timezone }: Props) {
  return <FileEgressEventsTable deviceId={deviceId} timezone={timezone} />;
}
