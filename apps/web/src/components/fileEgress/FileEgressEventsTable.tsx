import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Usb, Network, Upload } from "lucide-react";
import { fetchWithAuth } from "../../stores/auth";
import { formatDateTime } from "../../lib/dateTimeFormat";
import type { FileEgressEvent, FileEgressType } from "./types";

interface Props {
  // When set, scopes to one device and hides the device column/filter.
  deviceId?: string;
  timezone?: string;
}

const LIMIT = 50;

const TYPE_ICON: Record<FileEgressType, ReactNode> = {
  removable: <Usb className="h-4 w-4" />,
  network_share: <Network className="h-4 w-4" />,
  app_upload: <Upload className="h-4 w-4" />,
};

export default function FileEgressEventsTable({ deviceId, timezone }: Props) {
  const { t } = useTranslation("file-egress");
  const [events, setEvents] = useState<FileEgressEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [typeFilter, setTypeFilter] = useState<"" | FileEgressType>("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const none = t("eventsTable.none");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (deviceId) params.set("deviceId", deviceId);
      if (typeFilter) params.set("egressType", typeFilter);
      if (from) params.set("start", new Date(from).toISOString());
      if (to) params.set("end", new Date(to + "T23:59:59").toISOString());
      params.set("limit", String(LIMIT));
      params.set("offset", String(offset));
      const response = await fetchWithAuth(`/file-egress/events?${params.toString()}`);
      if (!response.ok) throw new Error(t("eventsTable.loadError"));
      const json = await response.json();
      const data: FileEgressEvent[] = Array.isArray(json.data) ? json.data : Array.isArray(json) ? json : [];
      setEvents(data);
      setTotal(json.pagination?.total ?? json.total ?? data.length);
    } catch {
      setError(t("eventsTable.loadError"));
    } finally {
      setLoading(false);
    }
  }, [deviceId, typeFilter, from, to, offset, t]);

  useEffect(() => {
    void load();
  }, [load]);

  // Reset to first page when a filter changes.
  useEffect(() => {
    setOffset(0);
  }, [typeFilter, from, to]);

  const destinationOf = (e: FileEgressEvent): string => {
    const d = e.details;
    if (!d) return none;
    if (e.egressType === "app_upload") return d.destDomain ?? d.destHost ?? d.destIp ?? none;
    return d.destVolume ?? none;
  };

  const hasNext = offset + LIMIT < total;
  const shownFrom = total === 0 ? 0 : offset + 1;
  const shownTo = Math.min(offset + events.length, total);

  return (
    <div data-testid="file-egress-events">
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="block text-xs text-muted-foreground">{t("eventsTable.filters.type")}</span>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as "" | FileEgressType)}
            data-testid="file-egress-events-type-filter"
            className="mt-1 rounded-md border border-border bg-background px-2 py-1.5 text-sm"
          >
            <option value="">{t("eventsTable.filters.allTypes")}</option>
            <option value="removable">{t("eventsTable.types.removable")}</option>
            <option value="network_share">{t("eventsTable.types.network_share")}</option>
            <option value="app_upload">{t("eventsTable.types.app_upload")}</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="block text-xs text-muted-foreground">{t("eventsTable.filters.from")}</span>
          <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} className="mt-1 rounded-md border border-border bg-background px-2 py-1.5 text-sm" />
        </label>
        <label className="text-sm">
          <span className="block text-xs text-muted-foreground">{t("eventsTable.filters.to")}</span>
          <input type="date" value={to} onChange={(e) => setTo(e.target.value)} className="mt-1 rounded-md border border-border bg-background px-2 py-1.5 text-sm" />
        </label>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
      )}

      {loading ? (
        <div className="py-10 text-center text-sm text-muted-foreground">…</div>
      ) : events.length === 0 ? (
        <div className="rounded-md border border-dashed border-border py-10 text-center text-sm text-muted-foreground">
          {t("eventsTable.empty")}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-4 py-2">{t("eventsTable.columns.time")}</th>
                {!deviceId && <th className="px-4 py-2">{t("eventsTable.columns.device")}</th>}
                <th className="px-4 py-2">{t("eventsTable.columns.type")}</th>
                <th className="px-4 py-2">{t("eventsTable.columns.file")}</th>
                <th className="px-4 py-2">{t("eventsTable.columns.destination")}</th>
                <th className="px-4 py-2">{t("eventsTable.columns.process")}</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-t border-border" data-testid={`file-egress-event-${e.id}`}>
                  <td className="whitespace-nowrap px-4 py-3 text-muted-foreground">
                    {formatDateTime(e.occurredAt, timezone ? { timeZone: timezone } : {})}
                  </td>
                  {!deviceId && <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{e.deviceId.slice(0, 8)}</td>}
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1.5 text-foreground">
                      {TYPE_ICON[e.egressType]}
                      {t(`eventsTable.types.${e.egressType}`)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-foreground" title={e.details?.filePath ?? undefined}>
                    {e.details?.fileName ?? e.details?.filePath ?? none}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{destinationOf(e)}</td>
                  <td className="px-4 py-3 text-muted-foreground">{e.details?.processName ?? e.details?.processPath ?? none}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-3 flex items-center justify-between text-sm text-muted-foreground">
        <span>{t("eventsTable.showing", { from: shownFrom, to: shownTo, total })}</span>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - LIMIT))}
            className="rounded-md border border-border px-2 py-1 disabled:opacity-40"
          >
            {t("eventsTable.prev")}
          </button>
          <button
            type="button"
            disabled={!hasNext}
            onClick={() => setOffset(offset + LIMIT)}
            className="rounded-md border border-border px-2 py-1 disabled:opacity-40"
          >
            {t("eventsTable.next")}
          </button>
        </div>
      </div>
    </div>
  );
}
