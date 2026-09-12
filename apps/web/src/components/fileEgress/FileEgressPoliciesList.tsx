import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Plus, Layers, Usb, Network, Upload } from "lucide-react";
import { fetchWithAuth } from "../../stores/auth";
import FileEgressPolicyForm from "./FileEgressPolicyForm";
import type { FileEgressPolicy } from "./types";

export default function FileEgressPoliciesList() {
  const { t } = useTranslation("file-egress");
  const [policies, setPolicies] = useState<FileEgressPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<FileEgressPolicy | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchWithAuth("/file-egress/policies");
      if (!response.ok) throw new Error(t("policiesList.loadError"));
      const json = await response.json();
      setPolicies(Array.isArray(json.data) ? json.data : Array.isArray(json) ? json : []);
    } catch {
      setError(t("policiesList.loadError"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
  }, [load]);

  const openNew = () => {
    setEditing(null);
    setFormOpen(true);
  };
  const openEdit = (p: FileEgressPolicy) => {
    setEditing(p);
    setFormOpen(true);
  };
  const onFormClose = (changed: boolean) => {
    setFormOpen(false);
    setEditing(null);
    if (changed) void load();
  };

  return (
    <div data-testid="file-egress-policies">
      <div className="mb-4 flex items-center justify-between">
        <div />
        <button
          type="button"
          onClick={openNew}
          data-testid="file-egress-new-policy"
          className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          <Plus className="h-4 w-4" />
          {t("policiesList.new")}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <div className="py-10 text-center text-sm text-muted-foreground">…</div>
      ) : policies.length === 0 ? (
        <div className="rounded-md border border-dashed border-border py-10 text-center text-sm text-muted-foreground">
          {t("policiesList.empty")}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-4 py-2">{t("policiesList.columns.name")}</th>
                <th className="px-4 py-2">{t("policiesList.columns.scope")}</th>
                <th className="px-4 py-2">{t("policiesList.columns.surfaces")}</th>
                <th className="px-4 py-2">{t("policiesList.columns.status")}</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => openEdit(p)}
                  data-testid={`file-egress-policy-row-${p.id}`}
                  className="cursor-pointer border-t border-border hover:bg-muted/30"
                >
                  <td className="px-4 py-3 font-medium text-foreground">{p.name}</td>
                  <td className="px-4 py-3">
                    {p.orgId === null ? (
                      <span
                        data-testid="file-egress-policy-partner-wide-badge"
                        title={t("policiesList.partnerWideTitle")}
                        className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary"
                      >
                        <Layers className="h-3 w-3" />
                        {t("policiesList.allOrgs")}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 text-muted-foreground">
                      {p.watchRemovable && (
                        <span className="inline-flex items-center gap-1" title={t("policiesList.surfaces.removable")}>
                          <Usb className="h-4 w-4" />
                        </span>
                      )}
                      {p.watchNetworkShares && (
                        <span className="inline-flex items-center gap-1" title={t("policiesList.surfaces.network")}>
                          <Network className="h-4 w-4" />
                        </span>
                      )}
                      {p.watchUploads && (
                        <span className="inline-flex items-center gap-1" title={t("policiesList.surfaces.uploads")}>
                          <Upload className="h-4 w-4" />
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex rounded-full px-2 py-0.5 text-xs ${
                        p.enabled
                          ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : "bg-muted text-muted-foreground"
                      }`}
                    >
                      {p.enabled ? t("policiesList.status.enabled") : t("policiesList.status.disabled")}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {formOpen && <FileEgressPolicyForm policy={editing} onClose={onFormClose} />}
    </div>
  );
}
