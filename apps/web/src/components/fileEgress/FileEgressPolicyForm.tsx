import { useState } from "react";
import { useTranslation } from "react-i18next";
import { X, Plus, Trash2 } from "lucide-react";
import { fetchWithAuth } from "../../stores/auth";
import { runAction, ActionError } from "../../lib/runAction";
import { useDefaultOwnerScope } from "../../hooks/useDefaultOwnerScope";
import type { FileEgressPolicy } from "./types";

interface Props {
  policy: FileEgressPolicy | null;
  onClose: (changed: boolean) => void;
}

export default function FileEgressPolicyForm({ policy, onClose }: Props) {
  const { t } = useTranslation("file-egress");
  const isEdit = !!policy;
  const { isPartnerScope, defaultOwnerScope } = useDefaultOwnerScope();

  const [name, setName] = useState(policy?.name ?? "");
  const [enabled, setEnabled] = useState(policy?.enabled ?? false);
  const [watchRemovable, setWatchRemovable] = useState(policy?.watchRemovable ?? true);
  const [watchNetworkShares, setWatchNetworkShares] = useState(policy?.watchNetworkShares ?? true);
  const [watchUploads, setWatchUploads] = useState(policy?.watchUploads ?? true);
  const [watchlist, setWatchlist] = useState<string[]>(policy?.uploadProcessWatchlist ?? []);
  const [globs, setGlobs] = useState<string[]>(policy?.ignoreGlobs ?? []);
  const [minSize, setMinSize] = useState<number>(policy?.minFileSizeBytes ?? 0);
  const [ownerScope, setOwnerScope] = useState<"organization" | "partner">(defaultOwnerScope);

  const [watchlistDraft, setWatchlistDraft] = useState("");
  const [globDraft, setGlobDraft] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const addTo = (
    list: string[],
    setList: (v: string[]) => void,
    draft: string,
    setDraft: (v: string) => void,
  ) => {
    const v = draft.trim();
    if (v && !list.includes(v)) setList([...list, v]);
    setDraft("");
  };

  const save = async () => {
    if (!name.trim()) {
      setNameError(t("policyForm.errors.nameRequired"));
      return;
    }
    setNameError(null);
    setSaving(true);
    const body: Record<string, unknown> = {
      name: name.trim(),
      enabled,
      watchRemovable,
      watchNetworkShares,
      watchUploads,
      uploadProcessWatchlist: watchlist.length > 0 ? watchlist : null,
      ignoreGlobs: globs,
      minFileSizeBytes: minSize,
    };
    if (isEdit) {
      body.id = policy!.id;
    } else if (isPartnerScope) {
      body.ownerScope = ownerScope; // create-only; updates never move ownership axis
    }
    try {
      await runAction({
        request: () =>
          fetchWithAuth("/file-egress/policies", { method: "POST", body: JSON.stringify(body) }),
        errorFallback: t("policyForm.errors.save"),
        successMessage: t("policyForm.saved"),
      });
      onClose(true);
    } catch (err) {
      if (err instanceof ActionError && err.status === 401) return; // auth redirect handles it
      // non-401 ActionError already toasted by runAction
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!policy) return;
    if (!window.confirm(t("policyForm.deleteConfirm"))) return;
    setSaving(true);
    try {
      await runAction({
        request: () => fetchWithAuth(`/file-egress/policies/${policy.id}`, { method: "DELETE" }),
        errorFallback: t("policyForm.errors.delete"),
        successMessage: t("policyForm.deleted"),
      });
      onClose(true);
    } catch (err) {
      if (err instanceof ActionError && err.status === 401) return;
    } finally {
      setSaving(false);
    }
  };

  const toggle = (label: string, hint: string | null, value: boolean, set: (v: boolean) => void, tid: string) => (
    <label className="flex cursor-pointer items-start gap-3 py-2" data-testid={tid}>
      <input
        type="checkbox"
        checked={value}
        onChange={(e) => set(e.target.checked)}
        className="mt-1 h-4 w-4 rounded border-border"
      />
      <span>
        <span className="text-sm font-medium text-foreground">{label}</span>
        {hint && <span className="block text-xs text-muted-foreground">{hint}</span>}
      </span>
    </label>
  );

  const arrayEditor = (
    label: string,
    hint: string,
    placeholder: string,
    list: string[],
    setList: (v: string[]) => void,
    draft: string,
    setDraft: (v: string) => void,
    tid: string,
  ) => (
    <div data-testid={tid}>
      <label className="text-sm font-medium text-foreground">{label}</label>
      <p className="mb-1 text-xs text-muted-foreground">{hint}</p>
      <div className="flex gap-2">
        <input
          type="text"
          value={draft}
          placeholder={placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addTo(list, setList, draft, setDraft);
            }
          }}
          className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        />
        <button
          type="button"
          onClick={() => addTo(list, setList, draft, setDraft)}
          className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-sm hover:bg-muted"
        >
          <Plus className="h-4 w-4" />
          {t("policyForm.add")}
        </button>
      </div>
      {list.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-2">
          {list.map((v) => (
            <li key={v} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs">
              {v}
              <button
                type="button"
                aria-label={t("policyForm.remove")}
                onClick={() => setList(list.filter((x) => x !== v))}
                className="text-muted-foreground hover:text-destructive"
              >
                <X className="h-3 w-3" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
      <div className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-lg border border-border bg-background p-5 shadow-xl" data-testid="file-egress-policy-form">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-foreground">
            {isEdit ? t("policyForm.editTitle") : t("policyForm.newTitle")}
          </h2>
          <button type="button" onClick={() => onClose(false)} aria-label={t("policyForm.cancel")}>
            <X className="h-5 w-5 text-muted-foreground" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium text-foreground" htmlFor="fe-name">{t("policyForm.name")}</label>
            <input
              id="fe-name"
              type="text"
              value={name}
              maxLength={200}
              onChange={(e) => setName(e.target.value)}
              data-testid="file-egress-policy-name"
              className="mt-1 w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm"
            />
            {nameError && <p className="mt-1 text-xs text-destructive">{nameError}</p>}
          </div>

          {toggle(t("policyForm.enabled"), t("policyForm.enabledHint"), enabled, setEnabled, "file-egress-policy-enabled")}

          <fieldset className="rounded-md border border-border p-3">
            <legend className="px-1 text-sm font-medium text-foreground">{t("policyForm.surfacesLegend")}</legend>
            {toggle(t("policyForm.watchRemovable"), null, watchRemovable, setWatchRemovable, "file-egress-watch-removable")}
            {toggle(t("policyForm.watchNetworkShares"), null, watchNetworkShares, setWatchNetworkShares, "file-egress-watch-network")}
            {toggle(t("policyForm.watchUploads"), t("policyForm.watchUploadsHint"), watchUploads, setWatchUploads, "file-egress-watch-uploads")}
          </fieldset>

          {watchUploads &&
            arrayEditor(
              t("policyForm.uploadWatchlist"),
              t("policyForm.uploadWatchlistHint"),
              t("policyForm.uploadWatchlistPlaceholder"),
              watchlist,
              setWatchlist,
              watchlistDraft,
              setWatchlistDraft,
              "file-egress-watchlist",
            )}

          {arrayEditor(
            t("policyForm.ignoreGlobs"),
            t("policyForm.ignoreGlobsHint"),
            t("policyForm.ignoreGlobsPlaceholder"),
            globs,
            setGlobs,
            globDraft,
            setGlobDraft,
            "file-egress-globs",
          )}

          <div>
            <label className="text-sm font-medium text-foreground" htmlFor="fe-minsize">{t("policyForm.minFileSize")}</label>
            <p className="mb-1 text-xs text-muted-foreground">{t("policyForm.minFileSizeHint")}</p>
            <input
              id="fe-minsize"
              type="number"
              min={0}
              value={minSize}
              onChange={(e) => setMinSize(Math.max(0, Number(e.target.value) || 0))}
              className="w-40 rounded-md border border-border bg-background px-3 py-1.5 text-sm"
            />
          </div>

          {!isEdit && isPartnerScope && (
            <fieldset className="rounded-md border border-border p-3" data-testid="file-egress-policy-owner">
              <legend className="px-1 text-sm font-medium text-foreground">{t("policyForm.scope")}</legend>
              <label className="flex cursor-pointer items-center gap-2 py-1">
                <input
                  type="radio"
                  checked={ownerScope === "partner"}
                  onChange={() => setOwnerScope("partner")}
                  data-testid="file-egress-policy-owner-partner"
                />
                <span className="text-sm">
                  {t("policyForm.allOrganizations")}{" "}
                  <span className="text-xs text-muted-foreground">({t("policyForm.partnerWide")})</span>
                </span>
              </label>
              <label className="flex cursor-pointer items-center gap-2 py-1">
                <input
                  type="radio"
                  checked={ownerScope === "organization"}
                  onChange={() => setOwnerScope("organization")}
                  data-testid="file-egress-policy-owner-org"
                />
                <span className="text-sm">{t("policyForm.thisOrganization")}</span>
              </label>
            </fieldset>
          )}
        </div>

        <div className="mt-6 flex items-center justify-between">
          {isEdit ? (
            <button
              type="button"
              onClick={remove}
              disabled={saving}
              data-testid="file-egress-policy-delete"
              className="inline-flex items-center gap-1 text-sm text-destructive hover:underline disabled:opacity-50"
            >
              <Trash2 className="h-4 w-4" />
              {t("policyForm.delete")}
            </button>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => onClose(false)}
              className="rounded-md border border-border px-3 py-2 text-sm hover:bg-muted"
            >
              {t("policyForm.cancel")}
            </button>
            <button
              type="button"
              onClick={save}
              disabled={saving}
              data-testid="file-egress-policy-save"
              className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              {t("policyForm.save")}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
