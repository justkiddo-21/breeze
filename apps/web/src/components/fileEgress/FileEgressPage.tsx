import { useState } from "react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ShieldAlert, Activity } from "lucide-react";
import "../../lib/i18n"; // ensure i18next is initialized before first render
import FileEgressPoliciesList from "./FileEgressPoliciesList";
import FileEgressEventsTable from "./FileEgressEventsTable";

type Tab = "policies" | "activity";

interface FileEgressPageProps {
  defaultTab?: Tab;
}

export default function FileEgressPage({ defaultTab = "policies" }: FileEgressPageProps) {
  const { t } = useTranslation("file-egress");
  const [activeTab, setActiveTab] = useState<Tab>(defaultTab);

  const tabs: { id: Tab; label: string; icon: ReactNode }[] = [
    { id: "policies", label: t("fileEgressPage.tabs.policies"), icon: <ShieldAlert className="h-4 w-4" /> },
    { id: "activity", label: t("fileEgressPage.tabs.activity"), icon: <Activity className="h-4 w-4" /> },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 py-6" data-testid="file-egress-page">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold text-foreground">{t("fileEgressPage.title")}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{t("fileEgressPage.subtitle")}</p>
      </header>

      <div className="mb-6 border-b border-border">
        <nav className="-mb-px flex gap-6" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              data-testid={`file-egress-tab-${tab.id}`}
              className={`flex items-center gap-2 border-b-2 px-1 pb-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
              }`}
              aria-current={activeTab === tab.id ? "page" : undefined}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === "policies" && <FileEgressPoliciesList />}
      {activeTab === "activity" && <FileEgressEventsTable />}
    </div>
  );
}
