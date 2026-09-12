import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { fetchWithAuthMock } = vi.hoisted(() => ({ fetchWithAuthMock: vi.fn() }));
vi.mock("../../stores/auth", () => ({ fetchWithAuth: fetchWithAuthMock }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));
// Stub the form so the list test doesn't pull the whole form dependency tree.
vi.mock("./FileEgressPolicyForm", () => ({ default: () => null }));

import FileEgressPoliciesList from "./FileEgressPoliciesList";

function resp(data: unknown[]) {
  return { ok: true, json: async () => ({ data }) };
}

describe("FileEgressPoliciesList", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows the empty state when there are no policies", async () => {
    fetchWithAuthMock.mockResolvedValue(resp([]) as never);
    render(<FileEgressPoliciesList />);
    await waitFor(() => expect(screen.getByText("policiesList.empty")).toBeInTheDocument());
  });

  it("renders rows and a partner-wide badge for org_id=null policies", async () => {
    fetchWithAuthMock.mockResolvedValue(
      resp([
        { id: "p1", orgId: null, partnerId: "pt1", name: "Fleet DLP", enabled: true, watchRemovable: true, watchNetworkShares: false, watchUploads: true, uploadProcessWatchlist: null, ignoreGlobs: [], minFileSizeBytes: 0, isActive: true, createdAt: "", updatedAt: "" },
        { id: "p2", orgId: "o1", partnerId: null, name: "Org DLP", enabled: false, watchRemovable: true, watchNetworkShares: true, watchUploads: false, uploadProcessWatchlist: null, ignoreGlobs: [], minFileSizeBytes: 0, isActive: true, createdAt: "", updatedAt: "" },
      ]) as never,
    );
    render(<FileEgressPoliciesList />);
    await waitFor(() => expect(screen.getByTestId("file-egress-policy-row-p1")).toBeInTheDocument());
    expect(screen.getByText("Fleet DLP")).toBeInTheDocument();
    expect(screen.getByText("Org DLP")).toBeInTheDocument();
    // Only the partner-wide (org_id null) policy shows the badge.
    expect(screen.getAllByTestId("file-egress-policy-partner-wide-badge")).toHaveLength(1);
  });

  it("shows an error state on fetch failure", async () => {
    fetchWithAuthMock.mockResolvedValue({ ok: false, json: async () => ({}) } as never);
    render(<FileEgressPoliciesList />);
    await waitFor(() => expect(screen.getByText("policiesList.loadError")).toBeInTheDocument());
  });
});
