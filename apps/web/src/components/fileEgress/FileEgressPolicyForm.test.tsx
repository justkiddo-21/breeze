import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { fetchWithAuthMock } = vi.hoisted(() => ({
  fetchWithAuthMock: vi.fn(),
}));
const { ownerScopeMock } = vi.hoisted(() => ({
  ownerScopeMock: vi.fn(),
}));

vi.mock("../../stores/auth", () => ({ fetchWithAuth: fetchWithAuthMock }));
vi.mock("../../hooks/useDefaultOwnerScope", () => ({ useDefaultOwnerScope: ownerScopeMock }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));
// runAction executes the request thunk so we can assert the fetchWithAuth call,
// and mirrors its throw-on-non-2xx contract.
vi.mock("../../lib/runAction", () => ({
  ActionError: class ActionError extends Error {
    status: number;
    constructor(m: string, s: number) {
      super(m);
      this.status = s;
    }
  },
  runAction: vi.fn(async (opts: { request: () => Promise<Response> }) => {
    const resp = await opts.request();
    if (!(resp as Response).ok) throw new Error("fail");
    return {};
  }),
}));

import FileEgressPolicyForm from "./FileEgressPolicyForm";

describe("FileEgressPolicyForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fetchWithAuthMock.mockResolvedValue({ ok: true, json: async () => ({ data: {} }) } as never);
    ownerScopeMock.mockReturnValue({ isPartnerScope: false, defaultOwnerScope: "organization" });
  });

  it("requires a name before saving", async () => {
    render(<FileEgressPolicyForm policy={null} onClose={vi.fn()} />);
    fireEvent.click(screen.getByTestId("file-egress-policy-save"));
    await waitFor(() => expect(screen.getByText("policyForm.errors.nameRequired")).toBeInTheDocument());
    expect(fetchWithAuthMock).not.toHaveBeenCalled();
  });

  it("creates an org-owned policy (no ownerScope for org-scope users)", async () => {
    const onClose = vi.fn();
    render(<FileEgressPolicyForm policy={null} onClose={onClose} />);
    fireEvent.change(screen.getByTestId("file-egress-policy-name"), { target: { value: "Kiosk DLP" } });
    fireEvent.click(screen.getByTestId("file-egress-policy-save"));
    await waitFor(() => expect(onClose).toHaveBeenCalledWith(true));
    const [url, opts] = fetchWithAuthMock.mock.calls[0];
    expect(url).toBe("/file-egress/policies");
    const body = JSON.parse((opts as { body: string }).body);
    expect(body.name).toBe("Kiosk DLP");
    expect(body.ownerScope).toBeUndefined();
    expect(body.id).toBeUndefined();
  });

  it("shows the ownerScope selector for partner scope and sends ownerScope on create", async () => {
    ownerScopeMock.mockReturnValue({ isPartnerScope: true, defaultOwnerScope: "partner" });
    const onClose = vi.fn();
    render(<FileEgressPolicyForm policy={null} onClose={onClose} />);
    expect(screen.getByTestId("file-egress-policy-owner")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("file-egress-policy-name"), { target: { value: "Fleet-wide DLP" } });
    fireEvent.click(screen.getByTestId("file-egress-policy-save"));
    await waitFor(() => expect(onClose).toHaveBeenCalledWith(true));
    const body = JSON.parse((fetchWithAuthMock.mock.calls[0][1] as { body: string }).body);
    expect(body.ownerScope).toBe("partner");
  });

  it("edits an existing policy: sends id, never ownerScope", async () => {
    ownerScopeMock.mockReturnValue({ isPartnerScope: true, defaultOwnerScope: "partner" });
    const onClose = vi.fn();
    const policy = {
      id: "p1",
      orgId: "o1",
      partnerId: null,
      name: "Existing",
      enabled: true,
      watchRemovable: true,
      watchNetworkShares: true,
      watchUploads: true,
      uploadProcessWatchlist: null,
      ignoreGlobs: [],
      minFileSizeBytes: 0,
      isActive: true,
      createdAt: "",
      updatedAt: "",
    };
    render(<FileEgressPolicyForm policy={policy} onClose={onClose} />);
    // Edit mode hides the ownerScope selector even for partner scope.
    expect(screen.queryByTestId("file-egress-policy-owner")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("file-egress-policy-save"));
    await waitFor(() => expect(onClose).toHaveBeenCalledWith(true));
    const body = JSON.parse((fetchWithAuthMock.mock.calls[0][1] as { body: string }).body);
    expect(body.id).toBe("p1");
    expect(body.ownerScope).toBeUndefined();
  });
});
