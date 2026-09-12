import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

const { fetchWithAuthMock } = vi.hoisted(() => ({
  fetchWithAuthMock: vi.fn(),
}));
vi.mock("../../stores/auth", () => ({ fetchWithAuth: fetchWithAuthMock }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (k: string, opts?: Record<string, unknown>) =>
      opts ? `${k}:${JSON.stringify(opts)}` : k,
  }),
}));
vi.mock("../../lib/dateTimeFormat", () => ({ formatDateTime: (v: string) => v }));

import FileEgressEventsTable from "./FileEgressEventsTable";

function resp(data: unknown[], total: number) {
  return { ok: true, json: async () => ({ data, pagination: { total } }) };
}

describe("FileEgressEventsTable", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders events; destination reads the right detail per egress type", async () => {
    fetchWithAuthMock.mockResolvedValue(
      resp(
        [
          {
            id: "e1",
            orgId: "o1",
            deviceId: "device-aaaaaaaa",
            sourceEventId: null,
            egressType: "app_upload",
            details: { fileName: "báo-giá.pdf", processName: "Zalo.exe", destDomain: "zalo.me" },
            occurredAt: "2026-09-11T10:00:00Z",
            createdAt: "2026-09-11T10:00:00Z",
          },
          {
            id: "e2",
            orgId: "o1",
            deviceId: "device-bbbbbbbb",
            sourceEventId: null,
            egressType: "removable",
            details: { fileName: "list.csv", destVolume: "E:" },
            occurredAt: "2026-09-11T09:00:00Z",
            createdAt: "2026-09-11T09:00:00Z",
          },
        ],
        2,
      ) as never,
    );

    render(<FileEgressEventsTable />);
    await waitFor(() => expect(screen.getByTestId("file-egress-event-e1")).toBeInTheDocument());
    expect(screen.getByText("báo-giá.pdf")).toBeInTheDocument();
    expect(screen.getByText("zalo.me")).toBeInTheDocument(); // app_upload -> destDomain
    expect(screen.getByText("E:")).toBeInTheDocument(); // removable -> destVolume
    expect(screen.getByText("Zalo.exe")).toBeInTheDocument();
  });

  it("scopes to a device (no device column) and passes deviceId to the API", async () => {
    fetchWithAuthMock.mockResolvedValue(resp([], 0) as never);
    render(<FileEgressEventsTable deviceId="dev-1" />);
    await waitFor(() => expect(screen.getByText("eventsTable.empty")).toBeInTheDocument());
    const url = fetchWithAuthMock.mock.calls[0][0] as string;
    expect(url).toContain("deviceId=dev-1");
    expect(screen.queryByText("eventsTable.columns.device")).not.toBeInTheDocument();
  });

  it("sends egressType when the type filter changes", async () => {
    fetchWithAuthMock.mockResolvedValue(resp([], 0) as never);
    render(<FileEgressEventsTable />);
    await waitFor(() => expect(fetchWithAuthMock).toHaveBeenCalled());
    fireEvent.change(screen.getByTestId("file-egress-events-type-filter"), { target: { value: "app_upload" } });
    await waitFor(() => {
      const lastUrl = fetchWithAuthMock.mock.calls.at(-1)![0] as string;
      expect(lastUrl).toContain("egressType=app_upload");
    });
  });
});
