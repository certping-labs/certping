// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import MachineIdentityDevicesPage from "@/app/(main)/machine-identity/devices/page";
import { useAuthStore } from "@/stores/auth-store";
import { server } from "@/test/msw/server";
import type { DeviceListItem } from "@/types/machine-identity-backend";

const replaceMock = jest.fn();
const pushMock = jest.fn();
let mockSearchParams = "";

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: pushMock }),
  usePathname: () => "/machine-identity/devices",
  useSearchParams: () => new URLSearchParams(mockSearchParams),
}));

/**
 * The real table is a large generic component with its own toolbar; this stand-in
 * keeps the test about the page's own logic while still exercising the toolbar
 * slot the filter bar now lives in.
 */
jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    data,
    toolbarLeading,
    emptyTableMsg,
  }: {
    data: DeviceListItem[];
    toolbarLeading?: React.ReactNode;
    emptyTableMsg?: string;
  }) => (
    <div>
      {toolbarLeading}
      <div data-testid="device-rows">
        {data.length === 0 ? <p>{emptyTableMsg}</p> : null}
        {data.map((device) => (
          <div key={device.deviceXref} data-testid="device-row">
            {device.deviceName} · {device.status}
          </div>
        ))}
      </div>
    </div>
  ),
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;

const SOURCES = [
  {
    sourceXref: "src_intune_qa",
    provider: "INTUNE",
    sourceCategory: "ENDPOINT_MANAGEMENT",
    connectionProfileRef: "intune-primary",
    displayName: "Intune QA",
    description: null,
    configurationMetadata: null,
    syncEnabled: true,
    status: "ACTIVE",
    firstAdvertisedAt: "2026-08-28T00:00:00Z",
    lastAdvertisedAt: "2026-08-28T00:00:00Z",
    health: null,
    sync: null,
    deviceCount: 7,
  },
];

const SUMMARY = {
  totalDevices: 7,
  activeDevices: 3,
  byStatus: { REGISTERED: 3, ORPHANED: 4, DECOMMISSIONED: 0 },
  byProvider: { INTUNE: 7 },
  byDeviceClass: { MANAGED_ENDPOINT: 7 },
  byOwnership: { PERSONAL: 4, COMPANY: 3 },
  byOperatingSystem: { macOS: 5, Windows: 1, UNKNOWN: 1 },
  byComplianceState: { COMPLIANT: 7 },
  bySource: [],
  encryption: { yes: 6, no: 1, unknown: 0 },
  supervision: { yes: 5, no: 2, unknown: 0 },
  sources: {
    total: 1,
    syncEnabled: 1,
    healthy: 1,
    degraded: 0,
    unhealthy: 0,
    stale: 0,
    unknown: 0,
  },
  lastSyncCompletedAt: "2026-08-28T15:21:00Z",
};

function device(name: string, status: string): DeviceListItem {
  return {
    deviceXref: `dev_${name}`,
    deviceName: name,
    serialNumber: `SN-${name}`,
    deviceClass: "MANAGED_ENDPOINT",
    operatingSystem: "macOS",
    osVersion: "26.6.2",
    model: "MacBook Air",
    ownerUpn: null,
    ownerDisplayName: null,
    complianceState: "COMPLIANT",
    status: status as DeviceListItem["status"],
    platformDisplayName: "Intune QA",
    lastSeenInSourceAt: "2026-08-28T14:22:00Z",
  };
}

const ALL_DEVICES = [
  ...Array.from({ length: 3 }, (_, i) =>
    device(`registered-${i}`, "REGISTERED"),
  ),
  ...Array.from({ length: 4 }, (_, i) => device(`orphaned-${i}`, "ORPHANED")),
];

/** Records what the page actually asked the devices endpoint for. */
let deviceRequests: URLSearchParams[] = [];

function page(content: DeviceListItem[]) {
  return {
    content,
    totalElements: content.length,
    totalPages: 1,
    size: 25,
    number: 0,
    numberOfElements: content.length,
    first: true,
    last: true,
    empty: content.length === 0,
    pageable: {
      pageNumber: 0,
      pageSize: 25,
      offset: 0,
      paged: true,
      unpaged: false,
    },
    sort: { empty: false, sorted: true, unsorted: false },
  };
}

function defaultHandlers() {
  return [
    http.get(`${API}/api/v1/iot/sources`, () => HttpResponse.json(SOURCES)),
    http.get(`${API}/api/v1/iot/summary`, () => HttpResponse.json(SUMMARY)),
    http.get(`${API}/api/v1/iot/devices`, ({ request }) => {
      const url = new URL(request.url);
      deviceRequests.push(url.searchParams);
      const status = url.searchParams.get("status");
      const source = url.searchParams.get("source");

      if (source && source !== "src_intune_qa") {
        return HttpResponse.json(
          { message: "Device source not found" },
          {
            status: 404,
          },
        );
      }
      const rows = status
        ? ALL_DEVICES.filter((row) => row.status === status)
        : ALL_DEVICES;
      return HttpResponse.json(page(rows));
    }),
  ];
}

function renderPage() {
  useAuthStore.setState({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      organizationName: "Org",
      roles: ["USER"],
      permissions: ["iot_device:view"],
      authMethod: "LOCAL",
    },
    isLoading: false,
    isSuperAdmin: false,
    expiresAt: Date.now() + 60_000,
  } as never);

  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MachineIdentityDevicesPage />
    </QueryClientProvider>,
  );
}

/** The KPI tile whose title is exactly `name` (the tiles are the only buttons carrying one). */
function tile(name: string): HTMLElement {
  const found = screen
    .getAllByRole("button")
    .find((candidate) => within(candidate).queryByText(name) !== null);
  if (!found) throw new Error(`No tile titled "${name}"`);
  return found;
}

beforeEach(() => {
  mockSearchParams = "";
  deviceRequests = [];
  replaceMock.mockReset();
  pushMock.mockReset();
  server.use(...defaultHandlers());
});

describe("devices page", () => {
  it("shows every device by default, so the tiles and the table agree", async () => {
    // The reported bug: tiles read 7 while the table silently pinned
    // status=REGISTERED and showed 3, with nothing on screen explaining the
    // missing 4.
    renderPage();

    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );

    expect(within(tile("All devices")).getByText("7")).toBeInTheDocument();
    expect(within(tile("Registered")).getByText("3")).toBeInTheDocument();
    expect(within(tile("Orphaned")).getByText("4")).toBeInTheDocument();

    expect(deviceRequests[0].get("status")).toBeNull();
  });

  it("narrows the table to exactly the tile that was clicked", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );

    await userEvent.click(tile("Orphaned"));

    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(4),
    );
    expect(
      deviceRequests.some((params) => params.get("status") === "ORPHANED"),
    ).toBe(true);
  });

  it("clicking the active tile again clears the filter", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );

    await userEvent.click(tile("Orphaned"));
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(4),
    );

    await userEvent.click(tile("Orphaned"));
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );
  });

  it("sends a source xref, not a provider constant", async () => {
    // `GET /iot/devices?source=` resolves a sourceXref and 404s the whole
    // request otherwise, which used to blank the table on every selection.
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );

    await userEvent.click(
      screen.getByRole("combobox", { name: "Filter by Source" }),
    );
    await userEvent.click(
      await screen.findByRole("option", { name: "Intune QA" }),
    );

    await waitFor(() =>
      expect(
        deviceRequests.some(
          (params) => params.get("source") === "src_intune_qa",
        ),
      ).toBe(true),
    );
    expect(
      deviceRequests.some((params) => params.get("source") === "INTUNE"),
    ).toBe(false);
  });

  it("recovers from a deep link whose source no longer exists", async () => {
    mockSearchParams = "source=src_deleted";
    renderPage();

    expect(
      await screen.findByText(/device source in this link is no longer/i),
    ).toBeInTheDocument();
    // It falls back to the full inventory instead of 404ing the table.
    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );
    expect(
      deviceRequests.every((params) => params.get("source") === null),
    ).toBe(true);
  });

  it("ignores a status the API would reject rather than sending it", async () => {
    mockSearchParams = "status=NOT_A_STATUS";
    renderPage();

    await waitFor(() =>
      expect(screen.getAllByTestId("device-row")).toHaveLength(7),
    );
    expect(
      deviceRequests.every((params) => params.get("status") === null),
    ).toBe(true);
  });

  it("names the disabled capability when the feature flag is off", async () => {
    server.use(
      http.get(`${API}/api/v1/iot/devices`, () =>
        HttpResponse.json(
          {
            status: 423,
            error: "Feature Disabled",
            feature: "IOT_DEVICE_MANAGEMENT",
            message: "disabled",
          },
          { status: 423 },
        ),
      ),
    );
    renderPage();

    // A flag switched off while the page was open lands on the shared
    // not-available surface, named from the 423 body.
    expect(
      await screen.findByRole("heading", {
        name: "Machine Identity isn't available",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/ask your CertPing administrator/),
    ).toBeInTheDocument();
  });

  it("offers a retry, not a dead end, when the inventory call fails", async () => {
    server.use(
      http.get(`${API}/api/v1/iot/devices`, () =>
        HttpResponse.json({ message: "boom" }, { status: 500 }),
      ),
    );
    renderPage();

    expect(
      await screen.findByText("Unable to load devices"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /try again/i }),
    ).toBeInTheDocument();
  });
});
