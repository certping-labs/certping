// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { server } from "@/test/msw/server";
import { resetUrl } from "@/test/url-state";

let mockPermissions: string[] = [];

jest.mock(
  "next/navigation",
  () => jest.requireActual("@/test/url-state").navigation,
);

jest.mock("@/components/ui/select", () =>
  jest.requireActual("@/test/select-mock"),
);

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn(), info: jest.fn() },
}));

jest.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => false }));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      roles: ["USER"],
      permissions: mockPermissions,
      authMethod: "LOCAL",
    },
    isLoading: false,
    isSuperAdmin: false,
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: () => true,
  useIsOrgFeatureEnabled: () => true,
}));

jest.mock("@/hooks/use-animated-count", () => ({
  useAnimatedCount: (target: number) => target,
}));

jest.mock("@/components/common/tooltip-card", () => ({
  ToolTipCard: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
}));

jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: () => null,
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const DELETE_URL = `${API_BASE_URL}/api/v1/user-domain-certificates/:id`;
const FAILED_IDS = ["f1", "f2", "f3", "f4", "f5", "f6", "f7"];
const toastSuccess = jest.mocked(toast.success);
const toastError = jest.mocked(toast.error);

const certificate = (id: string, status: string) => ({
  certificateXref: `xref-${id}`,
  userDomainCertId: id,
  domain: `${id}.example.com`,
  status,
  caProvider: "LETS_ENCRYPT",
});

function serveCertificates() {
  const items = [
    certificate("ok", "ACTIVE"),
    ...FAILED_IDS.map((id) => certificate(id, "FAILED")),
    certificate("stale", "RENEWAL_FAILED"),
  ];
  server.use(
    http.get(`${API_BASE_URL}/api/v1/certs`, () =>
      HttpResponse.json({
        items,
        page: 0,
        size: 100,
        totalItems: items.length,
        totalPages: 1,
      }),
    ),
  );
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const invalidate = jest.spyOn(queryClient, "invalidateQueries");
  render(
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>,
  );
  const listRefreshes = () =>
    invalidate.mock.calls.filter(
      ([filters]) => filters?.queryKey?.[0] === "ssl-cert-list",
    ).length;
  return { listRefreshes };
}

async function openBulkDeleteForAllFailed() {
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("button", { name: "Select all failed" }),
  );
  await user.click(screen.getByRole("button", { name: "Delete selected (7)" }));
  return { user, dialog: await screen.findByRole("alertdialog") };
}

describe("certificate bulk delete", () => {
  beforeEach(() => {
    mockPermissions = ["certificate:read", "certificate:delete"];
    resetUrl("", "/cert-manager");
    serveCertificates();
  });

  afterEach(() => {
    server.resetHandlers();
  });

  it("offers no selection without the delete permission", async () => {
    mockPermissions = ["certificate:read"];
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CertManagerPage />
      </QueryClientProvider>,
    );
    await screen.findByText("ok.example.com");
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Select all failed" }),
    ).not.toBeInTheDocument();
  });

  it("names each checkbox and lets only deletable rows be selected", async () => {
    renderPage();
    await screen.findByText("ok.example.com");

    expect(
      screen.getByRole("checkbox", { name: "Select all on this page" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select ok.example.com" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "Select stale.example.com" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "Select f1.example.com" }),
    ).toBeEnabled();
  });

  it("confirms with the exact copy and the real count", async () => {
    renderPage();
    const { dialog } = await openBulkDeleteForAllFailed();

    expect(
      within(dialog).getByRole("heading", { name: "Delete 7 domains?" }),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        "This removes each domain with all its certificates and settings. Deployed certificates aren't rolled back. This can't be undone.",
      ),
    ).toBeInTheDocument();
  });

  it("deletes past failures, counts 404 as gone, refreshes once, and retries only the failures", async () => {
    const requested: string[] = [];
    let inFlight = 0;
    let maxInFlight = 0;
    server.use(
      http.delete(DELETE_URL, async ({ params }) => {
        const id = String(params.id);
        requested.push(id);
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        // Yield once so concurrent requests overlap before any answers.
        await new Promise((resolve) => setTimeout(resolve, 0));
        inFlight -= 1;
        if (id === "f3") return new HttpResponse(null, { status: 500 });
        if (id === "f4") return new HttpResponse(null, { status: 404 });
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const { listRefreshes } = renderPage();
    const { user, dialog } = await openBulkDeleteForAllFailed();

    await user.click(
      within(dialog).getByRole("button", { name: "Delete domains" }),
    );

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(
        "Deleted 6. 1 couldn't be deleted.",
        expect.objectContaining({
          description: "Request failed with status code 500",
          action: expect.objectContaining({ label: "Retry" }),
        }),
      ),
    );
    expect([...requested].sort()).toEqual(FAILED_IDS);
    expect(maxInFlight).toBeLessThanOrEqual(5);
    expect(listRefreshes()).toBe(1);
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: /Delete selected/ }),
    ).not.toBeInTheDocument();

    requested.length = 0;
    const [, options] = toastError.mock.calls[0]!;
    const retry = options?.action as {
      onClick: (event: React.MouseEvent<HTMLButtonElement>) => void;
    };
    retry.onClick({} as React.MouseEvent<HTMLButtonElement>);

    await waitFor(() => expect(toastError).toHaveBeenCalledTimes(2));
    expect(requested).toEqual(["f3"]);
    expect(toastError).toHaveBeenLastCalledWith(
      "Deleted 0. 1 couldn't be deleted.",
      expect.anything(),
    );
    expect(listRefreshes()).toBe(2);
  });

  it("stops starting deletes when the dialog closes mid-run and still reports", async () => {
    const requested: string[] = [];
    const releases: (() => void)[] = [];
    server.use(
      http.delete(DELETE_URL, async ({ params }) => {
        requested.push(String(params.id));
        await new Promise<void>((resolve) => releases.push(resolve));
        return new HttpResponse(null, { status: 204 });
      }),
    );
    renderPage();
    const { user, dialog } = await openBulkDeleteForAllFailed();

    await user.click(
      within(dialog).getByRole("button", { name: "Delete domains" }),
    );
    await waitFor(() => expect(releases).toHaveLength(5));
    expect(within(dialog).getByRole("status")).toHaveTextContent(
      "Deleting 1 of 7…",
    );
    // A second submit is impossible while the run goes.
    expect(
      within(dialog).getByRole("button", { name: "Delete domains" }),
    ).toBeDisabled();

    await user.click(within(dialog).getByRole("button", { name: "Stop" }));
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
    releases.forEach((release) => release());

    await waitFor(() =>
      expect(toastSuccess).toHaveBeenCalledWith(
        "Deleted 5. Stopped before the other 2.",
        expect.anything(),
      ),
    );
    expect(requested).toHaveLength(5);
  });
});
