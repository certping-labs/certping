// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { server } from "@/test/msw/server";
import { navigateTo, replaced, resetUrl } from "@/test/url-state";

let tableMounts = 0;

jest.mock(
  "next/navigation",
  () => jest.requireActual("@/test/url-state").navigation,
);

jest.mock("@/components/ui/select", () =>
  jest.requireActual("@/test/select-mock"),
);

// Counts mounts of the real table: a remount is the visible flash.
jest.mock("@/components/ui/custom-table", () => {
  const actual = jest.requireActual("@/components/ui/custom-table");
  const ReactActual = jest.requireActual("react");
  function CountingCustomTable(props: Record<string, unknown>) {
    ReactActual.useEffect(() => {
      tableMounts += 1;
    }, []);
    return ReactActual.createElement(actual.CustomTable, props);
  }
  return { ...actual, CustomTable: CountingCustomTable };
});

let mockIsMobile = false;
jest.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => mockIsMobile }));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      email: "user@example.com",
      organizationId: "org-1",
      roles: ["USER"],
      permissions: ["certificate:read", "certificate:delete"],
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

const certificate = (domain: string, status: string, id: string) => ({
  certificateXref: `xref-${id}`,
  userDomainCertId: id,
  domain,
  status,
  caProvider: "LETS_ENCRYPT",
});

function serveCertificates() {
  server.use(
    http.get(`${API_BASE_URL}/api/v1/certs`, () =>
      HttpResponse.json({
        items: [
          certificate("ok.example.com", "ACTIVE", "1"),
          certificate("broken.example.com", "FAILED", "2"),
          certificate("stale.example.com", "RENEWAL_FAILED", "3"),
        ],
        page: 0,
        size: 100,
        totalItems: 3,
        totalPages: 1,
      }),
    ),
  );
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>,
  );
}

function chip(label: string) {
  return within(
    screen.getByLabelText(`Filter by ${label}`).parentElement as HTMLElement,
  );
}

const tableRowCount = () => screen.getAllByRole("row").length - 1;

describe("certificate list filters and the URL", () => {
  beforeEach(() => {
    tableMounts = 0;
    mockIsMobile = false;
    serveCertificates();
  });

  afterEach(() => {
    server.resetHandlers();
  });

  it("settles a same-page jump to ?status=FAILED without a URL loop or a table remount", async () => {
    resetUrl("", "/cert-manager");
    renderPage();
    expect(await screen.findByText("ok.example.com")).toBeInTheDocument();
    const mountsBeforeJump = tableMounts;

    // "Show failed" is a same-page <Link>: only the search params change.
    await act(async () => navigateTo("status=FAILED"));

    expect(replaced.length).toBeLessThanOrEqual(1);
    expect(tableMounts).toBe(mountsBeforeJump);
    await waitFor(() =>
      expect(screen.queryByText("ok.example.com")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("broken.example.com")).toBeInTheDocument();
    expect(screen.queryByText("stale.example.com")).not.toBeInTheDocument();
  });

  it("writes a filter the user picks to the URL once, without remounting the table", async () => {
    const user = userEvent.setup();
    resetUrl("", "/cert-manager");
    renderPage();
    await screen.findByText("ok.example.com");
    const mounts = tableMounts;

    await user.click(chip("Status").getByRole("button", { name: "Active" }));

    await waitFor(() =>
      expect(screen.queryByText("broken.example.com")).not.toBeInTheDocument(),
    );
    expect(replaced).toEqual(["/cert-manager?status=ACTIVE"]);
    expect(tableMounts).toBe(mounts);
  });

  it("ends on the second of two quick filter changes with at most two replaces", async () => {
    const user = userEvent.setup();
    resetUrl("", "/cert-manager");
    renderPage();
    await screen.findByText("ok.example.com");

    await user.click(chip("Status").getByRole("button", { name: "Failed" }));
    await user.click(
      chip("Status").getByRole("button", { name: "Renewal failed" }),
    );

    await waitFor(() =>
      expect(screen.queryByText("broken.example.com")).not.toBeInTheDocument(),
    );
    expect(replaced.length).toBeLessThanOrEqual(2);
    expect(replaced.at(-1)).toBe("/cert-manager?status=RENEWAL_FAILED");
    expect(screen.getByText("stale.example.com")).toBeInTheDocument();
    expect(tableRowCount()).toBe(1);
  });

  it("follows back/forward to an unfiltered URL without writing to it", async () => {
    resetUrl("status=FAILED", "/cert-manager");
    renderPage();
    await screen.findByText("broken.example.com");
    expect(screen.queryByText("ok.example.com")).not.toBeInTheDocument();

    await act(async () => navigateTo(""));

    expect(await screen.findByText("ok.example.com")).toBeInTheDocument();
    expect(replaced).toEqual([]);
  });

  it("keeps ?search when a filter changes", async () => {
    const user = userEvent.setup();
    resetUrl("search=example", "/cert-manager");
    renderPage();
    await screen.findByText("ok.example.com");
    expect(
      screen.getByRole("textbox", {
        name: "Search by domain, provider or issuer",
      }),
    ).toHaveValue("example");

    await user.click(chip("Status").getByRole("button", { name: "Failed" }));

    await waitFor(() =>
      expect(replaced).toEqual(["/cert-manager?search=example&status=FAILED"]),
    );
  });

  it("counts only failed issuances in the callout, matching the rows ?status=FAILED shows", async () => {
    resetUrl("", "/cert-manager");
    renderPage();
    expect(
      await screen.findByText("1 certificate failed to issue"),
    ).toBeInTheDocument();

    await act(async () => navigateTo("status=FAILED"));

    await waitFor(() => expect(tableRowCount()).toBe(1));
    expect(screen.getByText("broken.example.com")).toBeInTheDocument();
  });

  it("filters the card view by ?status and writes its status picks to the URL", async () => {
    mockIsMobile = true;
    const user = userEvent.setup();
    resetUrl("status=FAILED", "/cert-manager");
    renderPage();

    expect(await screen.findByText("broken.example.com")).toBeInTheDocument();
    expect(screen.queryByText("ok.example.com")).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Bulk delete is available in table view on a larger screen.",
      ),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "All statuses" }));

    expect(await screen.findByText("ok.example.com")).toBeInTheDocument();
    expect(replaced).toEqual(["/cert-manager"]);
  });
});
