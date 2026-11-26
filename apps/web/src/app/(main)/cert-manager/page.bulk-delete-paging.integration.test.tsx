// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { server } from "@/test/msw/server";
import { resetUrl } from "@/test/url-state";

jest.mock(
  "next/navigation",
  () => jest.requireActual("@/test/url-state").navigation,
);

jest.mock("@/components/ui/select", () =>
  jest.requireActual("@/test/select-mock"),
);

// Pages are released by the test, not by the real gap between requests.
jest.mock("@/lib/progressive-pagination", () => ({
  PROGRESSIVE_PAGE_REQUEST_GAP_MS: 0,
  waitForProgressivePageWindow: () => Promise.resolve(),
}));

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
const LOADING_MESSAGE = "Loading all certificates…";

type CertificateRow = ReturnType<typeof certificate>;

const certificate = (id: string, status: string) => ({
  certificateXref: `xref-${id}`,
  userDomainCertId: id,
  domain: `${id}.example.com`,
  status,
  caProvider: "LETS_ENCRYPT",
});

/**
 * Serves `pages` of the inventory. A page listed in `held` waits until the
 * test calls `release(page)`, so each page lands exactly when the test says.
 */
function serveInventory(pages: CertificateRow[][], held: number[] = []) {
  const releases = new Map<number, () => void>();
  const gates = new Map(
    held.map((page) => [
      page,
      new Promise<void>((resolve) => releases.set(page, resolve)),
    ]),
  );
  const inventory = { pages };
  server.use(
    http.get(`${API_BASE_URL}/api/v1/certs`, async ({ request }) => {
      const page = Number(new URL(request.url).searchParams.get("page") ?? 0);
      await gates.get(page);
      const totalItems = inventory.pages.flat().length;
      return HttpResponse.json({
        items: inventory.pages[page] ?? [],
        page,
        size: 100,
        totalItems,
        totalPages: inventory.pages.length,
      });
    }),
  );
  return {
    inventory,
    release: (page: number) => releases.get(page)?.(),
    hold: (page: number) =>
      gates.set(
        page,
        new Promise<void>((resolve) => releases.set(page, resolve)),
      ),
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>,
  );
}

const checkbox = (domainId: string) =>
  screen.getByRole("checkbox", { name: `Select ${domainId}.example.com` });

async function expectInventoryComplete() {
  await waitFor(() =>
    expect(screen.queryByText(LOADING_MESSAGE)).not.toBeInTheDocument(),
  );
}

describe("certificate bulk delete while the list loads page by page", () => {
  beforeEach(() => {
    resetUrl("", "/cert-manager");
  });

  afterEach(() => {
    server.resetHandlers();
  });

  it("keeps a selection through every page, including the final one", async () => {
    const user = userEvent.setup();
    const { release } = serveInventory(
      [
        [certificate("ok", "ACTIVE"), certificate("f1", "FAILED")],
        [certificate("f2", "FAILED")],
        [certificate("f3", "FAILED")],
      ],
      [1, 2],
    );
    renderPage();

    const shortcut = await screen.findByRole("button", {
      name: "Select all failed",
    });
    expect(shortcut).toBeDisabled();
    expect(screen.getByText(LOADING_MESSAGE)).toBeInTheDocument();

    await user.click(checkbox("f1"));
    expect(
      screen.getByRole("button", { name: "Delete selected (1)" }),
    ).toBeDisabled();

    release(1);
    await screen.findByText("f2.example.com");
    expect(checkbox("f1")).toBeChecked();

    release(2);
    await screen.findByText("f3.example.com");
    await expectInventoryComplete();
    expect(checkbox("f1")).toBeChecked();
    expect(
      screen.getByRole("button", { name: "Delete selected (1)" }),
    ).toBeEnabled();
  });

  it("enables 'Select all failed' only once complete, then picks failures from every page", async () => {
    const user = userEvent.setup();
    const { release } = serveInventory(
      [
        [certificate("f1", "FAILED")],
        [certificate("ok", "ACTIVE")],
        [certificate("f2", "FAILED"), certificate("f3", "FAILED")],
      ],
      [1, 2],
    );
    renderPage();

    const shortcut = await screen.findByRole("button", {
      name: "Select all failed",
    });
    expect(shortcut).toBeDisabled();
    release(1);
    await screen.findByText("ok.example.com");
    expect(shortcut).toBeDisabled();

    release(2);
    await expectInventoryComplete();
    await user.click(screen.getByRole("button", { name: "Select all failed" }));

    expect(
      screen.getByRole("button", { name: "Delete selected (3)" }),
    ).toBeEnabled();
    for (const id of ["f1", "f2", "f3"]) {
      expect(checkbox(id)).toBeChecked();
    }
  });

  it("ends a bulk delete with nothing selected, even when the refresh reloads pages", async () => {
    const user = userEvent.setup();
    server.use(
      http.delete(
        `${API_BASE_URL}/api/v1/user-domain-certificates/:id`,
        () => new HttpResponse(null, { status: 204 }),
      ),
    );
    const { inventory, release, hold } = serveInventory([
      [certificate("f1", "FAILED"), certificate("f2", "FAILED")],
      [certificate("ok", "ACTIVE")],
    ]);
    renderPage();
    await screen.findByText("ok.example.com");
    await expectInventoryComplete();

    // The backend still lists the deleted domains, and the refresh finds a
    // new page, so the list goes back to loading after the run.
    inventory.pages = [...inventory.pages, [certificate("new", "FAILED")]];
    hold(2);

    await user.click(screen.getByRole("button", { name: "Select all failed" }));
    await user.click(
      screen.getByRole("button", { name: "Delete selected (2)" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await user.click(
      within(dialog).getByRole("button", { name: "Delete domains" }),
    );

    expect(await screen.findByText(LOADING_MESSAGE)).toBeInTheDocument();
    expect(checkbox("f1")).not.toBeChecked();
    expect(checkbox("f2")).not.toBeChecked();

    release(2);
    await screen.findByText("new.example.com");
    await expectInventoryComplete();
    for (const id of ["f1", "f2", "new"]) {
      expect(checkbox(id)).not.toBeChecked();
    }
    expect(
      screen.queryByRole("button", { name: /Delete selected/ }),
    ).not.toBeInTheDocument();
  });
});
