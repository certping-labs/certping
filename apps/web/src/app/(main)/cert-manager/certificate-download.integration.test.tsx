// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import CertManagerPage from "@/app/(main)/cert-manager/page";
import { saveBlob } from "@/lib/download";
import { server } from "@/test/msw/server";

let featureFlags: Record<string, boolean> = {};
let mockPermissions = ["certificate:read", "certificate:deploy"];

jest.mock("next/navigation", () => ({
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
  usePathname: () => "/cert-manager",
  useSearchParams: () => new URLSearchParams(""),
}));
jest.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => true }));
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
  useIsFeatureEnabled: (key: string) => featureFlags[key] !== false,
  useIsOrgFeatureEnabled: (key: string) => featureFlags[key] !== false,
}));
jest.mock("@/hooks/use-animated-count", () => ({
  useAnimatedCount: (target: number) => target,
}));
jest.mock("@/lib/download", () => ({ saveBlob: jest.fn() }));
jest.mock("@/components/cert-manager/certificate-management-dialog", () => ({
  CertificateManagementDialog: () => null,
}));
jest.mock("@/components/cert-manager/manual-txt-records-dialog", () => ({
  ManualTxtRecordsDialog: () => null,
}));
jest.mock("@/components/common/tooltip-card", () => ({
  ToolTipCard: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}));
jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));
// Radix menus need layout JSDOM lacks; rows render their items inline instead.
jest.mock("@/components/ui/dropdown-menu", () => {
  const Passthrough = ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  );
  return {
    DropdownMenu: Passthrough,
    DropdownMenuTrigger: Passthrough,
    DropdownMenuContent: Passthrough,
    DropdownMenuSeparator: () => <hr />,
    DropdownMenuItem: ({
      children,
      onClick,
      asChild,
    }: {
      children: React.ReactNode;
      onClick?: () => void;
      asChild?: boolean;
    }) =>
      asChild ? (
        <div>{children}</div>
      ) : (
        <button type="button" onClick={onClick}>
          {children}
        </button>
      ),
  };
});

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const LIST_URL = `${API_BASE_URL}/api/v1/certs`;
const DETAIL_URL = `${API_BASE_URL}/api/v1/certs/:certificateXref`;
const EXPORT_URL = `${API_BASE_URL}/api/v1/certs/:certificateXref/export`;
const PASSWORD = "long enough";

const listResponse = () =>
  HttpResponse.json({
    items: [
      {
        certificateXref: "cert-le",
        domain: "le.example.com",
        status: "ACTIVE",
        caProvider: "LETS_ENCRYPT",
        exportAvailable: true,
      },
      {
        certificateXref: "cert-dc",
        domain: "dc.example.com",
        status: "ACTIVE",
        caProvider: "DIGICERT",
        exportAvailable: false,
      },
      {
        certificateXref: "cert-old",
        domain: "old.example.com",
        status: "ACTIVE",
        caProvider: "LETS_ENCRYPT",
      },
    ],
    page: 0,
    size: 100,
    totalItems: 3,
    totalPages: 1,
  });

/**
 * JSDOM's Blob has no `text()`, so the export adapter cannot read an error
 * body's `code` here as a browser does. Supplies it for one test.
 */
function supplyBlobText(): () => void {
  if (typeof Blob.prototype.text === "function") {
    return () => undefined;
  }
  Object.defineProperty(Blob.prototype, "text", {
    configurable: true,
    value(this: Blob) {
      return new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsText(this);
      });
    },
  });
  return () => {
    delete (Blob.prototype as { text?: unknown }).text;
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const tree = () => (
    <QueryClientProvider client={queryClient}>
      <CertManagerPage />
    </QueryClientProvider>
  );
  const view = render(tree());
  return {
    rerenderWithDownloadFlag: (on: boolean) => {
      featureFlags = { ...featureFlags, CERTIFICATE_DOWNLOAD: on };
      view.rerender(tree());
    },
  };
}

const cardFor = (domain: string): HTMLElement => {
  const link = screen.getByRole("link", { name: domain });
  const card = link.closest(".overflow-hidden");
  if (!(card instanceof HTMLElement)) {
    throw new Error(`No card for ${domain}`);
  }
  return card;
};

async function openPfxDialog() {
  const user = userEvent.setup();
  renderPage();
  await screen.findByText("le.example.com");
  await user.click(
    within(cardFor("le.example.com")).getByRole("button", {
      name: "Download",
    }),
  );
  const dialog = await screen.findByRole("dialog", {
    name: "Download certificate",
  });
  await user.click(
    within(dialog).getByRole("radio", { name: "PFX / PKCS#12" }),
  );
  await user.type(within(dialog).getByLabelText("File password"), PASSWORD);
  await user.type(within(dialog).getByLabelText("Confirm password"), PASSWORD);
  const download = within(dialog).getByRole("button", { name: "Download" });
  await waitFor(() => expect(download).toBeEnabled());
  return { user, dialog, download };
}

describe("certificate download (UI + MSW)", () => {
  beforeEach(() => {
    featureFlags = {};
    mockPermissions = ["certificate:read", "certificate:deploy"];
    server.use(http.get(`${API_BASE_URL}/api/v1/certs`, listResponse));
  });

  const offeredFormats = async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("le.example.com");
    await user.click(
      within(cardFor("le.example.com")).getByRole("button", {
        name: "Download",
      }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: "Download certificate",
    });
    return within(dialog)
      .getAllByRole("radio")
      .map((radio) => radio.getAttribute("value"));
  };

  it("offers a viewer only the formats without a private key", async () => {
    mockPermissions = ["certificate:read"];

    expect(await offeredFormats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
      "CERTIFICATE_DER",
      "PKCS7",
    ]);
  });

  it("offers a certificate:deploy holder every format, private key included", async () => {
    expect(await offeredFormats()).toEqual([
      "FULLCHAIN_PEM",
      "CERTIFICATE_PEM",
      "CERTIFICATE_DER",
      "PKCS7",
      "PRIVATE_KEY_PEM",
      "PKCS12",
    ]);
  });

  it("drops the key formats when the backend refuses the key with EXPORT_KEY_NOT_PERMITTED", async () => {
    server.use(
      http.post(EXPORT_URL, () =>
        HttpResponse.json(
          {
            status: 403,
            code: "EXPORT_KEY_NOT_PERMITTED",
            message: "key not permitted",
          },
          { status: 403 },
        ),
      ),
    );
    const removeBlobText = supplyBlobText();
    try {
      const { user, dialog, download } = await openPfxDialog();

      await user.click(download);

      await waitFor(() =>
        expect(within(dialog).getByRole("alert")).toHaveTextContent(
          "You can download the certificate and chain, but not the private key.",
        ),
      );
      expect(
        within(dialog)
          .getAllByRole("radio")
          .map((radio) => radio.getAttribute("value")),
      ).toEqual([
        "FULLCHAIN_PEM",
        "CERTIFICATE_PEM",
        "CERTIFICATE_DER",
        "PKCS7",
      ]);
      expect(
        within(dialog).getByRole("radio", { name: /Full chain/ }),
      ).toBeChecked();
      expect(saveBlob).not.toHaveBeenCalled();
    } finally {
      removeBlobText();
    }
  });

  it("offers Download only on rows the backend can export", async () => {
    renderPage();
    await screen.findByText("le.example.com");

    const downloadIn = (domain: string) =>
      within(cardFor(domain)).queryByRole("button", { name: "Download" });
    expect(downloadIn("le.example.com")).toBeInTheDocument();
    expect(downloadIn("dc.example.com")).not.toBeInTheDocument();
    expect(downloadIn("old.example.com")).not.toBeInTheDocument();
  });

  it("offers no Download anywhere while the flag is off", async () => {
    featureFlags = { CERTIFICATE_DOWNLOAD: false };
    renderPage();
    await screen.findByText("le.example.com");

    expect(
      screen.queryByRole("button", { name: "Download" }),
    ).not.toBeInTheDocument();
  });

  it("downloads a PFX through the authenticated POST and saves the server's file", async () => {
    let requestBody: unknown;
    let requestUrl = "";
    server.use(
      http.post(EXPORT_URL, async ({ request }) => {
        requestUrl = request.url;
        requestBody = await request.json();
        return new HttpResponse(new Uint8Array([48, 130, 1]), {
          headers: {
            "Content-Type": "application/x-pkcs12",
            "Content-Disposition": 'attachment; filename="le.example.com.pfx"',
            "Cache-Control": "no-store",
          },
        });
      }),
    );
    const { user, download } = await openPfxDialog();

    await user.click(download);

    await waitFor(() =>
      expect(saveBlob).toHaveBeenCalledWith(
        expect.any(Blob),
        "le.example.com.pfx",
      ),
    );
    expect(requestUrl).toBe(`${API_BASE_URL}/api/v1/certs/cert-le/export`);
    expect(requestUrl).not.toContain(encodeURIComponent(PASSWORD));
    expect(requestBody).toEqual({
      format: "PKCS12",
      password: PASSWORD,
      legacyPkcs12: false,
    });
    expect(toast.success).toHaveBeenCalledWith(
      "Downloaded le.example.com.pfx",
      {
        id: "certificate-export",
      },
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("explains a refusal inline from the JSON error envelope and clears the password", async () => {
    server.use(
      http.post(EXPORT_URL, () =>
        HttpResponse.json(
          { status: 410, code: "CERT_MATERIAL_GONE", message: "gone" },
          { status: 410 },
        ),
      ),
    );
    const { user, dialog, download } = await openPfxDialog();

    await user.click(download);

    await waitFor(() =>
      expect(within(dialog).getByRole("alert")).toHaveTextContent(
        "CertPing no longer holds the files for this certificate.",
      ),
    );
    expect(toast.error).not.toHaveBeenCalled();
    expect(saveBlob).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(within(dialog).getByLabelText("File password")).toHaveValue(""),
    );
    expect(within(dialog).getByLabelText("Confirm password")).toHaveValue("");
  });

  it("says key downloads are paused on a 503 for a PFX, with the reference", async () => {
    server.use(
      http.post(EXPORT_URL, () =>
        HttpResponse.json(
          { status: 503, code: "EXPORT_UNAVAILABLE", message: "down" },
          { status: 503, headers: { "X-Correlation-ID": "srv-503" } },
        ),
      ),
    );
    const { user, dialog, download } = await openPfxDialog();

    await user.click(download);

    await waitFor(() =>
      expect(within(dialog).getByRole("alert")).toHaveTextContent(
        "Downloads that include the private key are temporarily unavailable. Try again shortly. (Reference: srv-503)",
      ),
    );
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("toasts a 423 rather than leaving it only in the dialog", async () => {
    server.use(
      http.post(EXPORT_URL, () =>
        HttpResponse.json(
          { status: 423, feature: "CERTIFICATE_DOWNLOAD" },
          { status: 423 },
        ),
      ),
    );
    const { user, dialog, download } = await openPfxDialog();

    await user.click(download);

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Certificate download isn't available. Ask your CertPing administrator.",
        { id: "certificate-export" },
      ),
    );
    expect(within(dialog).getByRole("alert")).toBeEmptyDOMElement();
  });

  it("does not reopen the dialog when download access returns after being lost", async () => {
    const user = userEvent.setup();
    const { rerenderWithDownloadFlag } = renderPage();
    await screen.findByText("le.example.com");
    const openDialog = async () => {
      await user.click(
        within(cardFor("le.example.com")).getByRole("button", {
          name: "Download",
        }),
      );
      await screen.findByRole("dialog", { name: "Download certificate" });
    };

    await openDialog();
    rerenderWithDownloadFlag(false);
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "Download" }),
    ).not.toBeInTheDocument();

    rerenderWithDownloadFlag(true);
    expect(
      within(cardFor("le.example.com")).getByRole("button", {
        name: "Download",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await openDialog();
    rerenderWithDownloadFlag(false);
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    rerenderWithDownloadFlag(true);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("names the file from the domain when CORS hides Content-Disposition", async () => {
    server.use(
      http.post(
        EXPORT_URL,
        () =>
          new HttpResponse(new Uint8Array([48, 130, 1]), {
            headers: { "Content-Type": "application/x-pkcs12" },
          }),
      ),
    );
    const { user, download } = await openPfxDialog();

    await user.click(download);

    await waitFor(() =>
      expect(saveBlob).toHaveBeenCalledWith(
        expect.any(Blob),
        "le.example.com.pfx",
      ),
    );
  });
});

describe("certificate download availability while polling (UI + MSW)", () => {
  const pollingList = (row: Record<string, unknown>) => () =>
    HttpResponse.json({
      items: [row],
      page: 0,
      size: 100,
      totalItems: 1,
      totalPages: 1,
    });

  beforeEach(() => {
    featureFlags = {};
  });

  it("offers Download once a polled in-flight certificate becomes exportable", async () => {
    server.use(
      http.get(
        LIST_URL,
        pollingList({
          certificateXref: "cert-new",
          domain: "new.example.com",
          status: "VALIDATING",
          caProvider: "LETS_ENCRYPT",
          exportAvailable: false,
        }),
      ),
      http.get(DETAIL_URL, () =>
        HttpResponse.json({
          certificateXref: "cert-new",
          domain: "new.example.com",
          status: "ACTIVE",
          caProvider: "LETS_ENCRYPT",
          export: {
            available: true,
            reason: null,
            formats: ["FULLCHAIN_PEM", "PKCS12"],
          },
        }),
      ),
    );
    renderPage();
    await screen.findByText("new.example.com");

    expect(
      await within(cardFor("new.example.com")).findByRole("button", {
        name: "Download",
      }),
    ).toBeInTheDocument();
  });

  it("withdraws Download when the polled detail says the files can't be exported", async () => {
    let polled = false;
    server.use(
      http.get(
        LIST_URL,
        pollingList({
          certificateXref: "cert-renew",
          domain: "renew.example.com",
          status: "RENEWING",
          caProvider: "LETS_ENCRYPT",
          exportAvailable: true,
        }),
      ),
      http.get(DETAIL_URL, () => {
        polled = true;
        return HttpResponse.json({
          certificateXref: "cert-renew",
          domain: "renew.example.com",
          status: "ACTIVE",
          caProvider: "LETS_ENCRYPT",
          export: { available: false, reason: "NO_MATERIAL", formats: [] },
        });
      }),
    );
    renderPage();
    await screen.findByText("renew.example.com");

    await waitFor(() => expect(polled).toBe(true));
    await waitFor(() =>
      expect(
        within(cardFor("renew.example.com")).queryByRole("button", {
          name: "Download",
        }),
      ).not.toBeInTheDocument(),
    );
  });
});
