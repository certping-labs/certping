// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";

import { AppSidebar } from "@/components/sidebar/app-sidebar";

const mockUseFeatureFlags = jest.fn();
const mockIsSuperAdmin = jest.fn(() => false);
let mockPathname = "/cert-manager";
let mockSidebarState: "expanded" | "collapsed" = "expanded";

jest.mock("next/navigation", () => ({
  usePathname: () => mockPathname,
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useFeatureFlags: () => mockUseFeatureFlags(),
  useIsRouteAvailable: () => {
    const { effectiveMap } = mockUseFeatureFlags();
    return (href: string) =>
      jest.requireActual("@/lib/feature-routes").isRouteFeatureOn(href, {
        status: "ready",
        effectiveMap,
        isSuperAdmin: mockIsSuperAdmin(),
      });
  },
}));

let mockUser: Record<string, unknown> = { id: "user-1" };

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: mockUser, isSuperAdmin: mockIsSuperAdmin() }),
}));

jest.mock("@/components/common/tooltip-card", () => ({
  ToolTipCard: ({ children }: { children: React.ReactNode }) => children,
}));

jest.mock("@/components/ui/sidebar", () => {
  const passthrough =
    (testId: string) =>
    ({ children }: { children?: React.ReactNode }) => (
      <div data-testid={testId}>{children}</div>
    );
  return {
    Sidebar: passthrough("sidebar"),
    SidebarContent: passthrough("sidebar-content"),
    SidebarHeader: passthrough("sidebar-header"),
    SidebarMenu: passthrough("sidebar-menu"),
    SidebarMenuButton: passthrough("sidebar-menu-button"),
    SidebarMenuItem: passthrough("sidebar-menu-item"),
    SidebarRail: passthrough("sidebar-rail"),
    SidebarTrigger: (props: React.ComponentProps<"button">) => (
      <button type="button" {...props}>
        <span className="sr-only">Toggle sidebar</span>
      </button>
    ),
    useSidebar: () => ({
      isMobile: false,
      setOpenMobile: jest.fn(),
      state: mockSidebarState,
    }),
  };
});

jest.mock("@/components/sidebar/nav-secondary", () => ({
  NavSecondary: ({
    items,
    groupLabel,
    emphasis,
  }: {
    groupLabel?: string;
    emphasis?: string;
    items: Array<{
      title: string;
      url?: string;
      highlight?: boolean;
      subMenu?: Array<{ title: string; url: string }>;
    }>;
  }) => (
    <ul aria-label={groupLabel || "Top"} data-emphasis={emphasis}>
      {items.map((item) => (
        <li key={item.title} data-highlight={item.highlight || undefined}>
          {item.url ? <a href={item.url}>{item.title}</a> : item.title}
          {item.subMenu ? (
            <ul>
              {item.subMenu.map((sub) => (
                <li key={sub.title}>
                  <a href={sub.url}>{sub.title}</a>
                </li>
              ))}
            </ul>
          ) : null}
        </li>
      ))}
    </ul>
  ),
}));

jest.mock("@/components/sidebar/nav-main", () => ({
  NavMain: ({
    items,
    groupLabel,
    emphasis,
  }: {
    emphasis?: string;
    items: Array<{
      title: string;
      url?: string;
      subMenu?: Array<{ title: string; url: string }>;
    }>;
    groupLabel: string;
  }) => (
    <ul data-testid={`nav-main-${groupLabel}`} data-emphasis={emphasis}>
      {items.map((item) => (
        <li key={item.url ?? item.title}>
          {item.title}
          {item.subMenu ? (
            <ul>
              {item.subMenu.map((sub) => (
                <li key={sub.title}>
                  <a href={sub.url}>{sub.title}</a>
                </li>
              ))}
            </ul>
          ) : null}
        </li>
      ))}
    </ul>
  ),
}));

jest.mock("@/components/common/certping-brand", () => ({
  CertPingBrand: () => null,
}));

function mockFlags(effectiveMap: Record<string, boolean>): void {
  mockUseFeatureFlags.mockReturnValue({
    effectiveMap,
    // Production semantics: only a key confirmed on is enabled.
    isEnabled: (featureKey: string) => effectiveMap[featureKey] === true,
    isReady: true,
  });
}

const ALL_ON = {
  DISCOVERY: true,
  CERTIFICATE_RENEWAL: true,
  PQC_READINESS: true,
  CERTIFICATE_DEPLOYMENT: true,
  AUDIT_LOGS: true,
  IOT_DEVICE_MANAGEMENT: true,
  IOT_CERTIFICATE_PROFILE_MANAGEMENT: true,
};

const READ = [
  "certificate:read",
  "deployments:view",
  "audit:view",
  "organization:view",
  "users:view",
  "roles:view",
];

function signIn(roles: string[], permissions: string[]) {
  mockUser = { id: "user-1", organizationId: "7", roles, permissions };
}

function linkNames(): string[] {
  return screen.getAllByRole("link").map((a) => a.textContent ?? "");
}

const PRODUCT_LINKS = [
  "Overview",
  "Certificate Discovery",
  "Certificates",
  "PQC Readiness",
  "Rotation",
  "Deployments",
  "Devices",
  "Device certificates",
  "Profiles",
];

const REMOVED = [
  "Feature flags",
  "Password keys",
  "Account",
  "Members",
  "Organizations",
  "Integrations",
  "Alerts & escalations",
  "Notifications",
  "TLS certificates",
];

describe("AppSidebar collapse control", () => {
  afterEach(() => {
    mockSidebarState = "expanded";
  });

  it("names the action for the current state and sits in the header", () => {
    mockFlags(ALL_ON);
    render(<AppSidebar />);
    const header = screen.getByTestId("sidebar-header");
    expect(
      within(header).getByRole("button", { name: "Collapse sidebar" }),
    ).toBeInTheDocument();
  });

  it("offers to expand once collapsed", () => {
    mockSidebarState = "collapsed";
    mockFlags(ALL_ON);
    render(<AppSidebar />);
    expect(
      screen.getByRole("button", { name: "Expand sidebar" }),
    ).toBeInTheDocument();
  });
});

describe("AppSidebar product navigation", () => {
  afterEach(() => {
    mockUser = { id: "user-1" };
    mockIsSuperAdmin.mockReturnValue(false);
  });

  it("shows an organization admin the whole product surface and nothing else", () => {
    mockFlags(ALL_ON);
    signIn(
      ["ORGANIZATION_ADMIN"],
      [...READ, "certificate:issue", "users:manage"],
    );

    render(<AppSidebar />);

    expect(linkNames()).toEqual(expect.arrayContaining(PRODUCT_LINKS));
    const administration = screen.getByTestId("nav-main-Administration");
    expect(administration).toHaveTextContent("Organization & Access");
    expect(administration).toHaveTextContent("Support");
    expect(screen.getByTestId("nav-main-Operations")).toHaveTextContent(
      "Audit Logs",
    );
    for (const gone of REMOVED) {
      expect(screen.queryByText(gone)).not.toBeInTheDocument();
    }
  });

  it("gives a security analyst and a viewer the same read navigation", () => {
    mockFlags(ALL_ON);
    for (const role of ["SECURITY_ANALYST", "VIEWER"]) {
      signIn([role], READ);
      const { unmount } = render(<AppSidebar />);
      expect(linkNames()).toEqual(expect.arrayContaining(PRODUCT_LINKS));
      expect(screen.getByTestId("nav-main-Administration")).toHaveTextContent(
        "Organization & Access",
      );
      for (const gone of REMOVED) {
        expect(screen.queryByText(gone)).not.toBeInTheDocument();
      }
      unmount();
    }
  });

  it("hides the certificate pages from a member without certificate:read", () => {
    mockFlags(ALL_ON);
    signIn(["VIEWER"], ["organization:view"]);

    render(<AppSidebar />);

    for (const title of [
      "Certificates",
      "Rotation",
      "PQC Readiness",
      "Certificate Discovery",
    ]) {
      expect(
        screen.queryByRole("link", { name: title }),
      ).not.toBeInTheDocument();
    }
    expect(screen.getByTestId("nav-main-Administration")).toHaveTextContent(
      "Support",
    );
  });

  it("shows Agents next to Integrations only to members who manage agent tokens", () => {
    mockFlags(ALL_ON);
    signIn(["ORGANIZATION_ADMIN"], [...READ, "integrations:view"]);
    const { unmount } = render(<AppSidebar />);
    const items = within(screen.getByTestId("nav-main-Administration"))
      .getAllByRole("listitem")
      .map((item) => item.textContent);
    expect(items).toEqual([
      "Integrations",
      "Agents",
      "Organization & Access",
      "Support",
    ]);
    unmount();

    signIn(["VIEWER"], [...READ, "integrations:view"]);
    const { unmount: unmountViewer } = render(<AppSidebar />);
    expect(screen.getByTestId("nav-main-Administration")).not.toHaveTextContent(
      "Agents",
    );
    unmountViewer();

    signIn(["MEMBER"], ["organization:manage"]);
    render(<AppSidebar />);
    expect(screen.getByTestId("nav-main-Administration")).toHaveTextContent(
      "Agents",
    );
  });

  it("shows Certificate Discovery and PQC Readiness only when their features are on", () => {
    signIn(["VIEWER"], READ);
    mockFlags({ ...ALL_ON, DISCOVERY: false, PQC_READINESS: false });

    render(<AppSidebar />);

    expect(
      screen.queryByRole("link", { name: "Certificate Discovery" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "PQC Readiness" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates" })).toHaveAttribute(
      "href",
      "/cert-manager",
    );
    expect(screen.getByRole("link", { name: "Rotation" })).toHaveAttribute(
      "href",
      "/cert-manager/rotation",
    );
  });
});
