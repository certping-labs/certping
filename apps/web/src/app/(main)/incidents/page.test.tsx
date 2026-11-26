// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import type { SystemAlert } from "@/hooks/incidents";
import IncidentsPage from "./page";

const mockAlerts: SystemAlert[] = [];
let mockSearch = "";
const mockUseIncidentEscalations = jest.fn();
const mockMarkAll = jest.fn();
const mockUnread = { hasUnread: false, hasUnreadProblem: false };
const mockPermissions = {
  escalate: false,
  markSsl: false,
};

jest.mock("next/navigation", () => ({
  usePathname: () => "/incidents",
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: { id: "operator-1" }, isLoading: false }),
}));

const mockFlags: Record<string, boolean> = {};

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) => mockFlags[key] !== false,
  useIsOrgFeatureEnabled: (key: string) => mockFlags[key] !== false,
}));

jest.mock("@/hooks/users", () => ({
  useListUsers: () => ({ data: [] }),
}));

jest.mock("@/hooks/use-responsive-view-mode", () => ({
  useResponsiveViewMode: () => ["table", jest.fn()],
}));

jest.mock("@/lib/authz", () => ({
  canCreateIncidents: () => mockPermissions.escalate,
  canManageNotifications: () => mockPermissions.markSsl,
  canViewIncidents: () => true,
}));

jest.mock("@/components/incidents/escalate-incident-dialog", () => ({
  EscalateIncidentDialog: () => null,
}));

jest.mock("@/hooks/incidents", () => ({
  useCanMarkAlertRead: () => () => mockPermissions.markSsl,
  useFindLoadedAlert: () => (key: string) =>
    mockAlerts.find((alert) => `${alert.source}:${alert.id}` === key),
  useSystemAlerts: () => ({
    data: mockAlerts,
    isLoading: false,
    isError: false,
  }),
  useUnreadAlertSummary: () => mockUnread,
  useIncidentEscalations: (...args: unknown[]) => {
    mockUseIncidentEscalations(...args);
    return { data: { items: [] }, isLoading: false, isError: false };
  },
  useMarkSystemAlertAsRead: () => ({ mutate: jest.fn(), isPending: false }),
  useMarkAllSystemAlertsAsRead: () => ({
    mutate: mockMarkAll,
    isPending: false,
  }),
}));

jest.mock("sonner", () => ({
  toast: { error: jest.fn(), success: jest.fn() },
}));

const buildAlert = (overrides: Partial<SystemAlert>): SystemAlert => ({
  id: "1",
  source: "ssl",
  alertType: "CERTIFICATE_FAILURE",
  typeLabel: "Certificate failure",
  status: null,
  createdAt: "2026-09-12T12:00:00Z",
  message: "Message",
  severity: "INFO",
  unread: false,
  domain: "example.com",
  deploymentTarget: null,
  correlationId: null,
  ...overrides,
});

const rowFor = (message: string): HTMLElement => {
  const row = screen.getByText(message).closest("tr");
  if (!row) {
    throw new Error(`No table row for ${message}`);
  }
  return row;
};

describe("IncidentsPage alerts table", () => {
  beforeEach(() => {
    mockAlerts.length = 0;
    Object.assign(mockUnread, { hasUnread: false, hasUnreadProblem: false });
    Object.assign(mockPermissions, {
      escalate: false,
      markSsl: false,
    });
    mockMarkAll.mockReset();
    delete mockFlags.INTEGRATIONS;
    mockSearch = "";
    mockUseIncidentEscalations.mockClear();
  });

  it("falls back to Alerts from an escalations link and requests no escalations while integrations are off", () => {
    mockFlags.INTEGRATIONS = false;
    mockSearch = "tab=escalations";

    render(<IncidentsPage />);

    expect(screen.getByRole("tab", { name: "Alerts" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(mockUseIncidentEscalations).toHaveBeenCalledWith(
      {},
      { enabled: false },
    );
    expect(mockUseIncidentEscalations).not.toHaveBeenCalledWith(
      {},
      { enabled: true },
    );
  });

  it("drops escalations, not alerts, while integrations are off", () => {
    mockFlags.INTEGRATIONS = false;
    mockPermissions.escalate = true;
    mockAlerts.push(
      buildAlert({ id: "7", source: "ssl", message: "Certificate failed" }),
    );

    render(<IncidentsPage />);

    expect(screen.getByRole("tab", { name: "Alerts" })).toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Escalations" }),
    ).not.toBeInTheDocument();
    expect(
      within(rowFor("Certificate failed")).queryByRole("button", {
        name: "Escalate",
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("Alerts from your certificates."),
    ).toBeInTheDocument();
  });

  it("shows no status for a message and names the empty cell", () => {
    mockAlerts.push(buildAlert({ message: "example.com renewed" }));

    render(<IncidentsPage />);

    const row = rowFor("example.com renewed");
    expect(within(row).getByText("No status")).toHaveClass("sr-only");
    expect(within(row).queryByText(/open|resolved/i)).not.toBeInTheDocument();
  });

  it("offers Escalate on an alert when the user may escalate", () => {
    mockPermissions.escalate = true;
    mockAlerts.push(
      buildAlert({ id: "7", source: "ssl", message: "Certificate failed" }),
    );

    render(<IncidentsPage />);

    expect(
      within(rowFor("Certificate failed")).getByRole("button", {
        name: "Escalate",
      }),
    ).toBeInTheDocument();
  });

  it("shows Mark as read on an unread alert only with the permission", () => {
    mockAlerts.push(
      buildAlert({ id: "1", source: "ssl", unread: true, message: "SSL row" }),
    );

    const { unmount } = render(<IncidentsPage />);
    expect(
      within(rowFor("SSL row")).queryByRole("button", { name: "Mark as read" }),
    ).not.toBeInTheDocument();
    unmount();

    mockPermissions.markSsl = true;
    render(<IncidentsPage />);
    expect(
      within(rowFor("SSL row")).getByRole("button", { name: "Mark as read" }),
    ).toBeInTheDocument();
  });

  it("offers Mark all as read from the unread summary, not the loaded rows", async () => {
    mockPermissions.markSsl = true;
    mockUnread.hasUnread = true;
    const user = userEvent.setup();

    render(<IncidentsPage />);
    await user.click(screen.getByRole("button", { name: "Mark all as read" }));

    expect(mockMarkAll).toHaveBeenCalledTimes(1);
  });
});
