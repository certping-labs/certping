// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, within } from "@testing-library/react";

import { AlertList } from "@/components/common/alert-list";

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ user: { id: "operator-1" } }),
}));

jest.mock("@/lib/authz", () => ({
  canViewAlerts: () => true,
}));

jest.mock("@/hooks/incidents", () => ({
  useCanMarkAlertRead: () => () => true,
  useLatestSystemAlerts: () => ({
    data: [
      {
        id: "1",
        source: "ssl",
        alertType: "DEPLOYMENT_FAILURE",
        status: null,
        createdAt: "2026-09-12T00:00:00Z",
        message: "example.com expires in 7 day(s)",
        severity: "WARNING",
        unread: true,
        domain: "example.com",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "2",
        source: "ssl",
        alertType: "CERTIFICATE_FAILURE",
        status: "FAILED",
        createdAt: "2026-09-11T00:00:00Z",
        message: "Issuance failed",
        severity: "CRITICAL",
        unread: false,
        domain: "other.example.net",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "4",
        source: "ssl",
        alertType: "DEPLOYMENT_FAILURE",
        status: null,
        createdAt: "2026-09-12T01:00:00Z",
        message: "Transfer completed",
        severity: "INFO",
        unread: false,
        domain: "moved.example.net",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "3",
        source: "ssl",
        alertType: "CERTIFICATE_FAILURE",
        status: null,
        createdAt: "2026-09-10T12:00:00Z",
        message: "Renewal failed",
        severity: "CRITICAL",
        unread: false,
        domain: "example.com",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "5",
        source: "ssl",
        alertType: "CERTIFICATE_FAILURE",
        status: null,
        createdAt: "2026-09-10T13:00:00Z",
        message: "example.com renewed; the renewal problem has ended",
        severity: "INFO",
        unread: false,
        domain: "example.com",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "6",
        source: "ssl",
        alertType: "CERTIFICATE_FAILURE",
        status: "RESOLVED",
        createdAt: "2026-09-09T00:00:00Z",
        message: "Issuance recovered",
        severity: "WARNING",
        unread: false,
        domain: "example.com",
        deploymentTarget: null,
        correlationId: null,
      },
      {
        id: "7",
        source: "ssl",
        alertType: "DEPLOYMENT_FAILURE",
        status: "RESOLVED",
        createdAt: "2026-09-08T12:00:00Z",
        message: "example.com expires in 30 day(s)",
        severity: "WARNING",
        unread: false,
        domain: "example.com",
        deploymentTarget: null,
        correlationId: null,
      },
    ],
    isLoading: false,
    isError: false,
  }),
  useMarkSystemAlertAsRead: () => ({ mutate: jest.fn(), isPending: false }),
}));

describe("AlertList", () => {
  it("shows the alert type label with the message", () => {
    render(<AlertList />);

    expect(
      screen.getByText(/Deployment failure: example.com expires/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Certificate failure: Issuance failed/),
    ).toBeInTheDocument();
  });

  it("filters to one domain and renders nothing when hideEmpty and no match", () => {
    const { container, rerender } = render(<AlertList domain="example.com" />);
    expect(screen.getAllByRole("link")).toHaveLength(3);
    expect(
      screen.queryByText(/other\.example\.net|Issuance failed/),
    ).not.toBeInTheDocument();

    rerender(<AlertList domain="nothing.example.net" hideEmpty />);
    expect(container).toBeEmptyDOMElement();
  });

  it("keeps every message without a status, the problem and its ending, and hides every resolved alert", () => {
    render(<AlertList domain="example.com" />);

    expect(
      screen.getByRole("link", { name: /Renewal failed/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /example\.com renewed/ }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Issuance recovered/)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/expires in 30 day\(s\)/),
    ).not.toBeInTheDocument();
  });

  it("leads with the alert type on a domain's own page instead of repeating the domain", () => {
    render(<AlertList domain="example.com" />);

    const row = screen.getByRole("link", { name: /Renewal failed/ });
    const [title, detail] = row.querySelectorAll(".line-clamp-1");
    expect(title).toHaveTextContent(/^Certificate failure$/);
    expect(detail).toHaveTextContent(/^Renewal failed$/);
    expect(row).not.toHaveTextContent("example.com");
  });

  it("dates each row so an old message does not read as current", () => {
    render(<AlertList domain="example.com" />);

    const row = screen.getByRole("link", { name: /Renewal failed/ });
    const time = within(row).getByText("Sep 10, 2026");
    expect(time.tagName).toBe("TIME");
    expect(time.parentElement).toContainElement(
      within(row).getByText("Critical"),
    );
    expect(time).toHaveAttribute("dateTime", "2026-09-10T12:00:00Z");
  });

  it("shows the heading above the rows and hides it with them", () => {
    const { container, rerender } = render(
      <AlertList domain="example.com" heading="Recent messages" />,
    );
    expect(
      screen.getByRole("heading", { level: 2, name: "Recent messages" }),
    ).toBeInTheDocument();

    rerender(
      <AlertList
        domain="nothing.example.net"
        heading="Recent messages"
        hideEmpty
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders an INFO alert as informational, not as an error", () => {
    render(<AlertList />);

    const row = screen.getByRole("link", { name: /moved\.example\.net/ });
    expect(row).toHaveTextContent("Deployment failure: Transfer completed");
    expect(within(row).getByText("Info")).toHaveClass("bg-info-soft");
    expect(within(row).getByText("Info")).not.toHaveClass("bg-danger-soft");
    expect(row.querySelector("svg")).toHaveClass("status-info-text");
    expect(row.querySelector("svg")).not.toHaveClass("status-warning-text");
  });
});
