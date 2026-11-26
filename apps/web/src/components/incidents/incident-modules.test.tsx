// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  buildEscalationDraft,
  escalationActor,
  indexUserEmails,
} from "@/components/incidents/alert-presentation";
import {
  AlertGrid,
  EscalationGrid,
} from "@/components/incidents/incident-cards";
import type { AlertActions } from "@/components/incidents/incident-columns";
import type { SystemAlert } from "@/hooks/incidents";
import type { UserDto } from "@/types/auth";
import type { IncidentHistoryItem } from "@/types/integrations";

const alert: SystemAlert = {
  id: "42",
  source: "ssl",
  alertType: "CERTIFICATE_EXPIRING" as SystemAlert["alertType"],
  typeLabel: "Certificate expiring",
  status: "OPEN",
  createdAt: "2026-09-30T10:00:00Z",
  message: "Expires in 3 days",
  severity: "CRITICAL",
  unread: true,
  domain: "acme.com",
  deploymentTarget: null,
  correlationId: null,
};

const incident = {
  id: 7,
  alertId: 42,
  provider: "PAGERDUTY",
  summary: "Cert outage",
  externalReference: "PD-1",
  externalIncidentId: null,
  externalUrl: "https://pd.example/1",
  source: "PUBLIC_API",
  actorUserId: 3,
  createdAt: "2026-09-30T11:00:00Z",
} as unknown as IncidentHistoryItem;

function actions(overrides: Partial<AlertActions> = {}): AlertActions {
  return {
    escalationCount: () => 0,
    canMarkRead: () => true,
    canEscalate: () => true,
    isMarking: false,
    onOpen: jest.fn(),
    onMarkRead: jest.fn(),
    onEscalate: jest.fn(),
    onViewEscalations: jest.fn(),
    ...overrides,
  };
}

describe("escalation helpers", () => {
  it("drafts an escalation from the alert it came from", () => {
    expect(buildEscalationDraft(alert)).toEqual({
      alertId: 42,
      title: "Alert failure: acme.com",
      description:
        "Source: SSL\nDomain: acme.com\nStatus: OPEN\nMessage: Expires in 3 days",
      severity: "CRITICAL",
      source: "certping/incidents-alerts",
      dedupKey: "alert:ssl:42",
    });
    expect(buildEscalationDraft(null).alertId).toBe(0);
    expect(buildEscalationDraft({ ...alert, severity: "INFO" }).severity).toBe(
      "INFO",
    );
  });

  it("names who raised an escalation", () => {
    const emails = indexUserEmails([
      { id: 3, email: "ops@acme.com" } as UserDto,
    ]);

    expect(escalationActor(incident, emails)).toBe("ops@acme.com");
    expect(
      escalationActor({ ...incident, source: "INTERNAL_API" }, emails),
    ).toBe("System");
    expect(escalationActor({ ...incident, actorUserId: 9 }, emails)).toBe("-");
  });
});

describe("incident grids", () => {
  it("opens, marks and escalates an alert from its card", async () => {
    const user = userEvent.setup();
    const handlers = actions();
    render(<AlertGrid alerts={[alert]} actions={handlers} />);

    expect(screen.getByText("Critical")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "acme.com" }));
    await user.click(screen.getByRole("button", { name: "Mark as read" }));
    await user.click(screen.getByRole("button", { name: "Escalate" }));

    expect(handlers.onOpen).toHaveBeenCalledWith(alert);
    expect(handlers.onMarkRead).toHaveBeenCalledWith(alert);
    expect(handlers.onEscalate).toHaveBeenCalledWith(alert);
  });

  it("links an escalated alert to its escalations", async () => {
    const user = userEvent.setup();
    const handlers = actions({ escalationCount: () => 2 });
    render(<AlertGrid alerts={[alert]} actions={handlers} />);

    expect(screen.getByText("2 escalations")).toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "View 2 escalations" }),
    );
    expect(handlers.onViewEscalations).toHaveBeenCalledWith(42);
  });

  it("shows escalations with their provider link, and empty states", () => {
    const { rerender } = render(
      <EscalationGrid incidents={[incident]} actorFor={() => "ops@acme.com"} />,
    );
    expect(
      screen.getByRole("link", { name: /Open in PagerDuty/ }),
    ).toHaveAttribute("href", "https://pd.example/1");
    expect(screen.getByText("ops@acme.com")).toBeInTheDocument();

    rerender(<EscalationGrid incidents={[]} actorFor={() => "-"} />);
    expect(screen.getByText("No escalations found.")).toBeInTheDocument();
    rerender(<AlertGrid alerts={[]} actions={actions()} />);
    expect(screen.getByText("No incidents found.")).toBeInTheDocument();
  });
});
