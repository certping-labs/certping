// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import type { SystemAlert } from "@/hooks/incidents";
import { AlertDetailsDialog } from "./alert-details-dialog";

jest.mock("@/components/support/support-reference-link", () => ({
  SupportReferenceLink: () => null,
}));

const buildAlert = (overrides: Partial<SystemAlert>): SystemAlert => ({
  id: "1",
  source: "ssl",
  alertType: "CERTIFICATE_FAILURE",
  typeLabel: "Certificate failure",
  status: "FAILED",
  createdAt: "2026-09-12T12:00:00Z",
  message: "Issuance failed",
  severity: "CRITICAL",
  unread: false,
  domain: "example.com",
  deploymentTarget: null,
  correlationId: null,
  ...overrides,
});

const renderDialog = (alert: SystemAlert) =>
  render(
    <AlertDetailsDialog
      alert={alert}
      isOpen
      canEscalate={false}
      canMarkAsRead={false}
      hasEscalations={false}
      isMarkingAsRead={false}
      onClose={jest.fn()}
      onMarkAsRead={jest.fn()}
      onEscalate={jest.fn()}
      onViewEscalations={jest.fn()}
    />,
  );

describe("AlertDetailsDialog", () => {
  it("shows the status of a certificate alert", () => {
    renderDialog(buildAlert({}));

    expect(screen.getByRole("heading", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });
});
