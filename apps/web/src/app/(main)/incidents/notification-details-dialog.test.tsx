// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { NotificationDetailsDialog } from "@/app/(main)/incidents/notification-details-dialog";
import type { NotificationRecord } from "@/types/notifications";

const suppressed: NotificationRecord = {
  id: "notification-1",
  userId: null,
  organizationId: "42",
  websiteId: null,
  requestId: "cert-renewed:CERT-1",
  email: null,
  recipients: [],
  recipientSummary: null,
  templateName: "cert-renewal-success",
  subject: "CertPing - Cert renewal success",
  sentBy: "cert-manager",
  integrationType: "EMAIL",
  status: "SUPPRESSED",
  notificationType: "ACCOUNT_EVENT",
  notificationAction: "CERT_RENEWAL_SUCCESS",
  source: "cert-manager",
  roles: ["ORGANIZATION_ADMIN"],
  failureReason: "ORG_PREFERENCE:CERTIFICATE_ACTIVITY",
  sentAt: null,
  createdAt: "2026-10-19T09:12:44Z",
  updatedAt: "2026-10-19T09:12:44Z",
  messageId: "message-1",
};

describe("NotificationDetailsDialog", () => {
  it("says why a suppressed notification wasn't sent, by category name", () => {
    render(
      <NotificationDetailsDialog
        notification={suppressed}
        isOpen
        onClose={jest.fn()}
      />,
    );

    expect(screen.getByText("Why it wasn't sent")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Certificate activity is turned off in notification settings.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Not sent: turned off in notification settings"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/ORG_PREFERENCE/)).not.toBeInTheDocument();
    expect(screen.queryByText("Failure Reason")).not.toBeInTheDocument();
  });

  it("shows the record's details without a payload, which the API no longer sends", () => {
    render(
      <NotificationDetailsDialog
        notification={suppressed}
        isOpen
        onClose={jest.fn()}
      />,
    );

    expect(screen.queryByText("Payload")).not.toBeInTheDocument();
    expect(screen.queryByText("No payload available")).not.toBeInTheDocument();
    expect(
      screen.getByText("CertPing - Cert renewal success"),
    ).toBeInTheDocument();
    expect(screen.getByText("cert-renewal-success")).toBeInTheDocument();
  });

  it("keeps a failure's reason under Failure Reason", () => {
    render(
      <NotificationDetailsDialog
        notification={{
          ...suppressed,
          status: "FAILED",
          failureReason: "NO_RECIPIENT",
        }}
        isOpen
        onClose={jest.fn()}
      />,
    );

    expect(screen.getByText("Failure Reason")).toBeInTheDocument();
    expect(screen.getByText("NO_RECIPIENT")).toBeInTheDocument();
  });
});
