// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SystemNotificationsPage from "@/app/(main)/incidents/system-notifications/page";
import type {
  NotificationFilters,
  NotificationRecord,
} from "@/types/notifications";

const useSystemNotificationsMock = jest.fn();

jest.mock("@/hooks/incidents", () => ({
  useSystemNotifications: (...args: unknown[]) =>
    useSystemNotificationsMock(...args),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: { id: "user-1", permissions: ["notifications:view"] },
    isLoading: false,
  }),
}));

jest.mock("@/hooks/use-responsive-view-mode", () => ({
  useResponsiveViewMode: () => ["table", jest.fn()],
}));

jest.mock("@/lib/authz", () => ({
  canViewNotifications: () => true,
}));

jest.mock("@/lib/http-errors", () => ({
  isAccessDeniedError: () => false,
}));

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <h1>{title}</h1>,
}));

jest.mock("@/app/(main)/incidents/notification-details-dialog", () => ({
  NotificationDetailsDialog: () => null,
}));

const notification: NotificationRecord = {
  id: "notification-1",
  userId: null,
  organizationId: "42",
  websiteId: null,
  requestId: "request-1",
  email: "ops@example.com",
  recipients: ["ops@example.com"],
  recipientSummary: "ops@example.com",
  templateName: "cert-expired",
  subject: "Certificate expired",
  sentBy: "SYSTEM",
  integrationType: "EMAIL",
  status: "DELIVERED",
  notificationType: "CERT_EXPIRED",
  notificationAction: "EXPIRE",
  source: "CERTIFICATE_SCHEDULER",
  roles: [],
  failureReason: null,
  sentAt: "2026-07-21T09:12:45Z",
  createdAt: "2026-07-21T09:12:44Z",
  updatedAt: "2026-07-21T09:12:45Z",
  messageId: "message-1",
};

function mockPaginatedNotifications(): void {
  useSystemNotificationsMock.mockImplementation(
    (filters: NotificationFilters) => ({
      data: {
        items: [
          {
            ...notification,
            id: `notification-${filters.page ?? 0}`,
            subject: `Certificate expired page ${(filters.page ?? 0) + 1}`,
          },
        ],
        page: filters.page ?? 0,
        size: filters.size ?? 20,
        totalElements: 45,
        totalPages: Math.ceil(45 / (filters.size ?? 20)),
      },
      error: null,
      isFetched: true,
      isError: false,
      isFetching: false,
      isLoading: false,
      refetch: jest.fn(),
    }),
  );
}

describe("SystemNotificationsPage pagination", () => {
  beforeEach(() => {
    useSystemNotificationsMock.mockReset();
    mockPaginatedNotifications();
  });

  it("should render server metadata and describe search as page-local", () => {
    render(<SystemNotificationsPage />);

    expect(screen.getByText("Certificate expired page 1")).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("Search this page..."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Showing 1 to 20 of 45 entries"),
    ).toBeInTheDocument();
    expect(useSystemNotificationsMock).toHaveBeenLastCalledWith(
      { page: 0, size: 20 },
      { enabled: true, poll: true },
    );
  });

  it("should request the next zero-based page", async () => {
    const user = userEvent.setup();
    render(<SystemNotificationsPage />);

    await user.click(screen.getByRole("button", { name: "Go to next page" }));

    await waitFor(() =>
      expect(useSystemNotificationsMock).toHaveBeenLastCalledWith(
        { page: 1, size: 20 },
        { enabled: true, poll: true },
      ),
    );
    expect(screen.getByText("Certificate expired page 2")).toBeInTheDocument();
    expect(
      screen.getByText("Showing 21 to 40 of 45 entries"),
    ).toBeInTheDocument();
  });

  it("should reset to the first page after changing status or page size", async () => {
    const user = userEvent.setup();
    render(<SystemNotificationsPage />);

    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    await user.click(
      screen.getByRole("combobox", { name: "Filter by Status" }),
    );
    await user.click(await screen.findByRole("option", { name: "Failed" }));

    await waitFor(() =>
      expect(useSystemNotificationsMock).toHaveBeenLastCalledWith(
        { page: 0, size: 20, status: "FAILED" },
        { enabled: true, poll: true },
      ),
    );

    await user.click(screen.getByRole("combobox", { name: "Rows per page" }));
    await user.click(await screen.findByRole("option", { name: "50" }));

    await waitFor(() =>
      expect(useSystemNotificationsMock).toHaveBeenLastCalledWith(
        { page: 0, size: 50, status: "FAILED" },
        { enabled: true, poll: true },
      ),
    );
  });

  it("offers SUPPRESSED in the status filter by what it means", async () => {
    const user = userEvent.setup();
    render(<SystemNotificationsPage />);

    await user.click(
      screen.getByRole("combobox", { name: "Filter by Status" }),
    );
    await user.click(
      await screen.findByRole("option", {
        name: "Not sent: turned off in notification settings",
      }),
    );

    await waitFor(() =>
      expect(useSystemNotificationsMock).toHaveBeenLastCalledWith(
        { page: 0, size: 20, status: "SUPPRESSED" },
        { enabled: true, poll: true },
      ),
    );
  });

  it("should keep recovery in the background after an initial request fails", () => {
    const refetch = jest.fn();
    useSystemNotificationsMock.mockReturnValue({
      data: undefined,
      error: null,
      failureCount: 1,
      failureReason: new Error("Service unavailable"),
      isError: false,
      isFetched: false,
      isFetching: true,
      isLoading: true,
      refetch,
    });

    const { container } = render(<SystemNotificationsPage />);

    expect(
      screen.getByText("Notifications are temporarily unavailable"),
    ).toBeInTheDocument();
    expect(container.querySelector(".animate-pulse")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retrying" })).toBeDisabled();
    expect(screen.getByText("Refreshing notifications…")).toBeInTheDocument();
  });

  it("should let the user retry a settled notification failure", async () => {
    const user = userEvent.setup();
    const refetch = jest.fn();
    useSystemNotificationsMock.mockReturnValue({
      data: undefined,
      error: new Error("Service unavailable"),
      isError: true,
      isFetched: true,
      isFetching: false,
      isLoading: false,
      refetch,
    });

    render(<SystemNotificationsPage />);
    await user.click(screen.getByRole("button", { name: "Retry now" }));

    expect(refetch).toHaveBeenCalledTimes(1);
  });
});
