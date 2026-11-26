// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, AxiosHeaders } from "axios";

import { NotificationPreferences } from "@/components/settings/notification-preferences";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  getNotificationSettings,
  saveNotificationSettings,
} from "@/lib/backend/notification-settings";
import { toast } from "sonner";

const mockAuth = jest.fn();
let mockFlagsOn = new Set<string>();

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuth(),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useFeatureFlags: () => ({
    isEnabled: (featureKey: string) => mockFlagsOn.has(featureKey),
  }),
}));

const EVERY_FEATURE = new Set<string>(Object.values(FEATURE_FLAGS));
const PROD_LIKE = new Set<string>(
  [...EVERY_FEATURE].filter(
    (featureKey) =>
      featureKey !== FEATURE_FLAGS.CERTIFICATE_RENEWAL &&
      featureKey !== FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT &&
      featureKey !== FEATURE_FLAGS.INTEGRATIONS,
  ),
);

jest.mock("@/lib/backend/notification-settings", () => ({
  getNotificationSettings: jest.fn(),
  saveNotificationSettings: jest.fn(),
}));

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockedGet = jest.mocked(getNotificationSettings);
const mockedSave = jest.mocked(saveNotificationSettings);

const ALL_SENT = [
  { key: "CERTIFICATE_ACTIVITY", enabled: true },
  { key: "OTHER_CATEGORY", enabled: true },
  { key: "LATER_CATEGORY", enabled: true },
  { key: "REPORTS", enabled: true },
];

function asOrgAdmin() {
  mockAuth.mockReturnValue({
    user: {
      organizationId: "7",
      roles: ["ORGANIZATION_ADMIN"],
      permissions: ["organization:manage"],
    },
    isSuperAdmin: false,
  });
}

function httpError(status: number, data: unknown): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError("Request failed", String(status), undefined, null, {
    status,
    statusText: "",
    headers,
    config: { headers },
    data,
  });
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <NotificationPreferences />
    </QueryClientProvider>,
  );
}

describe("NotificationPreferences", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFlagsOn = new Set(EVERY_FEATURE);
    asOrgAdmin();
  });

  it("shows a switch per category and what is always sent", async () => {
    mockedGet.mockResolvedValue([
      ...ALL_SENT.slice(0, 3),
      { key: "REPORTS", enabled: false },
    ]);

    renderPage();

    expect(
      await screen.findByRole("switch", { name: "Certificate activity" }),
    ).toBeChecked();
    // Categories this app does not know are stored but not offered as switches.
    expect(
      screen.queryByRole("switch", { name: "Another category" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: "Reports and digests" }),
    ).not.toBeChecked();
    expect(screen.getByText("Always sent")).toBeInTheDocument();
    for (const line of [
      "Security and account",
      "Failures, expiry and action needed",
      "Service changes",
    ]) {
      expect(screen.getByText(line)).toBeInTheDocument();
    }
    expect(mockedGet).toHaveBeenCalledWith("7");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("saves the categories turned off and shows the saved state", async () => {
    mockedGet.mockResolvedValue(ALL_SENT);
    mockedSave.mockResolvedValue([
      { key: "CERTIFICATE_ACTIVITY", enabled: false },
      ...ALL_SENT.slice(1),
    ]);
    const user = userEvent.setup();
    renderPage();

    await user.click(
      await screen.findByRole("switch", { name: "Certificate activity" }),
    );
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(mockedSave).toHaveBeenCalledWith("7", ["CERTIFICATE_ACTIVITY"]),
    );
    expect(toast.success).toHaveBeenCalledWith("Notification settings saved.");
    await waitFor(() =>
      expect(
        screen.getByRole("switch", { name: "Certificate activity" }),
      ).not.toBeChecked(),
    );
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("keeps a category this page doesn't know as stored when saving", async () => {
    mockedGet.mockResolvedValue([
      ...ALL_SENT,
      { key: "SOMETHING_NEW", enabled: false },
      { key: "ANOTHER_NEW", enabled: true },
    ]);
    mockedSave.mockResolvedValue(ALL_SENT);
    const user = userEvent.setup();
    renderPage();

    await user.click(
      await screen.findByRole("switch", { name: "Certificate activity" }),
    );
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(mockedSave).toHaveBeenCalledWith("7", [
        "CERTIFICATE_ACTIVITY",
        "SOMETHING_NEW",
      ]),
    );
    expect(screen.queryByText("SOMETHING_NEW")).not.toBeInTheDocument();
  });

  it("describes each switch by its category's line", async () => {
    mockedGet.mockResolvedValue(ALL_SENT);
    renderPage();

    expect(
      await screen.findByRole("switch", {
        name: "Certificate activity",
        description: "A certificate was issued, renewed or deployed.",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("switch", {
        name: "Reports and digests",
        description:
          "Scan reports and activity digests. Findings stay in the app.",
      }),
    ).toBeInTheDocument();
  });

  it("turning a switch back leaves nothing to save", async () => {
    mockedGet.mockResolvedValue(ALL_SENT);
    const user = userEvent.setup();
    renderPage();

    const reports = await screen.findByRole("switch", {
      name: "Reports and digests",
    });
    await user.click(reports);
    expect(screen.getByRole("button", { name: "Save changes" })).toBeEnabled();
    await user.click(reports);

    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("explains a refused list and a closed feature generically, never in the API's words", async () => {
    mockedGet.mockResolvedValue(ALL_SENT);
    mockedSave
      .mockRejectedValueOnce(
        httpError(400, { message: "Unknown notification category" }),
      )
      .mockRejectedValueOnce(httpError(423, { code: "FEATURE_DISABLED" }));
    const user = userEvent.setup();
    renderPage();

    await user.click(
      await screen.findByRole("switch", { name: "Certificate activity" }),
    );
    const save = screen.getByRole("button", { name: "Save changes" });
    await user.click(save);
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Notification settings couldn't be saved. Please try again.",
      ),
    );
    expect(toast.error).not.toHaveBeenCalledWith(
      "Unknown notification category",
    );

    await user.click(save);
    await waitFor(() =>
      expect(toast.error).toHaveBeenLastCalledWith(
        "Notification settings aren't available. Ask your CertPing administrator.",
      ),
    );
  });

  it("says the settings aren't available when they are off", async () => {
    mockedGet.mockRejectedValue(httpError(423, { code: "FEATURE_DISABLED" }));

    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Notification settings aren't available. Ask your CertPing administrator.",
    );
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  });

  it("asks to try again when the settings could not be loaded", async () => {
    mockedGet.mockRejectedValue(httpError(403, {}));

    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Notification settings couldn't be loaded. Please try again.",
    );
  });

  it("shows a super admin the settings read-only", async () => {
    mockAuth.mockReturnValue({
      user: { organizationId: "7", roles: ["SUPER_ADMIN"], permissions: [] },
      isSuperAdmin: true,
    });
    mockedGet.mockResolvedValue([
      { key: "CERTIFICATE_ACTIVITY", enabled: false },
      ...ALL_SENT.slice(1),
    ]);

    renderPage();

    expect(
      await screen.findByText(
        "Only organization admins can change these settings.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: "Certificate activity: Off" }),
    ).toHaveTextContent("Off");
    expect(
      screen.getByRole("group", { name: "Reports and digests: Sent" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Save changes" }),
    ).not.toBeInTheDocument();
  });

  it("shows nothing and asks nothing without an organization", () => {
    mockAuth.mockReturnValue({
      user: { organizationId: null },
      isSuperAdmin: false,
    });

    const { container } = renderPage();

    expect(container).toBeEmptyDOMElement();
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it("shows nothing while CertPing has notification preferences off for the organization", () => {
    mockFlagsOn.delete(FEATURE_FLAGS.NOTIFICATION_PREFERENCES);

    const { container } = renderPage();

    expect(container).toBeEmptyDOMElement();
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it("shows nothing to a member who is not an organization admin", () => {
    mockAuth.mockReturnValue({
      user: { organizationId: "7", roles: ["VIEWER"], permissions: [] },
      isSuperAdmin: false,
    });

    const { container } = renderPage();

    expect(container).toBeEmptyDOMElement();
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it("names only what the organization's features send", async () => {
    mockFlagsOn = new Set(PROD_LIKE);
    mockedGet.mockResolvedValue(ALL_SENT);

    renderPage();

    expect(
      await screen.findByRole("switch", {
        name: "Certificate activity",
        description: "A certificate was issued.",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("switch", { name: "Monitoring changes" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        "Choose which informational notifications are sent. Each choice covers email.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Failed issuance and expiring certificates."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Features an administrator pauses or resumes."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/renewal|deployment/i)).not.toBeInTheDocument();
  });

  it("keeps a hidden category as stored when saving", async () => {
    mockedGet.mockResolvedValue([
      ...ALL_SENT.slice(0, 2),
      { key: "LATER_CATEGORY", enabled: false },
      ALL_SENT[3],
    ]);
    mockedSave.mockResolvedValue(ALL_SENT);
    const user = userEvent.setup();
    renderPage();

    await user.click(
      await screen.findByRole("switch", { name: "Reports and digests" }),
    );
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(mockedSave).toHaveBeenCalledWith("7", [
        "LATER_CATEGORY",
        "REPORTS",
      ]),
    );
  });
});
