// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AppSearch } from "@/components/common/app-search";
import type { SsoUser } from "@/types/auth";

const pushMock = jest.fn();
const prefetchMock = jest.fn();

const currentUser: SsoUser = {
  id: "user-1",
  email: "user@example.com",
  organizationId: "organization-1",
  organizationName: "Acme",
  roles: ["ORGANIZATION_ADMIN"],
  permissions: [
    "certificate:read",
    "credential:read",
    "credential:create",
    "notifications:view",
    "organization:manage",
  ],
  authMethod: "LOCAL",
};

jest.mock("next/navigation", () => ({
  useRouter: () => ({
    prefetch: prefetchMock,
    push: pushMock,
  }),
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    isSuperAdmin: false,
    user: currentUser,
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsRouteAvailable: () => () => true,
  useFeatureFlags: () => ({
    effectiveMap: {},
    isEnabled: (featureKey: string) =>
      featureKey === "ALERTS" ||
      featureKey === "CREDENTIALS_MANAGEMENT" ||
      featureKey === "DNS_CREDENTIALS",
    isReady: true,
  }),
}));

describe("AppSearch", () => {
  class MockResizeObserver {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }

  beforeEach(() => {
    pushMock.mockReset();
    prefetchMock.mockReset();
    Object.defineProperty(window, "ResizeObserver", {
      value: MockResizeObserver,
      configurable: true,
    });
  });

  /**
   * The search trigger, whichever breakpoint's copy jsdom happens to render.
   *
   * <p>There are two: a labelled toolbar control for `md` and up, and an
   * icon-only one below it. They share an accessible name because they are the
   * same action, and in a browser only one is ever in the accessibility tree -
   * the other is `display: none`. jsdom applies no media queries, so both are
   * present here and either will do.
   */
  function openSearchTrigger(): HTMLElement {
    return screen.getAllByRole("button", {
      name: /open application search/i,
    })[0];
  }

  async function openSearchAndRunQuery(query: string) {
    const user = userEvent.setup();
    render(<AppSearch />);

    await user.click(openSearchTrigger());
    await user.type(
      await screen.findByPlaceholderText(
        /search pages, settings, and actions/i,
      ),
      query,
    );

    return user;
  }

  it("opens with the universal shortcut and navigates to the selected item", async () => {
    const user = userEvent.setup();
    render(<AppSearch />);

    await user.keyboard("{Control>}k{/Control}");

    expect(
      await screen.findByPlaceholderText(
        /search pages, settings, and actions/i,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Overview")).toBeInTheDocument();

    await user.click(screen.getByText("Overview"));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("renders page and action results without duplicate React keys", async () => {
    const consoleError = jest
      .spyOn(console, "error")
      .mockImplementation(() => undefined);

    try {
      const user = userEvent.setup();
      render(<AppSearch />);

      await user.click(openSearchTrigger());
      expect(await screen.findByText("Overview")).toBeInTheDocument();

      const duplicateKeyWarnings = consoleError.mock.calls.filter(([message]) =>
        String(message).includes("same key"),
      );
      expect(duplicateKeyWarnings).toHaveLength(0);
    } finally {
      consoleError.mockRestore();
    }
  });

  it("prefetches a result route when the user hovers it", async () => {
    const user = await openSearchAndRunQuery("notification");

    await user.hover(await screen.findByText("Notifications"));

    expect(prefetchMock).toHaveBeenCalledWith(
      "/incidents/system-notifications",
    );
  });

  it("puts an exact title match first across all result groups", async () => {
    await openSearchAndRunQuery("notification");

    const results = await screen.findAllByRole("option");
    expect(results[0]).toHaveTextContent("Notifications");
    expect(results[0]).toHaveTextContent("/incidents/system-notifications");
  });

  it.each([
    [
      "connect dns provider",
      "Connect DNS Provider",
      "/integrations/connections/add?type=DNS",
    ],
    ["support", "Support", "/support"],
  ])("routes %s to %s", async (query, result, href) => {
    const user = await openSearchAndRunQuery(query);

    await user.click(await screen.findByText(result));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(href);
    });
  });
});
