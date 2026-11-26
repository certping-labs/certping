// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { useEffect } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse, type JsonBodyType } from "msw";

import { FeatureRouteGate } from "@/components/common/feature-route-gate";
import { useFeatureFlagsSync } from "@/hooks/use-feature-flags";
import { apiClient, supportApiClient } from "@/lib/api";
import { endSession } from "@/lib/session-end";
import { queryClient } from "@/providers/react-query";
import { tokenStorage } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";

const listFeatureFlagsMock = jest.fn();

jest.mock("@/lib/session-end", () => ({
  ...jest.requireActual("@/lib/session-end"),
  endSession: jest.fn(),
}));

jest.mock("@/hooks/use-feature-flags", () =>
  jest.requireActual("@/hooks/use-feature-flags"),
);

jest.mock("@/lib/backend/feature-flags", () => ({
  getEffectiveFeatureFlags: () => listFeatureFlagsMock(),
}));

jest.mock("next/navigation", () => ({
  usePathname: () => "/cert-manager/cryptography",
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    user: { organizationId: "org-1" },
  }),
}));

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL as string;
const CERTS_URL = `${API_BASE_URL}/api/v1/certs`;
const REFRESH_URL = `${API_BASE_URL}/api/auth/refresh`;

const handlerRefusal = (message: string) => ({
  status: 401,
  error: "Unauthorized",
  message,
  path: "/api/v1/certs",
  timestamp: "2026-09-26T10:00:00Z",
});

describe("401 handling in the API clients", () => {
  let requestCount = 0;

  afterEach(() => {
    server.resetHandlers();
    requestCount = 0;
    localStorage.clear();
  });

  const answer401With = (body: JsonBodyType) =>
    server.use(
      http.get(CERTS_URL, () => {
        requestCount += 1;
        return HttpResponse.json(body, { status: 401 });
      }),
    );

  it.each([
    [
      "a disabled account (message body)",
      handlerRefusal("Account is disabled or deleted"),
      "account-disabled",
    ],
    [
      "a suspended organization (message body)",
      handlerRefusal("Organization is suspended or inactive"),
      "organization-suspended",
    ],
    [
      "a disabled account (error body)",
      { error: "Account is disabled or deleted" },
      "account-disabled",
    ],
    [
      "a suspended organization (error body)",
      { error: "Organization is suspended or inactive" },
      "organization-suspended",
    ],
  ])(
    "signs out with the reason and does not retry for %s",
    async (_case, body, reason) => {
      answer401With(body);

      await expect(apiClient.get(CERTS_URL)).rejects.toMatchObject({
        response: { status: 401 },
      });

      expect(endSession).toHaveBeenCalledTimes(1);
      expect(endSession).toHaveBeenCalledWith(reason);
      expect(requestCount).toBe(1);
    },
  );

  const answerExpiredThenOk = () =>
    server.use(
      http.get(CERTS_URL, () => {
        requestCount += 1;
        return requestCount === 1
          ? HttpResponse.json(handlerRefusal("Invalid or expired token"), {
              status: 401,
            })
          : HttpResponse.json([]);
      }),
    );

  it("refreshes the token and retries any other 401 without signing out", async () => {
    tokenStorage.setTokens("old-access", "stored-refresh");
    answerExpiredThenOk();
    server.use(
      http.post(REFRESH_URL, () =>
        HttpResponse.json({
          accessToken: "new-access",
          refreshToken: "new-refresh",
          expiresIn: 900,
        }),
      ),
    );

    await expect(apiClient.get(CERTS_URL)).resolves.toMatchObject({
      status: 200,
    });

    expect(requestCount).toBe(2);
    expect(endSession).not.toHaveBeenCalled();
    expect(tokenStorage.getAccessToken()).toBe("new-access");
  });

  it("ends the session once, with the reason, when the refresh refuses the organization", async () => {
    tokenStorage.setTokens("old-access", "stored-refresh");
    answer401With(handlerRefusal("Invalid or expired token"));
    let refreshCount = 0;
    server.use(
      http.post(REFRESH_URL, () => {
        refreshCount += 1;
        return HttpResponse.json(
          {
            status: 401,
            error: "Unauthorized",
            message: "Organization is suspended or inactive",
          },
          { status: 401 },
        );
      }),
    );

    const results = await Promise.allSettled([
      apiClient.get(CERTS_URL),
      apiClient.get(CERTS_URL),
      apiClient.get(CERTS_URL),
    ]);

    expect(results.map((result) => result.status)).toEqual([
      "rejected",
      "rejected",
      "rejected",
    ]);
    expect(requestCount).toBe(3);
    expect(refreshCount).toBe(1);
    expect(endSession).toHaveBeenCalledTimes(1);
    expect(endSession).toHaveBeenCalledWith("organization-suspended");
  });

  it("does not sign out on a 403 that carries the same message", async () => {
    server.use(
      http.get(CERTS_URL, () =>
        HttpResponse.json(handlerRefusal("Account is disabled or deleted"), {
          status: 403,
        }),
      ),
    );

    await expect(apiClient.get(CERTS_URL)).rejects.toBeDefined();

    expect(endSession).not.toHaveBeenCalled();
  });

  it("signs out with the reason from the support client too", async () => {
    answer401With({ error: "Organization is suspended or inactive" });

    await expect(supportApiClient.get(CERTS_URL)).rejects.toBeDefined();

    expect(endSession).toHaveBeenCalledWith("organization-suspended");
    expect(requestCount).toBe(1);
  });
});

describe("423 handling in the API client", () => {
  const MONITORING_URL = `${API_BASE_URL}/api/v1/monitoring`;
  let mounts = 0;

  function GatedPage() {
    useEffect(() => {
      mounts += 1;
    }, []);
    return <div>Gated content</div>;
  }

  beforeEach(() => {
    mounts = 0;
    listFeatureFlagsMock.mockReset();
    listFeatureFlagsMock.mockResolvedValue({
      PQC_READINESS: true,
      WEBSITE_MONITORING: true,
    });
    useFeatureFlagStore.getState().reset();
  });

  afterEach(() => {
    server.resetHandlers();
    queryClient.clear();
  });

  function FlagSync() {
    useFeatureFlagsSync();
    return null;
  }

  const renderGatedPage = () =>
    render(
      <QueryClientProvider client={queryClient}>
        <FlagSync />
        <FeatureRouteGate>
          <GatedPage />
        </FeatureRouteGate>
      </QueryClientProvider>,
    );

  it("refetches the flags without unmounting an unrelated gated page", async () => {
    server.use(
      http.get(MONITORING_URL, () =>
        HttpResponse.json({ feature: "WEBSITE_MONITORING" }, { status: 423 }),
      ),
    );
    renderGatedPage();
    await screen.findByText("Gated content");

    await expect(apiClient.get(MONITORING_URL)).rejects.toMatchObject({
      response: { status: 423 },
    });

    await waitFor(() => expect(listFeatureFlagsMock).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Gated content")).toBeInTheDocument();
    expect(mounts).toBe(1);
    expect(useFeatureFlagStore.getState().isEnabled("WEBSITE_MONITORING")).toBe(
      false,
    );
  });

  it("swaps the page for the disabled state when its own feature answers 423", async () => {
    listFeatureFlagsMock
      .mockResolvedValueOnce({ PQC_READINESS: true })
      // The refetch has not answered yet; the 423 alone must close the page.
      .mockReturnValue(new Promise(() => undefined));
    server.use(
      http.get(MONITORING_URL, () =>
        HttpResponse.json({ feature: "PQC_READINESS" }, { status: 423 }),
      ),
    );
    renderGatedPage();
    await screen.findByText("Gated content");

    await expect(apiClient.get(MONITORING_URL)).rejects.toBeDefined();

    expect(
      await screen.findByRole("heading", {
        name: "PQC readiness isn't available",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Gated content")).not.toBeInTheDocument();
  });

  describe("when the flag endpoint keeps saying on (stale) after a 423", () => {
    const T0 = new Date("2026-10-06T10:00:00Z").getTime();
    // Only the clock is faked: MSW and React Query keep real timers, and
    // each "poll" below is an explicit refetch at a set time.
    beforeEach(() => {
      jest.useFakeTimers({
        doNotFake: [
          "setTimeout",
          "clearTimeout",
          "setInterval",
          "clearInterval",
          "setImmediate",
          "clearImmediate",
          "nextTick",
          "queueMicrotask",
        ],
      });
      jest.setSystemTime(T0);
      listFeatureFlagsMock.mockResolvedValue({ PQC_READINESS: true });
      server.use(
        http.get(MONITORING_URL, () =>
          HttpResponse.json({ feature: "PQC_READINESS" }, { status: 423 }),
        ),
      );
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    const poll = async () => {
      await queryClient.refetchQueries({ queryKey: ["feature-flags"] });
    };
    const hit423 = () =>
      expect(apiClient.get(MONITORING_URL)).rejects.toBeDefined();
    const disabledHeading = () =>
      screen.queryByRole("heading", { name: "PQC readiness isn't available" });

    it("closes once, ignores repeats, and reopens once after a quiet minute", async () => {
      renderGatedPage();
      await screen.findByText("Gated content");
      expect(listFeatureFlagsMock).toHaveBeenCalledTimes(1);

      await hit423();
      await waitFor(() => expect(disabledHeading()).toBeInTheDocument());
      // The closing 423 refetches once; the stale "on" cannot reopen.
      await waitFor(() =>
        expect(listFeatureFlagsMock).toHaveBeenCalledTimes(2),
      );
      expect(disabledHeading()).toBeInTheDocument();

      // Repeated stale 423s extend the cooldown without any refetch.
      for (const seconds of [10, 20, 30, 40, 50]) {
        jest.setSystemTime(T0 + seconds * 1_000);
        await hit423();
      }
      expect(listFeatureFlagsMock).toHaveBeenCalledTimes(2);

      // A normal poll inside the extended window stays closed.
      jest.setSystemTime(T0 + 90_000);
      await poll();
      expect(disabledHeading()).toBeInTheDocument();

      // A minute after the last 423, the next "on" poll reopens the page.
      jest.setSystemTime(T0 + 50_000 + 60_000);
      await poll();
      await screen.findByText("Gated content");

      expect(mounts).toBe(2);
      expect(listFeatureFlagsMock).toHaveBeenCalledTimes(4);
    });

    it("reopens at once when this session turns the feature back on itself", async () => {
      renderGatedPage();
      await screen.findByText("Gated content");
      await hit423();
      await waitFor(() => expect(disabledHeading()).toBeInTheDocument());

      jest.setSystemTime(T0 + 5_000);
      useFeatureFlagStore.getState().clearFeatureLock("PQC_READINESS");
      await poll();

      await screen.findByText("Gated content");
    });
  });
});
