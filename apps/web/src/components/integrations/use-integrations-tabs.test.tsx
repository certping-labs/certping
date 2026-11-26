// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { renderHook } from "@testing-library/react";

import { useIntegrationsTabs } from "@/components/integrations/use-integrations-tabs";

let mockFlags: Record<string, boolean> = {};
let mockPermissions: string[] = ["integrations:view", "credential:read"];

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "user-1",
      organizationId: "org-1",
      roles: ["USER"],
      permissions: mockPermissions,
    },
  }),
}));

jest.mock("@/hooks/use-feature-flags", () => ({
  useFeatureFlags: () => ({
    isEnabled: (featureKey: string) => mockFlags[featureKey] === true,
    isReady: true,
  }),
}));

const tabIds = () =>
  renderHook(() => useIntegrationsTabs()).result.current.tabs.map(
    (tab) => tab.id,
  );

describe("useIntegrationsTabs", () => {
  beforeEach(() => {
    mockPermissions = ["integrations:view", "credential:read"];
  });

  it("lists Apps while integrations are on", () => {
    mockFlags = { INTEGRATIONS: true, CREDENTIALS_MANAGEMENT: true };

    expect(tabIds()).toEqual(["apps", "dns", "certificate-authorities"]);
  });

  it("drops Apps, and keeps DNS providers, while integrations are off", () => {
    mockFlags = { CREDENTIALS_MANAGEMENT: true };

    expect(tabIds()).toEqual(["dns", "certificate-authorities"]);
  });

  it("hides Certificate authorities from a user who cannot view credentials", () => {
    mockFlags = { INTEGRATIONS: true, CREDENTIALS_MANAGEMENT: true };
    mockPermissions = ["integrations:view"];

    expect(tabIds()).not.toContain("certificate-authorities");
  });
});
