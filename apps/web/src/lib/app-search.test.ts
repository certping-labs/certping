// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { isRouteFeatureOn } from "@/lib/feature-routes";
import { getAppSearchItems } from "@/lib/app-search";
import { rankAppSearchItems } from "@/lib/app-search-ranking";
import type { SsoUser } from "@/types/auth";

function createUser(overrides: Partial<SsoUser> = {}): SsoUser {
  return {
    id: "user-1",
    email: "user@example.com",
    organizationId: "organization-1",
    organizationName: "Acme",
    roles: [],
    permissions: [],
    authMethod: "LOCAL",
    ...overrides,
  };
}

function titlesFor(user: SsoUser, enabledFeatures: readonly string[] = []) {
  return searchItemsFor(user, enabledFeatures).map((item) => item.title);
}

function searchItemsFor(
  user: SsoUser,
  enabledFeatures: readonly string[] = [],
) {
  return getAppSearchItems({
    isFeatureEnabled: (featureKey) => enabledFeatures.includes(featureKey),
    isRouteAvailable: (href) =>
      isRouteFeatureOn(href, {
        status: "ready",
        effectiveMap: Object.fromEntries(
          enabledFeatures.map((featureKey) => [featureKey, true]),
        ),
        isSuperAdmin: user.roles.includes("SUPER_ADMIN"),
      }),
    isSuperAdmin: user.roles.includes("SUPER_ADMIN"),
    user,
  });
}

describe("getAppSearchItems", () => {
  it("includes certificate lifecycle entries only for authorized users", () => {
    const titles = titlesFor(
      createUser({
        permissions: ["certificate:read", "certificate:issue"],
      }),
      ["CERTIFICATE_ISSUANCE", "PQC_READINESS", "DISCOVERY"],
    );

    expect(titles).toEqual(
      expect.arrayContaining([
        "Certificates",
        "Certificate Discovery",
        "PQC Readiness",
        "Issue Certificate",
      ]),
    );
  });

  it("hides Discovery when certificate discovery is off or unknown", () => {
    const certificateUser = createUser({ permissions: ["certificate:read"] });

    expect(titlesFor(certificateUser)).not.toContain("Certificate Discovery");
    expect(titlesFor(certificateUser, ["DISCOVERY"])).toContain(
      "Certificate Discovery",
    );
  });

  it("drops any result whose route the central map gates off", () => {
    const issuer = createUser({
      permissions: ["certificate:read", "certificate:issue"],
    });
    const hrefs = searchItemsFor(issuer).map((item) => item.href);

    expect(hrefs).not.toContain("/cert-manager/add");
    expect(hrefs).toContain("/cert-manager");
  });

  it("hides Cryptography when PQC readiness is off", () => {
    const certificateUser = createUser({ permissions: ["certificate:read"] });

    expect(titlesFor(certificateUser)).not.toContain("PQC Readiness");
    expect(titlesFor(certificateUser, ["PQC_READINESS"])).toContain(
      "PQC Readiness",
    );

    const beforeFlagsLoad = getAppSearchItems({
      isFeatureEnabled: () => true,
      isRouteAvailable: () => true,
      isFeatureFlagsReady: false,
      user: certificateUser,
    }).map((item) => item.title);
    expect(beforeFlagsLoad).not.toContain("PQC Readiness");
  });

  it("drops a result whose route would not render, as a backstop", () => {
    const titles = getAppSearchItems({
      isFeatureEnabled: () => true,
      isRouteAvailable: (href) =>
        isRouteFeatureOn(href, {
          status: "ready",
          effectiveMap: { DISCOVERY: false },
          isSuperAdmin: false,
        }),
      user: createUser({ permissions: ["certificate:read"] }),
    }).map((item) => item.title);

    expect(titles).toContain("Certificates");
    expect(titles).not.toContain("Certificate Discovery");
  });

  it("names the incidents entry after what it holds", () => {
    const user = createUser({ permissions: ["notifications:view"] });

    expect(titlesFor(user, ["ALERTS", "INTEGRATIONS"])).toContain(
      "Alerts & escalations",
    );
    const withoutIntegrations = searchItemsFor(user, ["ALERTS"]);
    expect(withoutIntegrations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: "Alerts",
          description: "Review alerts from your certificates.",
          href: "/incidents",
        }),
      ]),
    );
    expect(withoutIntegrations.map((item) => item.title)).not.toContain(
      "Alerts & escalations",
    );
  });

  it("keeps notifications searchable when the alerts feature is disabled", () => {
    const titles = titlesFor(
      createUser({
        permissions: ["notifications:view", "organization:manage"],
      }),
    );

    expect(titles).toContain("Notifications");
    expect(titles).not.toContain("Alerts & escalations");
  });

  it("hides the notifications list from users without organization:manage", () => {
    // The server returns 403 on /api/notifications to VIEWER and SECURITY_ANALYST.
    const titles = titlesFor(
      createUser({ permissions: ["notifications:view"] }),
      ["ALERTS"],
    );

    expect(titles).not.toContain("Notifications");
    expect(titles).toContain("Alerts");
  });

  it("offers no DNS provider shortcut while DNS credentials are off", () => {
    const titles = searchItemsFor(
      createUser({ permissions: ["credential:read", "credential:create"] }),
      ["CREDENTIALS_MANAGEMENT"],
    ).map((item) => item.title);

    expect(titles).toContain("DNS Providers");
    expect(titles).not.toContain("Connect DNS Provider");
  });
});

describe("rankAppSearchItems", () => {
  const items = searchItemsFor(
    createUser({
      permissions: [
        "certificate:read",
        "notifications:view",
        "organization:manage",
      ],
    }),
    ["ALERTS"],
  );

  it("ranks a direct title match before weaker keyword matches", () => {
    const results = rankAppSearchItems(items, "notification");

    expect(results[0]?.title).toBe("Notifications");
    expect(results.map((item) => item.title)).not.toContain(
      "Certificate Integrations",
    );
  });

  it("tolerates a small typo in a title", () => {
    expect(rankAppSearchItems(items, "notifcation")[0]?.title).toBe(
      "Notifications",
    );
  });

  it.each([
    ["cloudflare dns", "DNS Providers"],
    ["k8s", "Deployment Targets"],
    ["azure key vault", "Deployment Targets"],
  ])("maps %s to %s", (query, title) => {
    const results = rankAppSearchItems(
      searchItemsFor(
        createUser({
          permissions: ["credential:read", "credential:create"],
        }),
        ["CERTIFICATE_DEPLOYMENT", "CREDENTIALS_MANAGEMENT"],
      ),
      query,
    );

    expect(results[0]?.title).toBe(title);
  });
});
