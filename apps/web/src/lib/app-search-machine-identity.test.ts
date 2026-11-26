// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getMachineIdentitySearchItems } from "@/lib/app-search-machine-identity";
import { rankAppSearchItems } from "@/lib/app-search-ranking";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import type { AppSearchContext } from "@/lib/app-search-types";
import type { SsoUser } from "@/types/auth";

const previousAppMode = process.env.NEXT_PUBLIC_APP_MODE;

afterAll(() => {
  process.env.NEXT_PUBLIC_APP_MODE = previousAppMode;
});

function context({
  appMode = "enterprise",
  hasOrganization = true,
  enabledFlags = [
    FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT,
    FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT,
  ] as string[],
}: {
  appMode?: string;
  hasOrganization?: boolean;
  enabledFlags?: string[];
} = {}): AppSearchContext {
  process.env.NEXT_PUBLIC_APP_MODE = appMode;
  return {
    isRouteAvailable: () => true,
    isFeatureEnabled: (featureKey) => enabledFlags.includes(featureKey),
    isFeatureFlagsReady: true,
    isSuperAdmin: false,
    hasOrganization,
    user: { organizationId: hasOrganization ? "org-1" : null } as SsoUser,
  };
}

const titlesFor = (options?: Parameters<typeof context>[0]) =>
  getMachineIdentitySearchItems(context(options)).map((item) => item.title);

describe("machine identity search entries", () => {
  it("offers every Machine Identity destination when both flags are on", () => {
    expect(titlesFor()).toEqual([
      "Devices",
      "Device Certificates",
      "Certificate authorities",
      "Device sources",
      "Certificate Profiles",
      "New Certificate Profile",
    ]);
  });

  it("is absent outside the enterprise app mode", () => {
    // Offering it there would route to a page the deployment does not serve.
    expect(titlesFor({ appMode: "" })).toEqual([]);
  });

  it("is absent without an organization context", () => {
    expect(titlesFor({ hasOrganization: false })).toEqual([]);
  });

  it("separates the two backend flags that gate it", () => {
    // Devices/certificates/connectors are IOT_DEVICE_MANAGEMENT; profiles are
    // the independent IOT_CERTIFICATE_PROFILE_MANAGEMENT. Treating them as one
    // flag would surface a page whose endpoints answer 423.
    expect(
      titlesFor({ enabledFlags: [FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT] }),
    ).toEqual([
      "Devices",
      "Device Certificates",
      "Certificate authorities",
      "Device sources",
    ]);

    expect(
      titlesFor({
        enabledFlags: [FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT],
      }),
    ).toEqual(["Certificate Profiles", "New Certificate Profile"]);
  });

  it("offers nothing when the module is switched off entirely", () => {
    expect(titlesFor({ enabledFlags: [] })).toEqual([]);
  });

  it("points each entry at its real route", () => {
    const byTitle = new Map(
      getMachineIdentitySearchItems(context()).map((item) => [
        item.title,
        item.href,
      ]),
    );

    expect(byTitle.get("Devices")).toBe("/machine-identity/devices");
    expect(byTitle.get("Device Certificates")).toBe(
      "/machine-identity/device-certificates",
    );
    expect(byTitle.get("Certificate authorities")).toBe(
      "/integrations/certificate-authorities",
    );
    expect(byTitle.get("Device sources")).toBe("/integrations/device-sources");
    expect(byTitle.get("Certificate Profiles")).toBe(
      "/machine-identity/profiles",
    );
    expect(byTitle.get("New Certificate Profile")).toBe(
      "/machine-identity/profiles/new",
    );
  });
});

describe("what an operator actually types", () => {
  const items = () => getMachineIdentitySearchItems(context());

  function topResultFor(query: string): string | undefined {
    return rankAppSearchItems(items(), query)[0]?.title;
  }

  it.each([
    ["intune", "Devices"],
    ["mdm", "Devices"],
    ["iot", "Devices"],
    ["managed devices", "Devices"],
    ["scep", "Device Certificates"],
    ["ejbca", "Device Certificates"],
    ["smallstep", "Device Certificates"],
  ])("finds something for %p", (query, expected) => {
    // Nobody searches for "machine identity" - they search for the vendor,
    // the protocol, or the CA in front of them.
    const results = rankAppSearchItems(items(), query);
    expect(results.length).toBeGreaterThan(0);
    expect(results.map((item) => item.title)).toContain(expected);
  });

  it("puts the device inventory first for a bare device query", () => {
    expect(topResultFor("devices")).toBe("Devices");
  });

  it("puts profiles first for a profile query", () => {
    expect(topResultFor("certificate profile")).toBe("Certificate Profiles");
  });

  it("finds the agent-advertised categories by what they are about, not only by name", () => {
    expect(
      rankAppSearchItems(items(), "device source").map((item) => item.title),
    ).toContain("Device sources");
    // "Connectors" is retired from the UI but is still what long-time users
    // type, so both categories have to answer to it.
    expect(
      rankAppSearchItems(items(), "connectors").map((item) => item.title),
    ).toEqual(
      expect.arrayContaining(["Certificate authorities", "Device sources"]),
    );
  });
});
