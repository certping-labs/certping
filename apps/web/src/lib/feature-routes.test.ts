// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  FEATURE_ROUTE_RULES,
  findFeatureRouteRule,
  isRouteFeatureOn,
  resolveRouteAvailability,
  type RouteFlagContext,
} from "@/lib/feature-routes";

/** A loaded flag set with exactly these keys on. */
const enabledOnly = (
  ...keys: string[]
): RouteFlagContext & { asSuperAdmin: () => RouteFlagContext } => {
  const context: RouteFlagContext = {
    status: "ready",
    effectiveMap: Object.fromEntries(keys.map((key) => [key, true])),
    isSuperAdmin: false,
  };
  return {
    ...context,
    asSuperAdmin: () => ({ ...context, isSuperAdmin: true }),
  };
};

/** A super admin signed in without an organization: org flags do not apply. */
const noOrgSuperAdmin: RouteFlagContext = {
  status: "not-applicable",
  effectiveMap: {},
  isSuperAdmin: true,
};

describe("findFeatureRouteRule", () => {
  it.each([
    ["/cert-manager/add", ["CERTIFICATE_ISSUANCE"]],
    ["/cert-manager/deployments/abc/req-1", ["CERTIFICATE_DEPLOYMENT"]],
    ["/cert-manager/discovery", ["DISCOVERY"]],
    ["/cert-manager/discovery/42", ["DISCOVERY"]],
    ["/cert-manager/rotation", ["CERTIFICATE_RENEWAL"]],
    ["/cert-manager/cryptography", ["PQC_READINESS"]],
    ["/machine-identity/devices/dev-1", ["IOT_DEVICE_MANAGEMENT"]],
    ["/machine-identity/device-certificates", ["IOT_DEVICE_MANAGEMENT"]],
    ["/machine-identity/profiles/new", ["IOT_CERTIFICATE_PROFILE_MANAGEMENT"]],
    ["/integrations/certificate-authorities/ca-1", ["IOT_DEVICE_MANAGEMENT"]],
    ["/integrations/device-sources/src-1", ["IOT_DEVICE_MANAGEMENT"]],
    ["/integrations/apps", ["INTEGRATIONS"]],
    ["/integrations/connections/add", ["CREDENTIALS_MANAGEMENT"]],
    ["/integrations/connections/cred-1/edit", ["CREDENTIALS_MANAGEMENT"]],
    [
      "/integrations/deployment-targets",
      ["CREDENTIALS_MANAGEMENT", "CERTIFICATE_DEPLOYMENT"],
    ],
    ["/incidents", ["ALERTS"]],
    ["/incidents/system-notifications", []],
  ])("maps %s to %j", (path, features) => {
    expect(findFeatureRouteRule(path)?.features).toEqual(features);
  });

  it.each([
    "/dashboard",
    "/cert-manager",
    "/cert-manager/manage/abc",
    "/settings/organization-access",
    "/settings/organizations/acme",
    "/support",
    "/integrations/certificate-authorities",
  ])("leaves %s ungated", (path) => {
    expect(findFeatureRouteRule(path)).toBeUndefined();
  });

  it("ignores the query string and hash", () => {
    expect(
      findFeatureRouteRule("/cert-manager/discovery?modal=add#top")?.features,
    ).toEqual(["DISCOVERY"]);
  });

  it("does not match a sibling that only shares a prefix", () => {
    expect(findFeatureRouteRule("/cert-managerx")).toBeUndefined();
    expect(findFeatureRouteRule("/incidentsfoo")).toBeUndefined();
  });

  it("only names known flag keys", () => {
    for (const rule of FEATURE_ROUTE_RULES) {
      for (const feature of rule.features) {
        expect(feature).toMatch(/^[A-Z_]+$/);
      }
    }
  });
});

describe("isRouteFeatureOn", () => {
  it("allows ungated routes whatever the flags say", () => {
    const pending: RouteFlagContext = {
      status: "pending",
      effectiveMap: {},
      isSuperAdmin: false,
    };
    expect(isRouteFeatureOn("/dashboard", pending)).toBe(true);
    expect(isRouteFeatureOn("/incidents/system-notifications", pending)).toBe(
      true,
    );
    expect(isRouteFeatureOn("/settings/organization-access", pending)).toBe(
      true,
    );
  });

  it("requires every key of an all-of rule", () => {
    const href = "/integrations/deployment-targets";
    expect(isRouteFeatureOn(href, enabledOnly("CREDENTIALS_MANAGEMENT"))).toBe(
      false,
    );
    expect(
      isRouteFeatureOn(
        href,
        enabledOnly("CREDENTIALS_MANAGEMENT", "CERTIFICATE_DEPLOYMENT"),
      ),
    ).toBe(true);
  });

  it("gates rotation on CERTIFICATE_RENEWAL like the renewal views it gathers", () => {
    expect(isRouteFeatureOn("/cert-manager/rotation", enabledOnly())).toBe(
      false,
    );
    expect(
      isRouteFeatureOn(
        "/cert-manager/rotation",
        enabledOnly("CERTIFICATE_RENEWAL"),
      ),
    ).toBe(true);
  });
});

describe("sessions without an organization", () => {
  it.each([
    ["/incidents", "ALERTS"],
    ["/cert-manager/discovery", "DISCOVERY"],
    ["/cert-manager/rotation", "CERTIFICATE_RENEWAL"],
    ["/machine-identity/devices", "IOT_DEVICE_MANAGEMENT"],
  ])("explains that %s needs an organization", (path, featureKey) => {
    expect(resolveRouteAvailability(path, noOrgSuperAdmin)).toEqual({
      availability: "needs-organization",
      blockingKey: featureKey,
    });
    expect(isRouteFeatureOn(path, noOrgSuperAdmin)).toBe(false);
  });

  it.each(["/settings/audit-logs", "/incidents/system-notifications"])(
    "keeps %s, which serves platform data, reachable",
    (path) => {
      expect(isRouteFeatureOn(path, noOrgSuperAdmin)).toBe(true);
    },
  );

  it("shows audit logs as not available with AUDIT_LOGS off, except to super admins", () => {
    const off = enabledOnly("CERTIFICATE_ISSUANCE");

    expect(
      resolveRouteAvailability("/settings/audit-logs", off).availability,
    ).not.toBe("on");
    expect(isRouteFeatureOn("/settings/audit-logs?view=access", off)).toBe(
      false,
    );
    // Recording never stops; a super admin reads the platform log.
    expect(isRouteFeatureOn("/settings/audit-logs", off.asSuperAdmin())).toBe(
      true,
    );
    expect(
      isRouteFeatureOn("/settings/audit-logs", enabledOnly("AUDIT_LOGS")),
    ).toBe(true);
  });

  it("never marks audit logs as needing an organization", () => {
    expect(
      findFeatureRouteRule("/settings/audit-logs")?.requiresOrganization,
    ).toBeFalsy();
  });
});
