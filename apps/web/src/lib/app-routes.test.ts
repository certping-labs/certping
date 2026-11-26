// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { getDefaultAuthorizedRoute } from "@/lib/app-routes";
import type { SsoUser } from "@/types/auth";

function createUser(overrides: Partial<SsoUser>): SsoUser {
  return {
    id: "user-1",
    email: "user@example.com",
    organizationId: null,
    organizationName: null,
    roles: [],
    permissions: [],
    authMethod: "LOCAL",
    ...overrides,
  };
}

const allEnabled = () => true;
const allDisabled = () => false;

describe("getDefaultAuthorizedRoute", () => {
  describe("super admin", () => {
    const superAdmin = createUser({
      roles: ["SUPER_ADMIN"],
      permissions: ["organization:view", "organization:manage"],
    });

    it("routes to the organizations tab regardless of feature flags", () => {
      expect(getDefaultAuthorizedRoute(superAdmin, true, allEnabled)).toBe(
        "/settings/organization-access?tab=organization",
      );
      expect(getDefaultAuthorizedRoute(superAdmin, true, allDisabled)).toBe(
        "/settings/organization-access?tab=organization",
      );
    });
  });

  describe("organization admin with full permissions", () => {
    // User is scoped to an org but does not hold the ORGANIZATION_ADMIN role or
    // organization management permissions, so canViewOrganizations() returns false
    // and the routing logic falls through to the feature-flag-gated paths.
    const orgUser = createUser({
      organizationId: "org-123",
      organizationName: "Acme",
      roles: [],
      permissions: [
        "certificate:read",
        "certificate:issue",
        "notifications:view",
      ],
    });

    // Same org context, but lacks certificate:read so the dashboard route is not eligible.
    // Used to exercise the fallback paths to /incidents and the account tab.
    const orgUserNoCert = createUser({
      organizationId: "org-123",
      organizationName: "Acme",
      roles: [],
      permissions: ["notifications:view"],
    });

    it("routes to /dashboard whenever the user can view certificates (CERTIFICATE_ISSUANCE no longer gates the dashboard)", () => {
      // Flag on → /dashboard
      expect(
        getDefaultAuthorizedRoute(
          orgUser,
          false,
          (key) => key === "CERTIFICATE_ISSUANCE",
        ),
      ).toBe("/dashboard");
      // Flag off → /dashboard (issuance flag is irrelevant to viewing)
      expect(getDefaultAuthorizedRoute(orgUser, false, allDisabled)).toBe(
        "/dashboard",
      );
    });

    it("prefers the dashboard over organization settings for organization admins", () => {
      expect(
        getDefaultAuthorizedRoute(
          createUser({
            organizationId: "org-123",
            roles: ["ORGANIZATION_ADMIN"],
            permissions: ["certificate:read", "organization:view"],
          }),
          false,
          allEnabled,
        ),
      ).toBe("/dashboard");
    });

    it("routes to /incidents when user can't view certs but ALERTS is on and they can view notifications", () => {
      expect(
        getDefaultAuthorizedRoute(
          orgUserNoCert,
          false,
          (key) => key === "ALERTS",
        ),
      ).toBe("/incidents");
    });

    it("routes notification users to notifications when ALERTS is disabled", () => {
      const orgManagerNoCert = createUser({
        organizationId: "org-123",
        organizationName: "Acme",
        roles: [],
        permissions: ["notifications:view", "organization:manage"],
      });
      expect(
        getDefaultAuthorizedRoute(orgManagerNoCert, false, allDisabled),
      ).toBe("/incidents/system-notifications");
    });

    it("does not route to the notifications list without organization:manage", () => {
      expect(
        getDefaultAuthorizedRoute(orgUserNoCert, false, allDisabled),
      ).not.toBe("/incidents/system-notifications");
    });

    it("routes to /dashboard when isEnabled is not provided (default fail-open)", () => {
      expect(getDefaultAuthorizedRoute(orgUser, false)).toBe("/dashboard");
    });
  });

  describe("user with no permissions and no org context", () => {
    const noopUser = createUser({});

    it("returns the account tab as the ultimate fallback", () => {
      expect(getDefaultAuthorizedRoute(noopUser, false, allEnabled)).toBe(
        "/settings/organization-access?tab=account",
      );
    });

    it("returns the account tab even with no isEnabled provided", () => {
      expect(getDefaultAuthorizedRoute(noopUser, false)).toBe(
        "/settings/organization-access?tab=account",
      );
    });
  });

  describe("null/undefined user", () => {
    it("returns the account tab for a null user", () => {
      expect(getDefaultAuthorizedRoute(null, false, allEnabled)).toBe(
        "/settings/organization-access?tab=account",
      );
    });

    it("returns the account tab for an undefined user", () => {
      expect(getDefaultAuthorizedRoute(undefined, false, allEnabled)).toBe(
        "/settings/organization-access?tab=account",
      );
    });
  });
});
