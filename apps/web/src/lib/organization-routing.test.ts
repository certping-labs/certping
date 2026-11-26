// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getOrganizationDetailHref,
  getOrganizationSlug,
} from "@/lib/organization-routing";
import type { Organization } from "@/types/auth";

function createOrganization(
  overrides: Partial<Organization> = {},
): Organization {
  return {
    id: 1,
    name: "Acme Inc",
    slug: "acme",
    ...overrides,
  };
}

describe("organization-routing", () => {
  const originalAppUrl = process.env.NEXT_PUBLIC_APP_URL;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");

  afterEach(() => {
    process.env.NEXT_PUBLIC_APP_URL = originalAppUrl;
    if (originalWindow) {
      Object.defineProperty(globalThis, "window", originalWindow);
    } else {
      Reflect.deleteProperty(globalThis, "window");
    }
  });

  describe("getOrganizationSlug", () => {
    it("returns trimmed explicit slug", () => {
      expect(
        getOrganizationSlug(createOrganization({ slug: "  org-slug  " })),
      ).toBe("org-slug");
    });

    it("throws when slug is missing or blank", () => {
      expect(() =>
        getOrganizationSlug(createOrganization({ slug: "" })),
      ).toThrow("Organization slug is required for Acme Inc");
      expect(() =>
        getOrganizationSlug(
          createOrganization({ slug: "   ", name: "Contoso" }),
        ),
      ).toThrow("Organization slug is required for Contoso");
    });
  });

  describe("href helpers", () => {
    it("builds the organization detail route with an encoded slug", () => {
      const organization = createOrganization({ slug: "org/test" });
      expect(getOrganizationDetailHref(organization)).toBe(
        "/settings/organizations/org%2Ftest",
      );
    });
  });
});
