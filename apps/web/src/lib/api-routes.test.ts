// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiRoutes } from "@/lib/api";

describe("apiRoutes path builders", () => {
  it("encodes query route parameters", () => {
    expect(apiRoutes.query.organization.organizationById("tenant/1")).toBe(
      "/api/v1/organizations/tenant%2F1",
    );
    expect(apiRoutes.query.certs.detail("cert/1")).toBe(
      "/api/v1/certs/cert%2F1",
    );
    expect(apiRoutes.query.credentials.detail("cred/1")).toBe(
      "/api/v1/credentials/cred%2F1",
    );
    expect(apiRoutes.query.users.permissions("42")).toBe(
      "/api/v1/users/42/permissions",
    );
    expect(apiRoutes.query.permissions.byResource("cert manager")).toBe(
      "/api/v1/permissions/resource/cert%20manager",
    );
    expect(apiRoutes.query.integrations.detail("1/2")).toBe(
      "/api/v1/integrations/1%2F2",
    );
    expect(apiRoutes.query.admin.passwordHashInventory).toBe(
      "/api/v1/admin/password-hash/inventory",
    );
  });

  it("encodes mutation route parameters", () => {
    expect(apiRoutes.mutation.admin.passwordHashRotate(500)).toBe(
      "/api/v1/admin/password-hash/rotate?batchSize=500",
    );
    expect(apiRoutes.mutation.certs.convertToAutomated("cert/1")).toBe(
      "/api/v1/certs/cert%2F1/convert-to-automated",
    );
    expect(apiRoutes.mutation.certs.deploy("cert/1")).toBe(
      "/api/v1/certs/cert%2F1/deploy",
    );
    expect(apiRoutes.mutation.certs.delete("101/secondary")).toBe(
      "/api/v1/user-domain-certificates/101%2Fsecondary",
    );
    expect(apiRoutes.mutation.credentials.update("cred/1")).toBe(
      "/api/v1/credentials/cred%2F1",
    );
    expect(
      apiRoutes.mutation.domainCredentialConfig.removeDeploymentTarget(
        "example.com",
        "cred/1",
      ),
    ).toBe(
      "/api/v1/certs/domains/example.com/credential-config/deployment-targets/cred%2F1",
    );
    expect(apiRoutes.mutation.users.organizationUpdate("u/1")).toBe(
      "/api/v1/users/organization/u%2F1",
    );
    expect(apiRoutes.mutation.users.assignRoles("u/1")).toBe(
      "/api/v1/users/u%2F1/roles",
    );
    expect(apiRoutes.mutation.roles.updatePermissions("r/1")).toBe(
      "/api/v1/roles/r%2F1/permissions",
    );
    expect(apiRoutes.mutation.integrations.delete("7")).toBe(
      "/api/v1/integrations/7",
    );
  });

  it("resolves every route entry to a string path", () => {
    const seenPaths: string[] = [];

    const resolve = (value: unknown) => {
      if (typeof value === "string") {
        seenPaths.push(value);
        return;
      }

      if (typeof value === "function") {
        const arity = Math.max(1, value.length);
        const args = Array.from({ length: arity }, (_, index) =>
          index === 0 ? "a/b value" : "c/d value",
        );
        const resolved = (value as (...routeArgs: string[]) => string)(...args);
        seenPaths.push(resolved);
        return;
      }

      if (value && typeof value === "object") {
        Object.values(value).forEach(resolve);
      }
    };

    resolve(apiRoutes);

    expect(seenPaths.length).toBeGreaterThan(60);
    expect(seenPaths.every((path) => typeof path === "string")).toBe(true);
    expect(seenPaths.some((path) => path.includes("%2F"))).toBe(true);
    expect(seenPaths.some((path) => path.includes("/api/v1/certs"))).toBe(true);
    expect(seenPaths.some((path) => path.includes("/api/v1/support"))).toBe(
      false,
    );
  });
});
