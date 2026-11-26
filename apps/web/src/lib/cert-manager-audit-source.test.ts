// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  auditActorDetail,
  auditDetailFields,
  auditFailureLine,
  auditResourceField,
  certManagerAuditSource,
} from "@/lib/cert-manager-audit-source";
import type { SsoUser } from "@/types/auth";
import type { AuditTrailEntry } from "@/types/audit-trail";

const admin = (permissions: string[]): SsoUser => ({
  id: "1",
  email: "alice@acme.test",
  organizationId: "7",
  organizationName: "Acme",
  roles: ["ORGANIZATION_ADMIN"],
  permissions,
});

const entry = (overrides: Partial<AuditTrailEntry> = {}): AuditTrailEntry => ({
  id: 1,
  timestamp: "2026-10-07T09:00:00Z",
  action: "CREATE",
  summary: "Could not add the Azure credential 'staging-dns'",
  status: "SUCCESS",
  resource: "CREDENTIAL",
  actorType: "USER",
  actorName: "Alice Admin",
  changes: [],
  attributes: {},
  ...overrides,
});

const VISIBLE_FROM = new Date("2026-07-09T12:00:00Z");

describe("the cert-manager source's words", () => {
  it("says why a failure failed, and nothing for a success", () => {
    expect(
      auditFailureLine(
        entry({
          status: "FAILURE",
          reason: "You don't have permission to do this.",
        }),
      ),
    ).toBe("Failed: You don't have permission to do this.");
    expect(auditFailureLine(entry({ status: "FAILURE" }))).toBe(
      "Failed: Something went wrong.",
    );
    expect(auditFailureLine(entry())).toBeUndefined();
  });

  it("names who an automatic row acted for, or a member's email", () => {
    expect(
      auditActorDetail(
        entry({
          actorType: "SYSTEM",
          actorName: "CertPing (automatic)",
          requestedByName: "Bob Builder",
        }),
      ),
    ).toBe("requested by Bob Builder");
    expect(
      auditActorDetail(
        entry({
          actorType: "SYSTEM",
          actor: "system:trigger-renewals",
          requestedByName: "Bob Builder",
        }),
      ),
    ).toBe("trigger-renewals · requested by Bob Builder");
    expect(auditActorDetail(entry({ userEmail: "alice@acme.test" }))).toBe(
      "alice@acme.test",
    );
    expect(
      auditActorDetail(
        entry({ actorName: "alice@acme.test", userEmail: "alice@acme.test" }),
      ),
    ).toBeUndefined();
    expect(
      auditActorDetail(
        entry({ actorType: "SYSTEM", userEmail: "x@acme.test" }),
      ),
    ).toBeUndefined();
  });

  it("explains the window only to customers", () => {
    const user = admin(["audit:view"]);
    const notice = certManagerAuditSource.notice?.({
      user,
      platform: false,
      page: {
        content: [],
        totalElements: 0,
        totalPages: 0,
        totalCapped: false,
        visibleFrom: VISIBLE_FROM.toISOString(),
      },
    });

    expect(notice).toEqual({
      message: "Showing the last 90 days",
      action: {
        prompt: "Need older logs?",
        label: "Read the docs",
        href: "https://github.com/certping-labs/certping/tree/main/docs",
      },
    });
    expect(
      certManagerAuditSource.notice?.({ user, platform: true }),
    ).toBeUndefined();
  });

  it("reads the capped total as N+", () => {
    expect(certManagerAuditSource.copy.totalCapped?.("10,000", "events")).toBe(
      "10,000+ events",
    );
  });

  it("names a resource only when the row names one", () => {
    expect(auditResourceField(entry({ resource: "AUTH" }))).toBeUndefined();
    expect(
      auditResourceField(
        entry({ resourceName: "prod-dns", resourceRef: "cred_8f2k" }),
      ),
    ).toEqual({
      label: "Resource",
      value: "prod-dns",
      detail: "Credential · cred_8f2k",
    });
    expect(auditResourceField(entry({ resourceRef: "51" }))).toEqual({
      label: "Resource",
      value: "51",
      detail: "Credential",
    });
  });

  it.each([
    ["PASSWORD", "Password"],
    ["oidc", "Single sign-on (OIDC)"],
    ["GOOGLE", "Google"],
    ["PASSKEY", "Passkey"],
  ])("reads sign-in method %s as %s", (method, label) => {
    expect(
      auditDetailFields(
        entry({ event: "auth.signed_in", attributes: { method } }),
      ),
    ).toEqual([{ label: "Sign-in method", value: label }]);
  });

  it("shows no sign-in method when there is none, or off auth rows", () => {
    expect(auditDetailFields(entry({ event: "auth.signed_in" }))).toEqual([]);
    expect(
      auditDetailFields(
        entry({ event: "auth.signed_in", attributes: { method: "NONE" } }),
      ),
    ).toEqual([]);
    // api.request rows carry the HTTP method under the same name.
    expect(
      auditDetailFields(
        entry({ event: "api.request", attributes: { method: "POST" } }),
      ),
    ).toEqual([]);
  });
});
