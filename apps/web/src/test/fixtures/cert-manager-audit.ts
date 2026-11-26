// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The server's audit page JSON, copied verbatim from its contract test's
 * golden file (`apps/server/src/test/resources/audit/audit-log-page.golden.json`).
 * Keep the two in step: a change there is a change to what this app parses.
 */
export const CERT_MANAGER_AUDIT_GOLDEN_PAGE = {
  content: [
    {
      id: 9004,
      userId: 42,
      userEmail: "alice@acme.test",
      organizationId: 7,
      organizationName: "Acme",
      action: "DELETE",
      resource: "CREDENTIAL",
      resourceId: null,
      status: "SUCCESS",
      details: '{"attributes":{"credentialType":"DNS"}}',
      ipAddress: "203.0.113.7",
      timestamp: "2026-10-07T11:59:00.123456Z",
      event: "credential.deleted",
      summary: "Deleted the Azure credential 'prod-dns'",
      resourceName: "prod-dns",
      actorType: "USER",
      actorName: "Alice Admin",
      errorCode: null,
      requestId: "req-4",
      correlationId: "corr-4",
      changes: [],
      category: "CREDENTIALS",
      resourceRef: "cred_8f2k",
      reason: null,
      userAgent: "Mozilla/5.0",
      featureOff: true,
      requestedByName: null,
    },
    {
      id: 9003,
      userId: 42,
      userEmail: "alice@acme.test",
      organizationId: 7,
      organizationName: "Acme",
      action: "USER_ROLES_CHANGED",
      resource: "USER",
      resourceId: 51,
      status: "SUCCESS",
      details:
        '{"attributes":{"added":"ADMIN","removed":"VIEWER"},"changes":[{"field":"roles","before":"VIEWER","after":"ADMIN"}]}',
      ipAddress: "203.0.113.7",
      timestamp: "2026-10-07T11:00:00Z",
      event: "member.roles_changed",
      summary: "Changed Bob Builder's roles",
      resourceName: "Bob Builder",
      actorType: "USER",
      actorName: "Alice Admin",
      errorCode: null,
      requestId: "req-3",
      correlationId: null,
      changes: [
        {
          field: "roles",
          before: "VIEWER",
          after: "ADMIN",
        },
      ],
      category: "ACCESS_CONTROL",
      resourceRef: "51",
      reason: null,
      userAgent: null,
      featureOff: false,
      requestedByName: null,
    },
    {
      id: 9002,
      userId: null,
      userEmail: null,
      organizationId: 7,
      organizationName: "Acme",
      action: "ACCOUNT_LOCK",
      resource: "USER",
      resourceId: 77,
      status: "SUCCESS",
      details: '{"attributes":{"attempts":"5"}}',
      ipAddress: null,
      timestamp: "2026-10-07T10:00:00Z",
      event: "auth.account_locked",
      summary: "A former member's account was locked after 5 failed sign-ins",
      resourceName: null,
      actorType: "SYSTEM",
      actorName: "CertPing (automatic)",
      errorCode: null,
      requestId: null,
      correlationId: "corr-2",
      changes: [],
      category: "AUTHENTICATION",
      resourceRef: "77",
      reason: null,
      userAgent: null,
      featureOff: false,
      requestedByName: null,
    },
    {
      id: 9001,
      userId: 43,
      userEmail: null,
      organizationId: 7,
      organizationName: "Acme",
      action: "CREATE",
      resource: "CREDENTIAL",
      resourceId: null,
      status: "FAILURE",
      details: null,
      ipAddress: "198.51.100.9",
      timestamp: "2026-10-07T09:00:00Z",
      event: "credential.created",
      summary: "Could not add the Azure credential 'staging-dns'",
      resourceName: "staging-dns",
      actorType: "USER",
      actorName: "Former member",
      errorCode: "PERMISSION_DENIED",
      requestId: "req-1",
      correlationId: null,
      changes: [],
      category: "CREDENTIALS",
      resourceRef: null,
      reason: "You don't have permission to do this.",
      userAgent: null,
      featureOff: true,
      requestedByName: null,
    },
  ],
  number: 0,
  size: 4,
  totalElements: 57,
  totalPages: 15,
  first: true,
  last: false,
  numberOfElements: 4,
  empty: false,
  totalElementsCapped: false,
  nextCursor:
    "eyJ0IjoiMjAyNi0xMC0wN1QwOTowMDowMFoiLCJpIjo5MDAxLCJuIjoxLCJjIjo1NywieCI6ZmFsc2UsImEiOmZhbHNlfQ",
  visibleFrom: "2026-07-09T12:00:00Z",
};

type GoldenEntry = (typeof CERT_MANAGER_AUDIT_GOLDEN_PAGE)["content"][number];

/** One golden entry (by id) with overrides. */
export const certManagerAuditEntry = (
  id: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => {
  const entry = CERT_MANAGER_AUDIT_GOLDEN_PAGE.content.find(
    (candidate: GoldenEntry) => candidate.id === id,
  );
  if (!entry) {
    throw new Error(`No golden audit entry ${id}`);
  }
  return { ...entry, ...overrides };
};

/** A page of entries in the server's shape, last unless a cursor is given. */
export const certManagerAuditPage = (
  content: readonly Record<string, unknown>[],
  overrides: Record<string, unknown> = {},
) => ({
  content,
  number: 0,
  size: 25,
  totalElements: content.length,
  totalPages: 1,
  first: true,
  last: true,
  numberOfElements: content.length,
  empty: content.length === 0,
  totalElementsCapped: false,
  nextCursor: null,
  visibleFrom: CERT_MANAGER_AUDIT_GOLDEN_PAGE.visibleFrom,
  ...overrides,
});

/** `/api/v1/audit-logs/categories` for an organization with Discovery off. */
export const CERT_MANAGER_AUDIT_CATEGORIES = [
  {
    key: "ACCESS_CONTROL",
    label: "Access control",
    featureKey: null,
    enabled: true,
  },
  {
    key: "CREDENTIALS",
    label: "Credentials",
    featureKey: "CREDENTIALS_MANAGEMENT",
    enabled: true,
  },
  {
    key: "DISCOVERY",
    label: "Discovery",
    featureKey: "CERTIFICATE_DISCOVERY",
    enabled: false,
  },
];
