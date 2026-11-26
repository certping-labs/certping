// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { http, HttpResponse, type RequestHandler } from "msw";

import { CLIENT_LOG_PATH } from "@/lib/logger/client-log-path";

import {
  CERT_MANAGER_AUDIT_CATEGORIES,
  CERT_MANAGER_AUDIT_GOLDEN_PAGE,
} from "@/test/fixtures/cert-manager-audit";

export const mswHandlers: RequestHandler[] = [
  http.post(CLIENT_LOG_PATH, () => HttpResponse.json({}, { status: 200 })),
];

const API = process.env.NEXT_PUBLIC_API_URL ?? "";

export interface CertManagerAuditScenario {
  /** The list's answer; the golden page by default. */
  page?: unknown;
  /** Whether the export, Access and platform routes answer. */
  b2b?: boolean;
  members?: unknown;
  /** Every request the handlers saw, as its URL. */
  seen?: URL[];
}

/**
 * The server's audit routes for a page test. Without `b2b` the export,
 * Access and platform routes answer 404, as on a server without them.
 */
export const certManagerAuditHandlers = ({
  page = CERT_MANAGER_AUDIT_GOLDEN_PAGE,
  b2b = false,
  members = [],
  seen = [],
}: CertManagerAuditScenario = {}): RequestHandler[] => {
  const record = (request: Request) => {
    seen.push(new URL(request.url));
  };
  const notYet = () => HttpResponse.json({ status: 404 }, { status: 404 });
  const b2bRoute =
    (respond: () => Response) => (info: { request: Request }) => {
      record(info.request);
      return b2b ? respond() : notYet();
    };
  return [
    http.get(`${API}/api/v1/audit-logs`, ({ request }) => {
      record(request);
      return HttpResponse.json(page as Record<string, unknown>);
    }),
    http.get(`${API}/api/v1/audit-logs/categories`, ({ request }) => {
      record(request);
      return HttpResponse.json(CERT_MANAGER_AUDIT_CATEGORIES);
    }),
    http.get(`${API}/api/v1/users/organization`, ({ request }) => {
      record(request);
      return HttpResponse.json(members as unknown[]);
    }),
    http.get(
      `${API}/api/v1/audit-logs/export`,
      b2bRoute(
        () =>
          new HttpResponse("timestamp,summary\n", {
            headers: { "Content-Type": "text/csv" },
          }),
      ),
    ),
    http.get(
      `${API}/api/v1/audit-logs/access/activities`,
      b2bRoute(() => HttpResponse.json(["access.audit_log_exported"])),
    ),
    http.get(
      `${API}/api/v1/audit-logs/access`,
      b2bRoute(() =>
        HttpResponse.json({
          content: [],
          totalElements: 0,
          totalPages: 0,
          totalElementsCapped: false,
          nextCursor: null,
        }),
      ),
    ),
    http.get(
      `${API}/api/v1/admin/audit-logs`,
      b2bRoute(() => HttpResponse.json(page as Record<string, unknown>)),
    ),
    http.get(
      `${API}/api/v1/admin/audit-logs/categories`,
      b2bRoute(() => HttpResponse.json(CERT_MANAGER_AUDIT_CATEGORIES)),
    ),
    http.get(`${API}/api/v1/organizations`, ({ request }) => {
      record(request);
      return HttpResponse.json([{ id: 7, name: "Acme" }]);
    }),
  ];
};
