// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import type { QueryClient } from "@tanstack/react-query";

const AUDIT_LOGS_QUERY_KEY = ["audit-logs"] as const;
// The audit page's list (Access included) and its filter options
// (`CERT_MANAGER_AUDIT_QUERY_KEY`, `CERT_MANAGER_AUDIT_OPTIONS_QUERY_KEY`).
const AUDIT_LOG_OPTIONS_QUERY_KEY = ["audit-log-options"] as const;
const CREDENTIALS_QUERY_KEY = ["credentials"] as const;
const DEPLOYMENTS_QUERY_KEY = ["deployments"] as const;
const DEPLOYMENT_SUMMARY_QUERY_KEY = ["deployment-summary"] as const;
const SYSTEM_ALERTS_QUERY_KEY = "system-alerts";
const SYSTEM_NOTIFICATIONS_QUERY_KEY = "system-notifications";
const CERTIFICATE_DETAILS_QUERY_KEY = "ssl-cert-details";
const SSL_ALERTS_QUERY_KEY = "ssl-alerts";
const SSL_LIST_QUERY_KEY = "ssl-cert-list";
const CERT_HISTORY_QUERY_KEY = "ssl-cert-history";
const USERS_QUERY_KEY = "users";
const ROLES_QUERY_KEY = "roles";
const PERMISSIONS_QUERY_KEY = "permissions";

export async function invalidateAuditQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: AUDIT_LOGS_QUERY_KEY }),
    queryClient.invalidateQueries({ queryKey: AUDIT_LOG_OPTIONS_QUERY_KEY }),
  ]);
}

export async function invalidateAlertQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: [SSL_ALERTS_QUERY_KEY] }),
    queryClient.invalidateQueries({ queryKey: [SYSTEM_ALERTS_QUERY_KEY] }),
    queryClient.invalidateQueries({
      queryKey: [SYSTEM_NOTIFICATIONS_QUERY_KEY],
    }),
  ]);
}

export async function invalidateCertificateQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: [SSL_LIST_QUERY_KEY] }),
    queryClient.invalidateQueries({
      queryKey: [CERTIFICATE_DETAILS_QUERY_KEY],
    }),
  ]);
}

/** Certificate list and details plus each certificate's history. */
export async function invalidateCertificateDataQueries(
  queryClient: QueryClient,
) {
  await Promise.all([
    invalidateCertificateQueries(queryClient),
    queryClient.invalidateQueries({ queryKey: [CERT_HISTORY_QUERY_KEY] }),
  ]);
}

export async function invalidateDeploymentQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: DEPLOYMENTS_QUERY_KEY }),
    queryClient.invalidateQueries({ queryKey: DEPLOYMENT_SUMMARY_QUERY_KEY }),
  ]);
}

export async function invalidateCredentialQueries(queryClient: QueryClient) {
  await queryClient.invalidateQueries({ queryKey: CREDENTIALS_QUERY_KEY });
}

export async function invalidateTeamQueries(queryClient: QueryClient) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: [USERS_QUERY_KEY] }),
    queryClient.invalidateQueries({ queryKey: [ROLES_QUERY_KEY] }),
    queryClient.invalidateQueries({ queryKey: [PERMISSIONS_QUERY_KEY] }),
  ]);
}

export async function invalidateSecurityOperationsQueries(
  queryClient: QueryClient,
) {
  await Promise.all([
    invalidateAuditQueries(queryClient),
    invalidateAlertQueries(queryClient),
  ]);
}
