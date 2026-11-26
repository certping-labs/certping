// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { UserDomainCertificateDeploymentSummary } from "@/types/cert-manager";

export interface DeploymentSummaryMetrics {
  domains: number;
  totalRequests: number;
  healthyDomains: number;
  domainsWithFailures: number;
}

export function sortFailuresFirst(
  summaries: readonly UserDomainCertificateDeploymentSummary[],
): UserDomainCertificateDeploymentSummary[] {
  return summaries
    .map((summary, index) => ({ summary, index }))
    .sort(
      (left, right) =>
        right.summary.deploymentsFailed - left.summary.deploymentsFailed ||
        left.index - right.index,
    )
    .map(({ summary }) => summary);
}

export function deploymentSummaryMetrics(
  summaries: readonly UserDomainCertificateDeploymentSummary[],
): DeploymentSummaryMetrics {
  let totalRequests = 0;
  let healthyDomains = 0;
  let domainsWithFailures = 0;
  for (const item of summaries) {
    totalRequests += item.deploymentsRequested;
    if (item.deploymentsFailed > 0) domainsWithFailures += 1;
    else if (item.deploymentsSucceeded > 0) healthyDomains += 1;
  }
  return {
    domains: summaries.length,
    totalRequests,
    healthyDomains,
    domainsWithFailures,
  };
}
