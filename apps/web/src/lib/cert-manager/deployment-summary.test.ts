// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  deploymentSummaryMetrics,
  sortFailuresFirst,
} from "@/lib/cert-manager/deployment-summary";
import type { UserDomainCertificateDeploymentSummary } from "@/types/cert-manager";

const summary = (
  domain: string,
  requested: number,
  succeeded: number,
  failed: number,
) =>
  ({
    domain,
    deploymentsRequested: requested,
    deploymentsSucceeded: succeeded,
    deploymentsFailed: failed,
  }) as UserDomainCertificateDeploymentSummary;

describe("deployment summary", () => {
  const rows = [
    summary("a.com", 3, 3, 0),
    summary("b.com", 4, 3, 1),
    summary("c.com", 1, 0, 0),
    summary("d.com", 9, 6, 3),
  ];

  it("puts the domains with the most failures first and keeps the rest in order", () => {
    expect(sortFailuresFirst(rows).map((row) => row.domain)).toEqual([
      "d.com",
      "b.com",
      "a.com",
      "c.com",
    ]);
  });

  it("counts healthy domains only when something succeeded and nothing failed", () => {
    expect(deploymentSummaryMetrics(rows)).toEqual({
      domains: 4,
      totalRequests: 17,
      healthyDomains: 1,
      domainsWithFailures: 2,
    });
  });
});
