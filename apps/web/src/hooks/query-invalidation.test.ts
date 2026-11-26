// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  invalidateAlertQueries,
  invalidateAuditQueries,
  invalidateCertificateQueries,
  invalidateCredentialQueries,
  invalidateDeploymentQueries,
  invalidateSecurityOperationsQueries,
  invalidateTeamQueries,
} from "@/hooks/query-invalidation";

describe("query-invalidation", () => {
  const createClient = () =>
    ({
      invalidateQueries: jest.fn().mockResolvedValue(undefined),
    }) as unknown as {
      invalidateQueries: jest.Mock<Promise<void>, [{ queryKey: string[] }]>;
    };

  it("invalidates audit query groups", async () => {
    const queryClient = createClient();
    await invalidateAuditQueries(queryClient as never);
    expect(queryClient.invalidateQueries).toHaveBeenCalledTimes(2);
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["audit-logs"],
    });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["audit-log-options"],
    });
  });

  it("invalidates alert, certificate, deployment, credential, and team keys", async () => {
    const queryClient = createClient();

    await invalidateAlertQueries(queryClient as never);
    await invalidateCertificateQueries(queryClient as never);
    await invalidateDeploymentQueries(queryClient as never);
    await invalidateCredentialQueries(queryClient as never);
    await invalidateTeamQueries(queryClient as never);

    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["ssl-alerts"],
    });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["ssl-cert-list"],
    });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["deployments"],
    });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["credentials"],
    });
    expect(queryClient.invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["users"],
    });
  });

  it("invalidates security operations by composing audit + alert invalidations", async () => {
    const queryClient = createClient();
    await invalidateSecurityOperationsQueries(queryClient as never);
    expect(queryClient.invalidateQueries).toHaveBeenCalledTimes(5);
  });
});
