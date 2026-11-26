// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getManagedAuthModeValidationIssue,
  getManagedAwsAuthModes,
  getManagedAzureAuthModes,
  getManagedGcpAuthModes,
  normalizeCredentialAuthModesForAppMode,
  normalizeDeploymentAuthModeForAppMode,
} from "@/lib/cert-manager/deployment-auth-mode-policy";

describe("deployment-auth-mode-policy", () => {
  it("leaves enterprise auth mode choices unchanged", () => {
    const values = {
      provider: "AWS_ACM",
      awsAcmAuthMode: "ASSUME_ROLE" as const,
      azureKvAuthMode: "WORKLOAD_IDENTITY" as const,
      gcpAuthMode: "IMPERSONATE_SERVICE_ACCOUNT" as const,
    };

    expect(normalizeCredentialAuthModesForAppMode(values, false)).toBe(values);
    expect(
      normalizeDeploymentAuthModeForAppMode(
        values.awsAcmAuthMode,
        "STATIC_KEYS",
        false,
      ),
    ).toBe("ASSUME_ROLE");
    expect(getManagedAwsAuthModes(false)).toBeUndefined();
    expect(getManagedAzureAuthModes(false)).toBeUndefined();
    expect(getManagedGcpAuthModes(false)).toBeUndefined();
  });

  it("normalizes stored-credential cloud auth modes to supported credential-based modes", () => {
    expect(
      normalizeCredentialAuthModesForAppMode(
        {
          provider: "GCP_CERT_MANAGER",
          awsAcmAuthMode: "ASSUME_ROLE",
          azureKvAuthMode: "WORKLOAD_IDENTITY",
          gcpAuthMode: "IMPERSONATE_SERVICE_ACCOUNT",
        },
        true,
      ),
    ).toMatchObject({
      awsAcmAuthMode: "STATIC_KEYS",
      azureKvAuthMode: "SERVICE_PRINCIPAL",
      gcpAuthMode: "SERVICE_ACCOUNT_KEY",
    });
  });

  it("reports the provider-specific validation path for unsupported stored-credential modes", () => {
    expect(
      getManagedAuthModeValidationIssue({
        provider: "AWS_API_GW_REST",
        awsApiGwAuthMode: "INSTANCE_PROFILE",
      }),
    ).toEqual({
      path: "awsApiGwAuthMode",
      message: "Credentials stored in CertPing only support AWS static keys.",
    });
    expect(
      getManagedAuthModeValidationIssue({
        provider: "AZURE_AFD",
        azureAfdAuthMode: "WORKLOAD_IDENTITY",
      }),
    ).toEqual({
      path: "azureAfdAuthMode",
      message:
        "Credentials stored in CertPing only support Azure service principal auth.",
    });
    expect(
      getManagedAuthModeValidationIssue({
        provider: "GCP_ALB",
        gcpAuthMode: "WORKLOAD_IDENTITY",
      }),
    ).toEqual({
      path: "gcpAuthMode",
      message:
        "Credentials stored in CertPing only support GCP service account key auth.",
    });
  });

  it("does not report stored-credential validation issues for supported modes or other targets", () => {
    expect(
      getManagedAuthModeValidationIssue({
        provider: "AWS_ACM",
        awsAcmAuthMode: "STATIC_KEYS",
      }),
    ).toBeNull();
    expect(
      getManagedAuthModeValidationIssue({
        provider: "AZURE_KV",
        azureKvAuthMode: "SERVICE_PRINCIPAL",
      }),
    ).toBeNull();
    expect(
      getManagedAuthModeValidationIssue({
        provider: "CLOUDFLARE_EDGE",
      }),
    ).toBeNull();
  });
});
