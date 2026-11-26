// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { AwsAcmAuthMode } from "@/lib/credential-config-schemas/aws-acm";
import type { AwsApiGwAuthMode } from "@/lib/credential-config-schemas/aws-api-gateway";
import type { AwsCloudFrontAuthMode } from "@/lib/credential-config-schemas/aws-cloudfront";
import type { AwsLoadBalancerAuthMode } from "@/lib/credential-config-schemas/aws-load-balancer";
import type { AzureAgcAuthMode } from "@/lib/credential-config-schemas/azure-agc";
import type { AzureAfdAuthMode } from "@/lib/credential-config-schemas/azure-afd";
import type { AzureAppGwAuthMode } from "@/lib/credential-config-schemas/azure-app-gw";
import type { AzureKvAuthMode } from "@/lib/credential-config-schemas/azure-kv";
import type { GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";

export const MANAGED_AWS_AUTH_MODES = ["STATIC_KEYS"] as const;
export const MANAGED_AZURE_AUTH_MODES = ["SERVICE_PRINCIPAL"] as const;
export const MANAGED_GCP_AUTH_MODES = ["SERVICE_ACCOUNT_KEY"] as const;

const AWS_PROVIDER_VALUES = new Set([
  "AWS_ACM",
  "AWS_ALB",
  "AWS_NLB",
  "AWS_API_GW_REST",
  "AWS_API_GW_HTTP",
  "AWS_CLOUDFRONT",
]);
const AZURE_PROVIDER_VALUES = new Set([
  "AZURE_KV",
  "AZURE_APP_GW",
  "AZURE_APP_GW_CONTAINERS",
  "AZURE_AFD",
]);
const GCP_PROVIDER_VALUES = new Set([
  "GCP_CERT_MANAGER",
  "GCP_ALB",
  "GCP_API_GW",
  "GCP_CLOUD_CDN",
  "GCP_PROXY_NLB",
]);

const MANAGED_AUTH_MODE_ERROR_MESSAGES = {
  aws: "Credentials stored in CertPing only support AWS static keys.",
  azure:
    "Credentials stored in CertPing only support Azure service principal auth.",
  gcp: "Credentials stored in CertPing only support GCP service account key auth.",
} as const;

type DeploymentAuthMode =
  | AwsAcmAuthMode
  | AwsApiGwAuthMode
  | AwsCloudFrontAuthMode
  | AwsLoadBalancerAuthMode
  | AzureAgcAuthMode
  | AzureAfdAuthMode
  | AzureAppGwAuthMode
  | AzureKvAuthMode
  | GcpAuthMode;

type AwsAuthMode =
  | AwsAcmAuthMode
  | AwsApiGwAuthMode
  | AwsCloudFrontAuthMode
  | AwsLoadBalancerAuthMode;
type AzureAuthMode =
  AzureAgcAuthMode | AzureAfdAuthMode | AzureAppGwAuthMode | AzureKvAuthMode;

export interface DeploymentCredentialAuthModeValues {
  provider?: string;
  awsAcmAuthMode?: AwsAcmAuthMode;
  awsElbAuthMode?: AwsLoadBalancerAuthMode;
  awsApiGwAuthMode?: AwsApiGwAuthMode;
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode;
  azureKvAuthMode?: AzureKvAuthMode;
  azureAppGwAuthMode?: AzureAppGwAuthMode;
  azureAgcAzureAuthMode?: AzureAgcAuthMode;
  azureAfdAuthMode?: AzureAfdAuthMode;
  gcpAuthMode?: GcpAuthMode;
}

export interface ManagedAuthModeValidationIssue {
  path: keyof DeploymentCredentialAuthModeValues;
  message: string;
}

export function normalizeDeploymentAuthModeForAppMode<
  TMode extends DeploymentAuthMode,
>(
  mode: TMode | undefined,
  fallbackMode: TMode,
  usesManagedCredentials: boolean,
): TMode {
  return usesManagedCredentials ? fallbackMode : mode || fallbackMode;
}

export function normalizeCredentialAuthModesForAppMode<
  TValues extends DeploymentCredentialAuthModeValues,
>(values: TValues, usesManagedCredentials: boolean): TValues {
  if (!usesManagedCredentials) {
    return values;
  }

  return {
    ...values,
    awsAcmAuthMode: "STATIC_KEYS",
    awsElbAuthMode: "STATIC_KEYS",
    awsApiGwAuthMode: "STATIC_KEYS",
    awsCloudFrontAuthMode: "STATIC_KEYS",
    azureKvAuthMode: "SERVICE_PRINCIPAL",
    azureAppGwAuthMode: "SERVICE_PRINCIPAL",
    azureAgcAzureAuthMode: "SERVICE_PRINCIPAL",
    azureAfdAuthMode: "SERVICE_PRINCIPAL",
    gcpAuthMode: "SERVICE_ACCOUNT_KEY",
  };
}

export function getManagedAwsAuthModes(
  usesManagedCredentials: boolean,
): readonly AwsAuthMode[] | undefined {
  return usesManagedCredentials ? MANAGED_AWS_AUTH_MODES : undefined;
}

export function getManagedAzureAuthModes(
  usesManagedCredentials: boolean,
): readonly AzureAuthMode[] | undefined {
  return usesManagedCredentials ? MANAGED_AZURE_AUTH_MODES : undefined;
}

export function getManagedGcpAuthModes(
  usesManagedCredentials: boolean,
): readonly GcpAuthMode[] | undefined {
  return usesManagedCredentials ? MANAGED_GCP_AUTH_MODES : undefined;
}

export function getManagedAuthModeValidationIssue(
  values: DeploymentCredentialAuthModeValues,
): ManagedAuthModeValidationIssue | null {
  const provider = (values.provider || "").trim().toUpperCase();

  if (AWS_PROVIDER_VALUES.has(provider)) {
    return getAwsAuthModeValidationIssue(values);
  }

  if (AZURE_PROVIDER_VALUES.has(provider)) {
    return getAzureAuthModeValidationIssue(values);
  }

  if (GCP_PROVIDER_VALUES.has(provider)) {
    return getGcpAuthModeValidationIssue(values);
  }

  return null;
}

function getAwsAuthModeValidationIssue(
  values: DeploymentCredentialAuthModeValues,
): ManagedAuthModeValidationIssue | null {
  const provider = (values.provider || "").trim().toUpperCase();
  const authModeByProvider: Record<
    string,
    [keyof DeploymentCredentialAuthModeValues, string]
  > = {
    AWS_ACM: ["awsAcmAuthMode", values.awsAcmAuthMode || "STATIC_KEYS"],
    AWS_ALB: ["awsElbAuthMode", values.awsElbAuthMode || "STATIC_KEYS"],
    AWS_NLB: ["awsElbAuthMode", values.awsElbAuthMode || "STATIC_KEYS"],
    AWS_API_GW_REST: [
      "awsApiGwAuthMode",
      values.awsApiGwAuthMode || "STATIC_KEYS",
    ],
    AWS_API_GW_HTTP: [
      "awsApiGwAuthMode",
      values.awsApiGwAuthMode || "STATIC_KEYS",
    ],
    AWS_CLOUDFRONT: [
      "awsCloudFrontAuthMode",
      values.awsCloudFrontAuthMode || "STATIC_KEYS",
    ],
  };
  const [path, mode] = authModeByProvider[provider] || [];
  if (!path || isAllowedAuthMode(mode, MANAGED_AWS_AUTH_MODES)) {
    return null;
  }

  return { path, message: MANAGED_AUTH_MODE_ERROR_MESSAGES.aws };
}

function getAzureAuthModeValidationIssue(
  values: DeploymentCredentialAuthModeValues,
): ManagedAuthModeValidationIssue | null {
  const provider = (values.provider || "").trim().toUpperCase();
  const authModeByProvider: Record<
    string,
    [keyof DeploymentCredentialAuthModeValues, string]
  > = {
    AZURE_KV: [
      "azureKvAuthMode",
      values.azureKvAuthMode || "SERVICE_PRINCIPAL",
    ],
    AZURE_APP_GW: [
      "azureAppGwAuthMode",
      values.azureAppGwAuthMode || "SERVICE_PRINCIPAL",
    ],
    AZURE_APP_GW_CONTAINERS: [
      "azureAgcAzureAuthMode",
      values.azureAgcAzureAuthMode || "SERVICE_PRINCIPAL",
    ],
    AZURE_AFD: [
      "azureAfdAuthMode",
      values.azureAfdAuthMode || "SERVICE_PRINCIPAL",
    ],
  };
  const [path, mode] = authModeByProvider[provider] || [];
  if (!path || isAllowedAuthMode(mode, MANAGED_AZURE_AUTH_MODES)) {
    return null;
  }

  return { path, message: MANAGED_AUTH_MODE_ERROR_MESSAGES.azure };
}

function getGcpAuthModeValidationIssue(
  values: DeploymentCredentialAuthModeValues,
): ManagedAuthModeValidationIssue | null {
  const mode = values.gcpAuthMode || "SERVICE_ACCOUNT_KEY";
  if (isAllowedAuthMode(mode, MANAGED_GCP_AUTH_MODES)) {
    return null;
  }

  return {
    path: "gcpAuthMode",
    message: MANAGED_AUTH_MODE_ERROR_MESSAGES.gcp,
  };
}

function isAllowedAuthMode(
  mode: string,
  allowedModes: readonly string[],
): boolean {
  return allowedModes.includes(mode);
}
