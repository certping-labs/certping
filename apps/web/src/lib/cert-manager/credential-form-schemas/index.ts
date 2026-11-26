// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";
import { usesManagedStorage } from "@/lib/cert-manager/credential-storage";

import { AWS_ACM_AUTH_MODES } from "@/lib/credential-config-schemas/aws-acm";
import { AWS_API_GW_AUTH_MODES } from "@/lib/credential-config-schemas/aws-api-gateway";
import { AWS_CLOUDFRONT_AUTH_MODES } from "@/lib/credential-config-schemas/aws-cloudfront";
import { AWS_LOAD_BALANCER_AUTH_MODES } from "@/lib/credential-config-schemas/aws-load-balancer";
import { AZURE_KV_AUTH_MODES } from "@/lib/credential-config-schemas/azure-kv";
import { AZURE_APP_GW_AUTH_MODES } from "@/lib/credential-config-schemas/azure-app-gw";
import { AZURE_AFD_AUTH_MODES } from "@/lib/credential-config-schemas/azure-afd";
import {
  AZURE_AGC_API_STYLES,
  AZURE_AGC_AUTH_MODES,
  AZURE_AGC_CLUSTER_AUTH_MODES,
} from "@/lib/credential-config-schemas/azure-agc";
import { GCP_AUTH_MODES } from "@/lib/credential-config-schemas/gcp-shared";
import { KUBERNETES_AUTH_METHODS } from "@/lib/credential-config-schemas/kubernetes-secrets";
import { getManagedAuthModeValidationIssue } from "@/lib/cert-manager/deployment-auth-mode-policy";
import {
  isAwsApiGatewayCredentialKvPathRequired,
  isAwsApiGatewayCredentialProvider,
  validateAwsApiGatewayCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/aws-api-gateway";
import {
  isAwsCloudFrontCredentialKvPathRequired,
  isAwsCloudFrontCredentialProvider,
  validateAwsCloudFrontCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/aws-cloudfront";
import {
  isAwsAcmCredentialKvPathRequired,
  isAwsAcmCredentialProvider,
  validateAwsAcmCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/aws-acm";
import {
  isAwsLoadBalancerCredentialKvPathRequired,
  isAwsLoadBalancerCredentialProvider,
  validateAwsLoadBalancerCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/aws-load-balancer";
import {
  isAzureKvCredentialKvPathRequired,
  isAzureKvCredentialProvider,
  validateAzureKvCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/azure-kv";
import {
  isAzureAppGwCredentialKvPathRequired,
  isAzureAppGwCredentialProvider,
  validateAzureAppGwCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/azure-app-gw";
import {
  isAzureAgcCredentialKvPathRequired,
  isAzureAgcCredentialProvider,
  validateAzureAgcCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/azure-agc";
import {
  isAzureAfdCredentialKvPathRequired,
  isAzureAfdCredentialProvider,
  validateAzureAfdCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/azure-afd";
import {
  isKubernetesCredentialKvPathRequired,
  isKubernetesCredentialProvider,
  validateKubernetesCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/kubernetes-secrets";
import {
  isGcpCredentialKvPathRequired,
  isGcpCredentialProvider,
  validateGcpCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/gcp";
import {
  isAkamaiCpsCredentialKvPathRequired,
  isAkamaiCpsCredentialProvider,
  validateAkamaiCpsCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/akamai-cps";
import {
  isF5BigipCredentialKvPathRequired,
  isF5BigipCredentialProvider,
  validateF5BigipCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/f5-bigip";
import {
  isCloudflareEdgeCredentialKvPathRequired,
  isCloudflareEdgeCredentialProvider,
  validateCloudflareEdgeCredentialFields,
} from "@/lib/cert-manager/credential-form-schemas/cloudflare-edge";
import type {
  CredentialFormValidationValues,
  SchemaRefinementContext,
} from "@/lib/cert-manager/credential-form-schemas/types";

const MANAGED_AZURE_SERVICE_PRINCIPAL_CLIENT_ID_RULES: Array<{
  authModeField: keyof CredentialFormValidationValues;
  clientIdField: keyof CredentialFormValidationValues;
  isProvider: (provider?: string) => boolean;
}> = [
  {
    authModeField: "azureAppGwAuthMode",
    clientIdField: "azureAppGwClientId",
    isProvider: isAzureAppGwCredentialProvider,
  },
  {
    authModeField: "azureAgcAzureAuthMode",
    clientIdField: "azureAgcClientId",
    isProvider: isAzureAgcCredentialProvider,
  },
  {
    authModeField: "azureAfdAuthMode",
    clientIdField: "azureAfdClientId",
    isProvider: isAzureAfdCredentialProvider,
  },
];

function isKvPathRequired(values: CredentialFormValidationValues): boolean {
  if (isKubernetesCredentialProvider(values.provider)) {
    return isKubernetesCredentialKvPathRequired(values);
  }
  if (isAwsAcmCredentialProvider(values.provider)) {
    return isAwsAcmCredentialKvPathRequired(values);
  }
  if (isAwsLoadBalancerCredentialProvider(values.provider)) {
    return isAwsLoadBalancerCredentialKvPathRequired(values);
  }
  if (isAwsApiGatewayCredentialProvider(values.provider)) {
    return isAwsApiGatewayCredentialKvPathRequired(values);
  }
  if (isAwsCloudFrontCredentialProvider(values.provider)) {
    return isAwsCloudFrontCredentialKvPathRequired(values);
  }
  if (isAzureKvCredentialProvider(values.provider)) {
    return isAzureKvCredentialKvPathRequired(values);
  }
  if (isAzureAppGwCredentialProvider(values.provider)) {
    return isAzureAppGwCredentialKvPathRequired(values);
  }
  if (isAzureAgcCredentialProvider(values.provider)) {
    return isAzureAgcCredentialKvPathRequired(values);
  }
  if (isAzureAfdCredentialProvider(values.provider)) {
    return isAzureAfdCredentialKvPathRequired(values);
  }
  if (isGcpCredentialProvider(values.provider)) {
    return isGcpCredentialKvPathRequired(values);
  }
  if (isCloudflareEdgeCredentialProvider(values.provider)) {
    return isCloudflareEdgeCredentialKvPathRequired();
  }
  if (isAkamaiCpsCredentialProvider(values.provider)) {
    return isAkamaiCpsCredentialKvPathRequired();
  }
  if (isF5BigipCredentialProvider(values.provider)) {
    return isF5BigipCredentialKvPathRequired();
  }
  return true;
}

function validateProviderSpecificFields(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  if (isKubernetesCredentialProvider(values.provider)) {
    validateKubernetesCredentialFields(values, context);
    return;
  }
  if (isAwsAcmCredentialProvider(values.provider)) {
    validateAwsAcmCredentialFields(values, context);
    return;
  }
  if (isAwsLoadBalancerCredentialProvider(values.provider)) {
    validateAwsLoadBalancerCredentialFields(values, context);
    return;
  }
  if (isAwsApiGatewayCredentialProvider(values.provider)) {
    validateAwsApiGatewayCredentialFields(values, context);
    return;
  }
  if (isAwsCloudFrontCredentialProvider(values.provider)) {
    validateAwsCloudFrontCredentialFields(values, context);
    return;
  }
  if (isAzureKvCredentialProvider(values.provider)) {
    validateAzureKvCredentialFields(values, context);
    return;
  }
  if (isAzureAppGwCredentialProvider(values.provider)) {
    validateAzureAppGwCredentialFields(values, context);
    return;
  }
  if (isAzureAgcCredentialProvider(values.provider)) {
    validateAzureAgcCredentialFields(values, context);
    return;
  }
  if (isAzureAfdCredentialProvider(values.provider)) {
    validateAzureAfdCredentialFields(values, context);
    return;
  }
  if (isGcpCredentialProvider(values.provider)) {
    validateGcpCredentialFields(values, context);
    return;
  }
  if (isCloudflareEdgeCredentialProvider(values.provider)) {
    validateCloudflareEdgeCredentialFields(values, context);
    return;
  }
  if (isAkamaiCpsCredentialProvider(values.provider)) {
    validateAkamaiCpsCredentialFields(values, context);
    return;
  }
  if (isF5BigipCredentialProvider(values.provider)) {
    validateF5BigipCredentialFields(values, context);
  }
}

function validateManagedDeploymentAuthModes(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  if (!usesManagedStorage(values)) {
    return;
  }

  const issue = getManagedAuthModeValidationIssue(values);
  if (issue) {
    context.addIssue({
      code: "custom",
      path: [issue.path],
      message: issue.message,
    });
  }
}

function validateManagedAzureServicePrincipalClientId(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  if (!usesManagedStorage(values)) {
    return;
  }

  const rule = MANAGED_AZURE_SERVICE_PRINCIPAL_CLIENT_ID_RULES.find(
    (candidate) => candidate.isProvider(values.provider),
  );
  if (!rule) {
    return;
  }

  const authMode = values[rule.authModeField] || "SERVICE_PRINCIPAL";
  const clientId = values[rule.clientIdField];
  if (authMode === "SERVICE_PRINCIPAL" && !String(clientId || "").trim()) {
    context.addIssue({
      code: "custom",
      path: [rule.clientIdField],
      message: "Client ID is required for Azure service principal auth.",
    });
  }
}

// The secret handle points at a secret in the org's secret store, so its shape
// depends on the active store rather than always being a URL. Accept any of the
// known handle formats and let the backend do authoritative validation.
const GCP_SECRET_MANAGER_HANDLE =
  /^projects\/[^/]+\/secrets\/[^/]+\/versions\/[^/]+$/;
const AWS_SECRETS_MANAGER_ARN =
  /^arn:aws[a-z-]*:secretsmanager:[^:]*:[^:]*:secret:.+$/;

export function isValidSecretHandle(secretHandle: string): boolean {
  // Azure Key Vault and other URL-based stores use a full secret URI.
  if (z.string().url().safeParse(secretHandle).success) {
    return true;
  }
  // GCP Secret Manager resource path, e.g.
  // projects/<project>/secrets/<name>/versions/<version|latest>.
  if (GCP_SECRET_MANAGER_HANDLE.test(secretHandle)) {
    return true;
  }
  // AWS Secrets Manager ARN, e.g.
  // arn:aws:secretsmanager:<region>:<account>:secret:<name>.
  if (AWS_SECRETS_MANAGER_ARN.test(secretHandle)) {
    return true;
  }
  return false;
}

function validateCredentialForm(
  values: CredentialFormValidationValues,
  context: SchemaRefinementContext,
): void {
  const secretHandle = (values.secretHandle || "").trim();
  if (!usesManagedStorage(values) && isKvPathRequired(values)) {
    if (!secretHandle) {
      context.addIssue({
        code: "custom",
        path: ["secretHandle"],
        message: "Secret handle is required",
      });
    } else if (!isValidSecretHandle(secretHandle)) {
      context.addIssue({
        code: "custom",
        path: ["secretHandle"],
        message: "Enter a valid secret handle",
      });
    }
  }

  validateManagedDeploymentAuthModes(values, context);
  validateManagedAzureServicePrincipalClientId(values, context);
  validateProviderSpecificFields(values, context);
}

const sharedProviderFieldShape = {
  credentialStorage: z.enum(["managed", "vault"]).optional().default("vault"),
  secretHandle: z.string().trim().optional().default(""),
  credJson: z.string().trim().optional().default(""),
  secretDnsAwsAccessKeyId: z.string().trim().optional().default(""),
  secretDnsAwsSecretAccessKey: z.string().trim().optional().default(""),
  secretDnsCloudflareApiToken: z.string().trim().optional().default(""),
  secretDnsCloudflareZoneId: z.string().trim().optional().default(""),
  secretDnsCertPingApiKey: z.string().trim().optional().default(""),
  secretDnsGodaddyApiKey: z.string().trim().optional().default(""),
  secretDnsGodaddyApiSecret: z.string().trim().optional().default(""),
  secretDnsNamecomUsername: z.string().trim().optional().default(""),
  secretDnsNamecomApiToken: z.string().trim().optional().default(""),
  secretDnsHostingerApiToken: z.string().trim().optional().default(""),
  secretDnsNamecheapApiToken: z.string().trim().optional().default(""),
  secretDnsNamecheapApiUser: z.string().trim().optional().default(""),
  secretDnsNamecheapUserName: z.string().trim().optional().default(""),
  secretAwsAccessKeyId: z.string().trim().optional().default(""),
  secretAwsSecretAccessKey: z.string().trim().optional().default(""),
  secretAzureClientId: z.string().trim().optional().default(""),
  secretAzureClientSecret: z.string().trim().optional().default(""),
  secretGcpServiceAccountKeyJson: z.string().trim().optional().default(""),
  secretCloudflareApiToken: z.string().trim().optional().default(""),
  secretK8sApiServer: z.string().trim().optional().default(""),
  secretK8sBearerToken: z.string().trim().optional().default(""),
  secretK8sServiceAccountToken: z.string().trim().optional().default(""),
  secretK8sCaCertPem: z.string().trim().optional().default(""),
  secretK8sCaCertBase64: z.string().trim().optional().default(""),
  secretK8sAwsRegion: z.string().trim().optional().default(""),
  secretK8sAzureTenantId: z.string().trim().optional().default(""),
  secretK8sAzureSubscriptionId: z.string().trim().optional().default(""),
  secretK8sAzureResourceGroup: z.string().trim().optional().default(""),
  secretK8sAzureClientId: z.string().trim().optional().default(""),
  secretK8sAzureClientSecret: z.string().trim().optional().default(""),
  secretK8sGcpProjectId: z.string().trim().optional().default(""),
  secretK8sGcpLocation: z.string().trim().optional().default(""),
  secretK8sGcpServiceAccountKeyJson: z.string().trim().optional().default(""),
  secretAkamaiClientToken: z.string().trim().optional().default(""),
  secretAkamaiAccessToken: z.string().trim().optional().default(""),
  secretAkamaiClientSecret: z.string().trim().optional().default(""),
  secretAkamaiContractId: z.string().trim().optional().default(""),
  secretAkamaiCommonName: z.string().trim().optional().default(""),
  secretAkamaiDomains: z.array(z.string().trim()).optional().default([]),
  secretAkamaiNetwork: z.string().trim().optional().default(""),
  secretAkamaiCertType: z.string().trim().optional().default(""),
  secretF5Username: z.string().trim().optional().default(""),
  secretF5Password: z.string().trim().optional().default(""),
  awsAcmAuthMode: z.enum(AWS_ACM_AUTH_MODES).optional(),
  awsAcmRegion: z.string().trim().optional().default(""),
  awsAcmRoleArn: z.string().trim().optional().default(""),
  awsAcmExternalId: z.string().trim().optional().default(""),
  awsElbAuthMode: z.enum(AWS_LOAD_BALANCER_AUTH_MODES).optional(),
  awsElbRegion: z.string().trim().optional().default(""),
  awsElbRoleArn: z.string().trim().optional().default(""),
  awsElbExternalId: z.string().trim().optional().default(""),
  awsElbListeners: z.array(z.string().trim()).optional().default([]),
  awsApiGwAuthMode: z.enum(AWS_API_GW_AUTH_MODES).optional(),
  awsApiGwRegion: z.string().trim().optional().default(""),
  awsApiGwRoleArn: z.string().trim().optional().default(""),
  awsApiGwExternalId: z.string().trim().optional().default(""),
  awsApiGwCustomDomains: z.array(z.string().trim()).optional().default([]),
  awsCloudFrontAuthMode: z.enum(AWS_CLOUDFRONT_AUTH_MODES).optional(),
  awsCloudFrontDistributionId: z.string().trim().optional().default(""),
  awsCloudFrontRoleArn: z.string().trim().optional().default(""),
  awsCloudFrontExternalId: z.string().trim().optional().default(""),
  azureKvAuthMode: z.enum(AZURE_KV_AUTH_MODES).optional(),
  azureKvTenantId: z.string().trim().optional().default(""),
  azureKvVaultUri: z.string().trim().optional().default(""),
  azureKvClientId: z.string().trim().optional().default(""),
  azureAppGwAuthMode: z.enum(AZURE_APP_GW_AUTH_MODES).optional(),
  azureAppGwTenantId: z.string().trim().optional().default(""),
  azureAppGwSubscriptionId: z.string().trim().optional().default(""),
  azureAppGwClientId: z.string().trim().optional().default(""),
  azureAppGwResourceGroup: z.string().trim().optional().default(""),
  azureAppGwAppGateway: z.string().trim().optional().default(""),
  azureAppGwListeners: z.array(z.string().trim()).optional().default([]),
  azureAppGwKeyVaultUri: z.string().trim().optional().default(""),
  azureAgcAzureAuthMode: z.enum(AZURE_AGC_AUTH_MODES).optional(),
  azureAgcTenantId: z.string().trim().optional().default(""),
  azureAgcSubscriptionId: z.string().trim().optional().default(""),
  azureAgcResourceGroup: z.string().trim().optional().default(""),
  azureAgcClientId: z.string().trim().optional().default(""),
  azureAgcClusterAuthMode: z.enum(AZURE_AGC_CLUSTER_AUTH_MODES).optional(),
  azureAgcClusterName: z.string().trim().optional().default(""),
  azureAgcNamespace: z.string().trim().optional().default(""),
  azureAgcApiStyle: z.enum(AZURE_AGC_API_STYLES).optional(),
  azureAgcSecretNamespaces: z.array(z.string().trim()).optional().default([]),
  azureAfdAuthMode: z.enum(AZURE_AFD_AUTH_MODES).optional(),
  azureAfdTenantId: z.string().trim().optional().default(""),
  azureAfdSubscriptionId: z.string().trim().optional().default(""),
  azureAfdClientId: z.string().trim().optional().default(""),
  azureAfdResourceGroup: z.string().trim().optional().default(""),
  azureAfdProfileName: z.string().trim().optional().default(""),
  azureAfdKeyVaultUri: z.string().trim().optional().default(""),
  azureAfdCustomDomains: z.array(z.string().trim()).optional().default([]),
  gcpAuthMode: z.enum(GCP_AUTH_MODES).optional(),
  gcpProjectId: z.string().trim().optional().default(""),
  gcpLocation: z.string().trim().optional().default(""),
  gcpImpersonateServiceAccount: z.string().trim().optional().default(""),
  gcpCertManagerCertificateMap: z.string().trim().optional().default(""),
  gcpProxyTargetHttpsProxy: z.string().trim().optional().default(""),
  gcpProxyTargetSslProxy: z.string().trim().optional().default(""),

  // Cloudflare Edge
  cloudflareZoneId: z.string().trim().optional().default(""),

  // Akamai CPS
  akamaiHost: z.string().trim().optional().default(""),
  akamaiEnrollmentId: z.string().trim().optional().default(""),

  // F5 BIG-IP
  f5BigipHost: z.string().trim().optional().default(""),
  f5BigipPartition: z.string().trim().optional().default(""),
  f5BigipClientSslProfiles: z
    .array(z.string().trim())
    .optional()
    .default(["clientssl-api"]),
} as const;

export const createCredentialFormSchema = z
  .object({
    type: z.enum(["DNS", "DEPLOYMENT"]),
    provider: z.string().min(1, "Select a provider"),
    description: z.string().trim().min(1, "Description is required"),
    ...sharedProviderFieldShape,
    k8sAuthMethod: z.enum(KUBERNETES_AUTH_METHODS),
    k8sClusterName: z.string().trim(),
    k8sNamespaceMode: z
      .enum(["explicit", "all_namespaces"])
      .optional()
      .default("explicit"),
    k8sNamespaces: z.array(z.string().trim()).optional().default([]),
  })
  .superRefine(validateCredentialForm);

export type CreateCredentialFormValues = z.infer<
  typeof createCredentialFormSchema
>;

export const editCredentialFormSchema = z
  .object({
    provider: z.string().optional(),
    ...sharedProviderFieldShape,
    k8sAuthMethod: z.enum(KUBERNETES_AUTH_METHODS).optional(),
    k8sClusterName: z.string().trim().optional().default(""),
    k8sNamespaceMode: z
      .enum(["explicit", "all_namespaces"])
      .optional()
      .default("explicit"),
    k8sNamespaces: z.array(z.string().trim()).optional().default([]),
  })
  .superRefine(validateCredentialForm);

export type EditCredentialFormValues = z.infer<typeof editCredentialFormSchema>;
