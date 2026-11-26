// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { z } from "zod";

import type { AwsAcmAuthMode } from "@/lib/credential-config-schemas/aws-acm";
import type { AwsApiGwAuthMode } from "@/lib/credential-config-schemas/aws-api-gateway";
import type { AwsCloudFrontAuthMode } from "@/lib/credential-config-schemas/aws-cloudfront";
import type { AwsLoadBalancerAuthMode } from "@/lib/credential-config-schemas/aws-load-balancer";
import type { AzureAppGwAuthMode } from "@/lib/credential-config-schemas/azure-app-gw";
import type {
  AzureAgcApiStyle,
  AzureAgcAuthMode,
  AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import type { AzureKvAuthMode } from "@/lib/credential-config-schemas/azure-kv";
import type { AzureAfdAuthMode } from "@/lib/credential-config-schemas/azure-afd";
import type { GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";

export type CredentialFormValidationValues = {
  provider?: string;
  /** "managed": CertPing stores the pasted secret for the agent; "vault": a handle or agent identity. */
  credentialStorage?: CredentialStorage;
  secretHandle?: string;
  credJson?: string;
  secretDnsAwsAccessKeyId?: string;
  secretDnsAwsSecretAccessKey?: string;
  secretDnsCloudflareApiToken?: string;
  secretDnsCloudflareZoneId?: string;
  secretDnsCertPingApiKey?: string;
  secretDnsGodaddyApiKey?: string;
  secretDnsGodaddyApiSecret?: string;
  secretDnsNamecomUsername?: string;
  secretDnsNamecomApiToken?: string;
  secretDnsHostingerApiToken?: string;
  secretDnsNamecheapApiToken?: string;
  secretDnsNamecheapUserName?: string;
  secretDnsNamecheapApiUser?: string;
  secretAwsAccessKeyId?: string;
  secretAwsSecretAccessKey?: string;
  secretAzureClientId?: string;
  secretAzureClientSecret?: string;
  secretGcpServiceAccountKeyJson?: string;
  secretCloudflareApiToken?: string;
  secretK8sApiServer?: string;
  secretK8sBearerToken?: string;
  secretK8sServiceAccountToken?: string;
  secretK8sCaCertPem?: string;
  secretK8sCaCertBase64?: string;
  secretK8sAwsRegion?: string;
  secretK8sAzureTenantId?: string;
  secretK8sAzureSubscriptionId?: string;
  secretK8sAzureResourceGroup?: string;
  secretK8sAzureClientId?: string;
  secretK8sAzureClientSecret?: string;
  secretK8sGcpProjectId?: string;
  secretK8sGcpLocation?: string;
  secretK8sGcpServiceAccountKeyJson?: string;
  secretAkamaiClientToken?: string;
  secretAkamaiAccessToken?: string;
  secretAkamaiClientSecret?: string;
  secretAkamaiContractId?: string;
  secretAkamaiCommonName?: string;
  secretAkamaiDomains?: string[];
  secretAkamaiNetwork?: string;
  secretAkamaiCertType?: string;
  secretF5Username?: string;
  secretF5Password?: string;
  awsAcmAuthMode?: AwsAcmAuthMode;
  awsAcmRegion?: string;
  awsAcmRoleArn?: string;
  awsAcmExternalId?: string;
  awsElbAuthMode?: AwsLoadBalancerAuthMode;
  awsElbRegion?: string;
  awsElbRoleArn?: string;
  awsElbExternalId?: string;
  awsElbListeners?: string[];
  awsApiGwAuthMode?: AwsApiGwAuthMode;
  awsApiGwRegion?: string;
  awsApiGwRoleArn?: string;
  awsApiGwExternalId?: string;
  awsApiGwCustomDomains?: string[];
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode;
  awsCloudFrontDistributionId?: string;
  awsCloudFrontRoleArn?: string;
  awsCloudFrontExternalId?: string;
  azureKvAuthMode?: AzureKvAuthMode;
  azureKvTenantId?: string;
  azureKvVaultUri?: string;
  azureKvClientId?: string;
  azureAppGwAuthMode?: AzureAppGwAuthMode;
  azureAppGwTenantId?: string;
  azureAppGwSubscriptionId?: string;
  azureAppGwClientId?: string;
  azureAppGwResourceGroup?: string;
  azureAppGwAppGateway?: string;
  azureAppGwListeners?: string[];
  azureAppGwKeyVaultUri?: string;
  azureAgcAzureAuthMode?: AzureAgcAuthMode;
  azureAgcTenantId?: string;
  azureAgcSubscriptionId?: string;
  azureAgcResourceGroup?: string;
  azureAgcClientId?: string;
  azureAgcClusterAuthMode?: AzureAgcClusterAuthMode;
  azureAgcClusterName?: string;
  azureAgcNamespace?: string;
  azureAgcApiStyle?: AzureAgcApiStyle;
  azureAgcSecretNamespaces?: string[];
  azureAfdAuthMode?: AzureAfdAuthMode;
  azureAfdTenantId?: string;
  azureAfdSubscriptionId?: string;
  azureAfdClientId?: string;
  azureAfdResourceGroup?: string;
  azureAfdProfileName?: string;
  azureAfdKeyVaultUri?: string;
  azureAfdCustomDomains?: string[];
  k8sAuthMethod?: string;
  k8sClusterName?: string;
  k8sNamespaceMode?: "explicit" | "all_namespaces";
  k8sNamespaces?: string[];
  gcpAuthMode?: GcpAuthMode;
  gcpProjectId?: string;
  gcpLocation?: string;
  gcpImpersonateServiceAccount?: string;
  gcpCertManagerCertificateMap?: string;
  gcpProxyTargetHttpsProxy?: string;
  gcpProxyTargetSslProxy?: string;

  // Cloudflare Edge
  cloudflareZoneId?: string;

  // Akamai CPS
  akamaiHost?: string;
  akamaiEnrollmentId?: string;

  // F5 BIG-IP
  f5BigipHost?: string;
  f5BigipPartition?: string;
  f5BigipClientSslProfiles?: string[];
};

export type SchemaRefinementContext = z.RefinementCtx;

export type CredentialStorage = "managed" | "vault";
