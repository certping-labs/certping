// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useForm, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowLeftIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { FeatureDisabledPage } from "@/components/common/feature-disabled";
import {
  useCredentialReference,
  useUpdateCredential,
} from "@/hooks/credentials";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useUnsavedChangesWarning } from "@/hooks/use-unsaved-changes-warning";
import { useAgentTransport } from "@/hooks/use-deployment-mode";
import { isCertPingStoredHandle } from "@/lib/cert-manager/credential-storage";
import { getCredentialReferenceProviderOptions } from "@/lib/credential-providers";
import {
  MANAGED_CREDENTIAL_FIELD_DEFAULTS,
  CredentialFieldError,
  buildManagedCredentialJsonFromValues,
  getManagedCredentialJsonTemplate,
} from "@/lib/cert-manager/managed-credential-json";
import {
  normalizeCredentialAuthModesForAppMode,
  normalizeDeploymentAuthModeForAppMode,
} from "@/lib/cert-manager/deployment-auth-mode-policy";
import {
  getCredentialSecretPayloadTemplate,
  isCredentialKvPathRequired,
} from "@/lib/cert-manager/credential-secret-payload";
import { buildCredentialSecretStoragePayload } from "@/lib/cert-manager/credential-storage-payload";
import {
  awsCloudFrontCredentialConfigSchema,
  isAwsCloudFrontProvider,
  parseAwsCloudFrontCredentialConfig,
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import {
  KUBERNETES_ALL_NAMESPACES,
  MANAGED_KUBERNETES_AUTH_METHODS,
  KUBERNETES_SECRETS_PROVIDER,
  kubernetesCredentialConfigSchema,
  parseKubernetesCredentialConfig,
  type KubernetesAuthMethod,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  awsApiGatewayCredentialConfigSchema,
  isAwsApiGatewayProvider,
  parseAwsApiGatewayCredentialConfig,
  type AwsApiGwAuthMode,
} from "@/lib/credential-config-schemas/aws-api-gateway";
import {
  awsAcmCredentialConfigSchema,
  isAwsAcmProvider,
  parseAwsAcmCredentialConfig,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import {
  awsLoadBalancerCredentialConfigSchema,
  isAwsLoadBalancerProvider,
  parseAwsLoadBalancerCredentialConfig,
  type AwsLoadBalancerAuthMode,
} from "@/lib/credential-config-schemas/aws-load-balancer";
import {
  azureKvCredentialConfigSchema,
  isAzureKvProvider,
  parseAzureKvCredentialConfig,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import {
  azureAppGwCredentialConfigSchema,
  isAzureAppGwProvider,
  parseAzureAppGwCredentialConfig,
  type AzureAppGwAuthMode,
} from "@/lib/credential-config-schemas/azure-app-gw";
import {
  azureAgcCredentialConfigSchema,
  isAzureAgcProvider,
  parseAzureAgcCredentialConfig,
  type AzureAgcApiStyle,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import {
  azureAfdCredentialConfigSchema,
  isAzureAfdProvider,
  parseAzureAfdCredentialConfig,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import {
  akamaiCpsCredentialConfigSchema,
  isAkamaiCpsProvider,
  parseAkamaiCpsCredentialConfig,
} from "@/lib/credential-config-schemas/akamai-cps";
import {
  cloudflareEdgeCredentialConfigSchema,
  isCloudflareEdgeProvider,
  parseCloudflareEdgeCredentialConfig,
} from "@/lib/credential-config-schemas/cloudflare-edge";
import {
  f5BigipCredentialConfigSchema,
  isF5BigipProvider,
  parseF5BigipCredentialConfig,
} from "@/lib/credential-config-schemas/f5-bigip";
import {
  gcpCertManagerCredentialConfigSchema,
  isGcpCertManagerProvider,
  parseGcpCertManagerCredentialConfig,
} from "@/lib/credential-config-schemas/gcp-cert-manager";
import {
  gcpProxyCredentialConfigSchema,
  isGcpProxyProvider,
  parseGcpProxyCredentialConfig,
} from "@/lib/credential-config-schemas/gcp-proxy";
import { type GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";
import { CredentialPageActions } from "@/components/cert-manager/credentials/credential-page-actions";
import { connectionsListHref } from "@/lib/integrations/routes";
import { ManagedCredentialFields } from "@/components/cert-manager/credentials/managed-credential-fields";
import { CredentialProviderInfoDialog } from "@/components/cert-manager/credentials/credential-provider-info-dialog";
import { CredentialSelectedProviderBanner } from "@/components/cert-manager/credentials/credential-selected-provider-banner";
import { CredentialSecretPayloadCard } from "@/components/cert-manager/credentials/credential-secret-payload-card";
import { CredentialProviderFields } from "@/components/cert-manager/credentials/providers/provider-fields";
import {
  type EditCredentialFormValues,
  editCredentialFormSchema,
} from "@/lib/cert-manager/credential-form-schemas";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input, NoAutofillForm } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";

type CredentialConfigPayload = string | Record<string, unknown> | undefined;

function findFirstFormErrorMessage(error: unknown): string | null {
  if (!error || typeof error !== "object") {
    return null;
  }

  if ("message" in error && typeof error.message === "string") {
    const message = error.message.trim();
    if (message) {
      return message;
    }
  }

  for (const value of Object.values(error)) {
    const nested = findFirstFormErrorMessage(value);
    if (nested) {
      return nested;
    }
  }

  return null;
}

function buildUpdatedConfigJson(params: {
  isKubernetesProvider: boolean;
  isAwsAcmCredential: boolean;
  isAwsLoadBalancerCredential: boolean;
  isAwsApiGatewayCredential: boolean;
  isAwsCloudFrontCredential: boolean;
  isAzureKvCredential: boolean;
  isAzureAppGwCredential: boolean;
  isAzureAgcCredential: boolean;
  isAzureAfdCredential: boolean;
  isGcpCertManagerCredential: boolean;
  isGcpProxyCredential: boolean;
  isCloudflareEdgeCredential: boolean;
  isAkamaiCpsCredential: boolean;
  isF5BigipCredential: boolean;
  values: EditCredentialFormValues;
}): CredentialConfigPayload {
  const {
    isKubernetesProvider,
    isAwsAcmCredential,
    isAwsLoadBalancerCredential,
    isAwsApiGatewayCredential,
    isAwsCloudFrontCredential,
    isAzureKvCredential,
    isAzureAppGwCredential,
    isAzureAgcCredential,
    isAzureAfdCredential,
    isGcpCertManagerCredential,
    isGcpProxyCredential,
    isCloudflareEdgeCredential,
    isAkamaiCpsCredential,
    isF5BigipCredential,
    values,
  } = params;

  if (isKubernetesProvider) {
    const namespaces =
      values.k8sNamespaceMode === "all_namespaces"
        ? KUBERNETES_ALL_NAMESPACES
        : (values.k8sNamespaces || [])
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
    return kubernetesCredentialConfigSchema.parse({
      authMethod: values.k8sAuthMethod,
      clusterName: values.k8sClusterName,
      namespaces,
    }) as Record<string, unknown>;
  }

  if (isAwsAcmCredential) {
    const authMode = (values.awsAcmAuthMode || "STATIC_KEYS") as AwsAcmAuthMode;
    return awsAcmCredentialConfigSchema.parse({
      authMode,
      region: values.awsAcmRegion,
      ...(authMode === "ASSUME_ROLE" && values.awsAcmRoleArn?.trim()
        ? { roleArn: values.awsAcmRoleArn.trim() }
        : {}),
      ...(authMode === "ASSUME_ROLE" && values.awsAcmExternalId?.trim()
        ? { externalId: values.awsAcmExternalId.trim() }
        : {}),
    }) as Record<string, unknown>;
  }

  if (isAwsLoadBalancerCredential) {
    const authMode = (values.awsElbAuthMode ||
      "STATIC_KEYS") as AwsLoadBalancerAuthMode;
    const listeners = (values.awsElbListeners || [])
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    return awsLoadBalancerCredentialConfigSchema.parse({
      authMode,
      region: values.awsElbRegion,
      ...(authMode === "ASSUME_ROLE" && values.awsElbRoleArn?.trim()
        ? { roleArn: values.awsElbRoleArn.trim() }
        : {}),
      ...(authMode === "ASSUME_ROLE" && values.awsElbExternalId?.trim()
        ? { externalId: values.awsElbExternalId.trim() }
        : {}),
      listeners,
    }) as Record<string, unknown>;
  }

  if (isAwsApiGatewayCredential) {
    const authMode = (values.awsApiGwAuthMode ||
      "STATIC_KEYS") as AwsApiGwAuthMode;
    const customDomains = (values.awsApiGwCustomDomains || [])
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    return awsApiGatewayCredentialConfigSchema.parse({
      authMode,
      region: values.awsApiGwRegion,
      ...(authMode === "ASSUME_ROLE" && values.awsApiGwRoleArn?.trim()
        ? { roleArn: values.awsApiGwRoleArn.trim() }
        : {}),
      ...(authMode === "ASSUME_ROLE" && values.awsApiGwExternalId?.trim()
        ? { externalId: values.awsApiGwExternalId.trim() }
        : {}),
      customDomains,
    }) as Record<string, unknown>;
  }

  if (isAwsCloudFrontCredential) {
    const authMode = (values.awsCloudFrontAuthMode ||
      "STATIC_KEYS") as AwsCloudFrontAuthMode;
    return awsCloudFrontCredentialConfigSchema.parse({
      authMode,
      distributionId: values.awsCloudFrontDistributionId,
      ...(authMode === "ASSUME_ROLE" && values.awsCloudFrontRoleArn?.trim()
        ? { roleArn: values.awsCloudFrontRoleArn.trim() }
        : {}),
      ...(authMode === "ASSUME_ROLE" && values.awsCloudFrontExternalId?.trim()
        ? { externalId: values.awsCloudFrontExternalId.trim() }
        : {}),
    }) as Record<string, unknown>;
  }

  if (isAzureKvCredential) {
    return azureKvCredentialConfigSchema.parse({
      authMode: (values.azureKvAuthMode ||
        "SERVICE_PRINCIPAL") as AzureKvAuthMode,
      tenantId: values.azureKvTenantId?.trim() || "",
      vaultUri: values.azureKvVaultUri,
      ...(values.azureKvClientId?.trim()
        ? { clientId: values.azureKvClientId.trim() }
        : {}),
    }) as Record<string, unknown>;
  }

  if (isAzureAppGwCredential) {
    const listeners = (values.azureAppGwListeners || [])
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    return azureAppGwCredentialConfigSchema.parse({
      authMode: (values.azureAppGwAuthMode ||
        "SERVICE_PRINCIPAL") as AzureAppGwAuthMode,
      tenantId: values.azureAppGwTenantId,
      subscriptionId: values.azureAppGwSubscriptionId,
      ...(values.azureAppGwClientId?.trim()
        ? { clientId: values.azureAppGwClientId.trim() }
        : {}),
      resourceGroup: values.azureAppGwResourceGroup,
      appGateway: values.azureAppGwAppGateway,
      listeners,
      keyVaultUri: values.azureAppGwKeyVaultUri,
    }) as Record<string, unknown>;
  }

  if (isAzureAgcCredential) {
    const secretNamespaces = (values.azureAgcSecretNamespaces || [])
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    return azureAgcCredentialConfigSchema.parse({
      azureAuthMode: (values.azureAgcAzureAuthMode ||
        "SERVICE_PRINCIPAL") as AzureAgcAuthMode,
      tenantId: values.azureAgcTenantId,
      subscriptionId: values.azureAgcSubscriptionId,
      resourceGroup: values.azureAgcResourceGroup,
      ...(values.azureAgcClientId?.trim()
        ? { clientId: values.azureAgcClientId.trim() }
        : {}),
      clusterAuthMode: (values.azureAgcClusterAuthMode ||
        "AZURE") as AzureAgcClusterAuthMode,
      clusterName: values.azureAgcClusterName,
      agcNamespace: values.azureAgcNamespace,
      apiStyle: (values.azureAgcApiStyle || "GATEWAY_API") as AzureAgcApiStyle,
      secretNamespaces,
    }) as Record<string, unknown>;
  }

  if (isAzureAfdCredential) {
    const customDomains = (values.azureAfdCustomDomains || [])
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    return azureAfdCredentialConfigSchema.parse({
      authMode: (values.azureAfdAuthMode ||
        "SERVICE_PRINCIPAL") as AzureAfdAuthMode,
      tenantId: values.azureAfdTenantId,
      subscriptionId: values.azureAfdSubscriptionId,
      ...(values.azureAfdClientId?.trim()
        ? { clientId: values.azureAfdClientId.trim() }
        : {}),
      resourceGroup: values.azureAfdResourceGroup,
      profileName: values.azureAfdProfileName,
      keyVaultUri: values.azureAfdKeyVaultUri,
      customDomains,
    }) as Record<string, unknown>;
  }

  if (isGcpCertManagerCredential) {
    const authMode = (values.gcpAuthMode ||
      "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
    return gcpCertManagerCredentialConfigSchema.parse({
      authMode,
      projectId: values.gcpProjectId,
      location: values.gcpLocation,
      ...(authMode === "IMPERSONATE_SERVICE_ACCOUNT" &&
      values.gcpImpersonateServiceAccount?.trim()
        ? {
            impersonateServiceAccount:
              values.gcpImpersonateServiceAccount.trim(),
          }
        : {}),
      ...(values.gcpCertManagerCertificateMap?.trim()
        ? { certificateMap: values.gcpCertManagerCertificateMap.trim() }
        : {}),
    }) as Record<string, unknown>;
  }

  if (isGcpProxyCredential) {
    const provider = (values.provider || "").trim().toUpperCase();
    const authMode = (values.gcpAuthMode ||
      "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
    return gcpProxyCredentialConfigSchema.parse({
      authMode,
      projectId: values.gcpProjectId,
      location: values.gcpLocation,
      ...(authMode === "IMPERSONATE_SERVICE_ACCOUNT" &&
      values.gcpImpersonateServiceAccount?.trim()
        ? {
            impersonateServiceAccount:
              values.gcpImpersonateServiceAccount.trim(),
          }
        : {}),
      ...(provider === "GCP_PROXY_NLB"
        ? { targetSslProxy: values.gcpProxyTargetSslProxy }
        : { targetProxy: values.gcpProxyTargetHttpsProxy }),
    }) as Record<string, unknown>;
  }

  if (isCloudflareEdgeCredential) {
    return cloudflareEdgeCredentialConfigSchema.parse({
      zoneId: values.cloudflareZoneId,
    }) as Record<string, unknown>;
  }

  if (isAkamaiCpsCredential) {
    return akamaiCpsCredentialConfigSchema.parse({
      host: values.akamaiHost,
      enrollmentId: values.akamaiEnrollmentId,
    }) as Record<string, unknown>;
  }

  if (isF5BigipCredential) {
    return f5BigipCredentialConfigSchema.parse({
      bigipHost: values.f5BigipHost,
      partition: values.f5BigipPartition,
      clientSslProfiles: (values.f5BigipClientSslProfiles || [])
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    }) as Record<string, unknown>;
  }

  return undefined;
}

export default function EditCredentialPage() {
  const params = useParams<{ credentialXref: string }>();
  const router = useRouter();
  const updateCredential = useUpdateCredential();
  const isDnsCredentialsEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.DNS_CREDENTIALS,
  );
  const agentTransport = useAgentTransport();
  const credentialXref = decodeURIComponent(params.credentialXref || "");
  const credentialQuery = useCredentialReference(credentialXref);

  const credential = credentialQuery.data || null;
  // A secret pasted on a self-hosted install is edited the same way it was entered.
  const usesManagedCredentials =
    agentTransport === "GATEWAY" &&
    isCertPingStoredHandle(credential?.secretHandle);
  const providerApiValue = credential?.provider || "";

  const parsedK8sConfig = useMemo(
    () => parseKubernetesCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAwsAcmConfig = useMemo(
    () => parseAwsAcmCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAwsLoadBalancerConfig = useMemo(
    () => parseAwsLoadBalancerCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAwsApiGatewayConfig = useMemo(
    () => parseAwsApiGatewayCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAwsCloudFrontConfig = useMemo(
    () => parseAwsCloudFrontCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAzureKvConfig = useMemo(
    () => parseAzureKvCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAzureAppGwConfig = useMemo(
    () => parseAzureAppGwCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAzureAgcConfig = useMemo(
    () => parseAzureAgcCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAzureAfdConfig = useMemo(
    () => parseAzureAfdCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedGcpCertManagerConfig = useMemo(
    () => parseGcpCertManagerCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedGcpProxyConfig = useMemo(
    () => parseGcpProxyCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedCloudflareEdgeConfig = useMemo(
    () => parseCloudflareEdgeCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAkamaiCpsConfig = useMemo(
    () => parseAkamaiCpsCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedF5BigipConfig = useMemo(
    () => parseF5BigipCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );

  const form = useForm<EditCredentialFormValues>({
    resolver: zodResolver(
      editCredentialFormSchema,
    ) as Resolver<EditCredentialFormValues>,
    defaultValues: {
      provider: providerApiValue,
      secretHandle: "",
      credJson: "",
      ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
      k8sAuthMethod: "SA_INCLUSTER",
      k8sClusterName: "",
      k8sNamespaceMode: "explicit",
      k8sNamespaces: [],
      awsAcmAuthMode: "STATIC_KEYS",
      awsAcmRegion: "",
      awsAcmRoleArn: "",
      awsAcmExternalId: "",
      awsElbAuthMode: "STATIC_KEYS",
      awsElbRegion: "",
      awsElbRoleArn: "",
      awsElbExternalId: "",
      awsElbListeners: [],
      awsApiGwAuthMode: "STATIC_KEYS",
      awsApiGwRegion: "",
      awsApiGwRoleArn: "",
      awsApiGwExternalId: "",
      awsApiGwCustomDomains: [],
      awsCloudFrontAuthMode: "STATIC_KEYS",
      awsCloudFrontDistributionId: "",
      awsCloudFrontRoleArn: "",
      awsCloudFrontExternalId: "",
      azureKvAuthMode: "SERVICE_PRINCIPAL",
      azureKvTenantId: "",
      azureKvVaultUri: "",
      azureKvClientId: "",
      azureAppGwAuthMode: "SERVICE_PRINCIPAL",
      azureAppGwTenantId: "",
      azureAppGwSubscriptionId: "",
      azureAppGwClientId: "",
      azureAppGwResourceGroup: "",
      azureAppGwAppGateway: "",
      azureAppGwListeners: [],
      azureAppGwKeyVaultUri: "",
      azureAgcAzureAuthMode: "SERVICE_PRINCIPAL",
      azureAgcTenantId: "",
      azureAgcSubscriptionId: "",
      azureAgcResourceGroup: "",
      azureAgcClientId: "",
      azureAgcClusterAuthMode: "AZURE",
      azureAgcClusterName: "",
      azureAgcNamespace: "",
      azureAgcApiStyle: "GATEWAY_API",
      azureAgcSecretNamespaces: [],
      azureAfdAuthMode: "SERVICE_PRINCIPAL",
      azureAfdTenantId: "",
      azureAfdSubscriptionId: "",
      azureAfdClientId: "",
      azureAfdResourceGroup: "",
      azureAfdProfileName: "",
      azureAfdKeyVaultUri: "",
      azureAfdCustomDomains: [],
      gcpAuthMode: "SERVICE_ACCOUNT_KEY",
      gcpProjectId: "",
      gcpLocation: "global",
      gcpImpersonateServiceAccount: "",
      gcpCertManagerCertificateMap: "",
      gcpProxyTargetHttpsProxy: "",
      gcpProxyTargetSslProxy: "",
      cloudflareZoneId: "",
      akamaiHost: "",
      akamaiEnrollmentId: "",
      f5BigipHost: "",
      f5BigipPartition: "Common",
      f5BigipClientSslProfiles: ["clientssl-api"],
    },
  });

  useEffect(() => {
    if (!credential?.credentialXref) {
      return;
    }

    form.reset(
      {
        provider: providerApiValue,
        credentialStorage: usesManagedCredentials ? "managed" : "vault",
        secretHandle: usesManagedCredentials
          ? ""
          : credential.secretHandle || "",
        credJson: "",
        ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
        k8sAuthMethod: parsedK8sConfig?.authMethod || "SA_INCLUSTER",
        k8sClusterName: parsedK8sConfig?.clusterName || "",
        k8sNamespaceMode:
          parsedK8sConfig?.namespaces === KUBERNETES_ALL_NAMESPACES
            ? "all_namespaces"
            : "explicit",
        k8sNamespaces: Array.isArray(parsedK8sConfig?.namespaces)
          ? parsedK8sConfig.namespaces
          : [],
        awsAcmAuthMode: parsedAwsAcmConfig?.authMode || "STATIC_KEYS",
        awsAcmRegion: parsedAwsAcmConfig?.region || "",
        awsAcmRoleArn: parsedAwsAcmConfig?.roleArn || "",
        awsAcmExternalId: parsedAwsAcmConfig?.externalId || "",
        awsElbAuthMode: parsedAwsLoadBalancerConfig?.authMode || "STATIC_KEYS",
        awsElbRegion: parsedAwsLoadBalancerConfig?.region || "",
        awsElbRoleArn: parsedAwsLoadBalancerConfig?.roleArn || "",
        awsElbExternalId: parsedAwsLoadBalancerConfig?.externalId || "",
        awsElbListeners: Array.isArray(parsedAwsLoadBalancerConfig?.listeners)
          ? parsedAwsLoadBalancerConfig.listeners
          : [],
        awsApiGwAuthMode: parsedAwsApiGatewayConfig?.authMode || "STATIC_KEYS",
        awsApiGwRegion: parsedAwsApiGatewayConfig?.region || "",
        awsApiGwRoleArn: parsedAwsApiGatewayConfig?.roleArn || "",
        awsApiGwExternalId: parsedAwsApiGatewayConfig?.externalId || "",
        awsApiGwCustomDomains: Array.isArray(
          parsedAwsApiGatewayConfig?.customDomains,
        )
          ? parsedAwsApiGatewayConfig.customDomains
          : [],
        awsCloudFrontAuthMode:
          parsedAwsCloudFrontConfig?.authMode || "STATIC_KEYS",
        awsCloudFrontDistributionId:
          parsedAwsCloudFrontConfig?.distributionId || "",
        awsCloudFrontRoleArn: parsedAwsCloudFrontConfig?.roleArn || "",
        awsCloudFrontExternalId: parsedAwsCloudFrontConfig?.externalId || "",
        azureKvAuthMode: parsedAzureKvConfig?.authMode || "SERVICE_PRINCIPAL",
        azureKvTenantId: parsedAzureKvConfig?.tenantId || "",
        azureKvVaultUri: parsedAzureKvConfig?.vaultUri || "",
        azureKvClientId: parsedAzureKvConfig?.clientId || "",
        azureAppGwAuthMode:
          parsedAzureAppGwConfig?.authMode || "SERVICE_PRINCIPAL",
        azureAppGwTenantId: parsedAzureAppGwConfig?.tenantId || "",
        azureAppGwSubscriptionId: parsedAzureAppGwConfig?.subscriptionId || "",
        azureAppGwClientId: parsedAzureAppGwConfig?.clientId || "",
        azureAppGwResourceGroup: parsedAzureAppGwConfig?.resourceGroup || "",
        azureAppGwAppGateway: parsedAzureAppGwConfig?.appGateway || "",
        azureAppGwListeners: Array.isArray(parsedAzureAppGwConfig?.listeners)
          ? parsedAzureAppGwConfig.listeners
          : [],
        azureAppGwKeyVaultUri: parsedAzureAppGwConfig?.keyVaultUri || "",
        azureAgcAzureAuthMode:
          parsedAzureAgcConfig?.azureAuthMode || "SERVICE_PRINCIPAL",
        azureAgcTenantId: parsedAzureAgcConfig?.tenantId || "",
        azureAgcSubscriptionId: parsedAzureAgcConfig?.subscriptionId || "",
        azureAgcResourceGroup: parsedAzureAgcConfig?.resourceGroup || "",
        azureAgcClientId: parsedAzureAgcConfig?.clientId || "",
        azureAgcClusterAuthMode:
          parsedAzureAgcConfig?.clusterAuthMode || "AZURE",
        azureAgcClusterName: parsedAzureAgcConfig?.clusterName || "",
        azureAgcNamespace: parsedAzureAgcConfig?.agcNamespace || "",
        azureAgcApiStyle: parsedAzureAgcConfig?.apiStyle || "GATEWAY_API",
        azureAgcSecretNamespaces: Array.isArray(
          parsedAzureAgcConfig?.secretNamespaces,
        )
          ? parsedAzureAgcConfig.secretNamespaces
          : [],
        azureAfdAuthMode: parsedAzureAfdConfig?.authMode || "SERVICE_PRINCIPAL",
        azureAfdTenantId: parsedAzureAfdConfig?.tenantId || "",
        azureAfdSubscriptionId: parsedAzureAfdConfig?.subscriptionId || "",
        azureAfdClientId: parsedAzureAfdConfig?.clientId || "",
        azureAfdResourceGroup: parsedAzureAfdConfig?.resourceGroup || "",
        azureAfdProfileName: parsedAzureAfdConfig?.profileName || "",
        azureAfdKeyVaultUri: parsedAzureAfdConfig?.keyVaultUri || "",
        azureAfdCustomDomains: Array.isArray(
          parsedAzureAfdConfig?.customDomains,
        )
          ? parsedAzureAfdConfig.customDomains
          : [],
        gcpAuthMode:
          parsedGcpCertManagerConfig?.authMode ||
          parsedGcpProxyConfig?.authMode ||
          "SERVICE_ACCOUNT_KEY",
        gcpProjectId:
          parsedGcpCertManagerConfig?.projectId ||
          parsedGcpProxyConfig?.projectId ||
          "",
        gcpLocation:
          parsedGcpCertManagerConfig?.location ||
          parsedGcpProxyConfig?.location ||
          "global",
        gcpImpersonateServiceAccount:
          parsedGcpCertManagerConfig?.impersonateServiceAccount ||
          parsedGcpProxyConfig?.impersonateServiceAccount ||
          "",
        gcpCertManagerCertificateMap:
          parsedGcpCertManagerConfig?.certificateMap || "",
        gcpProxyTargetHttpsProxy: parsedGcpProxyConfig?.targetProxy || "",
        gcpProxyTargetSslProxy: parsedGcpProxyConfig?.targetSslProxy || "",
        cloudflareZoneId: parsedCloudflareEdgeConfig?.zoneId || "",
        akamaiHost: parsedAkamaiCpsConfig?.host || "",
        akamaiEnrollmentId: parsedAkamaiCpsConfig?.enrollmentId || "",
        f5BigipHost: parsedF5BigipConfig?.bigipHost || "",
        f5BigipPartition: parsedF5BigipConfig?.partition || "Common",
        f5BigipClientSslProfiles: Array.isArray(
          parsedF5BigipConfig?.clientSslProfiles,
        )
          ? parsedF5BigipConfig.clientSslProfiles
          : ["clientssl-api"],
      },
      // Ensures refresh/back protection does not trigger without user changes.
      { keepDirty: false },
    );
    form.setValue(
      "k8sAuthMethod",
      parsedK8sConfig?.authMethod || "SA_INCLUSTER",
      {
        shouldDirty: false,
        shouldTouch: false,
        shouldValidate: false,
      },
    );
  }, [
    credential?.credentialXref,
    credential?.secretHandle,
    form,
    parsedAwsAcmConfig,
    parsedAwsApiGatewayConfig,
    parsedAwsCloudFrontConfig,
    parsedAwsLoadBalancerConfig,
    parsedAzureKvConfig,
    parsedAzureAppGwConfig,
    parsedAzureAgcConfig,
    parsedAzureAfdConfig,
    parsedGcpCertManagerConfig,
    parsedGcpProxyConfig,
    parsedCloudflareEdgeConfig,
    parsedAkamaiCpsConfig,
    parsedF5BigipConfig,
    parsedK8sConfig,
    providerApiValue,
    usesManagedCredentials,
  ]);

  const isKubernetesProvider =
    providerApiValue.toUpperCase() === KUBERNETES_SECRETS_PROVIDER;
  const isAwsAcmCredential = isAwsAcmProvider(providerApiValue);
  const isAwsLoadBalancerCredential =
    isAwsLoadBalancerProvider(providerApiValue);
  const isAwsApiGatewayCredential = isAwsApiGatewayProvider(providerApiValue);
  const isAwsCloudFrontCredential = isAwsCloudFrontProvider(providerApiValue);
  const isAzureKvCredential = isAzureKvProvider(providerApiValue);
  const isAzureAppGwCredential = isAzureAppGwProvider(providerApiValue);
  const isAzureAgcCredential = isAzureAgcProvider(providerApiValue);
  const isAzureAfdCredential = isAzureAfdProvider(providerApiValue);
  const isGcpCertManagerCredential = isGcpCertManagerProvider(providerApiValue);
  const isGcpProxyCredential = isGcpProxyProvider(providerApiValue);
  const isCloudflareEdgeCredential = isCloudflareEdgeProvider(providerApiValue);
  const isAkamaiCpsCredential = isAkamaiCpsProvider(providerApiValue);
  const isF5BigipCredential = isF5BigipProvider(providerApiValue);
  const selectedK8sAuthMethod =
    form.watch("k8sAuthMethod") ||
    parsedK8sConfig?.authMethod ||
    "SA_INCLUSTER";
  const k8sAuthMethod =
    usesManagedCredentials &&
    isKubernetesProvider &&
    !MANAGED_KUBERNETES_AUTH_METHODS.includes(
      selectedK8sAuthMethod as KubernetesAuthMethod,
    )
      ? "AZURE"
      : selectedK8sAuthMethod;
  const awsAcmAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("awsAcmAuthMode") as AwsAcmAuthMode | undefined,
    "STATIC_KEYS",
    usesManagedCredentials,
  );
  const awsElbAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("awsElbAuthMode") as AwsLoadBalancerAuthMode | undefined,
    "STATIC_KEYS",
    usesManagedCredentials,
  );
  const awsApiGwAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("awsApiGwAuthMode") as AwsApiGwAuthMode | undefined,
    "STATIC_KEYS",
    usesManagedCredentials,
  );
  const awsCloudFrontAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("awsCloudFrontAuthMode") as AwsCloudFrontAuthMode | undefined,
    "STATIC_KEYS",
    usesManagedCredentials,
  );
  const azureKvAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("azureKvAuthMode") as AzureKvAuthMode | undefined,
    "SERVICE_PRINCIPAL",
    usesManagedCredentials,
  );
  const azureAppGwAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("azureAppGwAuthMode") as AzureAppGwAuthMode | undefined,
    "SERVICE_PRINCIPAL",
    usesManagedCredentials,
  );
  const azureAgcAzureAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("azureAgcAzureAuthMode") as AzureAgcAuthMode | undefined,
    "SERVICE_PRINCIPAL",
    usesManagedCredentials,
  );
  const azureAgcClusterAuthMode = (form.watch("azureAgcClusterAuthMode") ||
    "AZURE") as AzureAgcClusterAuthMode;
  const azureAgcApiStyle = (form.watch("azureAgcApiStyle") ||
    "GATEWAY_API") as AzureAgcApiStyle;
  const azureAfdAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("azureAfdAuthMode") as AzureAfdAuthMode | undefined,
    "SERVICE_PRINCIPAL",
    usesManagedCredentials,
  );
  const gcpAuthMode = normalizeDeploymentAuthModeForAppMode(
    form.watch("gcpAuthMode") as GcpAuthMode | undefined,
    "SERVICE_ACCOUNT_KEY",
    usesManagedCredentials,
  );
  const isKvPathRequired = useMemo(
    () =>
      isCredentialKvPathRequired({
        providerApiValue,
        kubernetesAuthMethod: k8sAuthMethod,
        awsAcmAuthMode,
        awsElbAuthMode,
        awsApiGwAuthMode,
        awsCloudFrontAuthMode,
        azureKvAuthMode,
        azureAppGwAuthMode,
        azureAgcAzureAuthMode,
        azureAgcClusterAuthMode,
        azureAfdAuthMode,
        gcpAuthMode,
      }),
    [
      awsAcmAuthMode,
      awsElbAuthMode,
      awsApiGwAuthMode,
      awsCloudFrontAuthMode,
      azureKvAuthMode,
      azureAppGwAuthMode,
      azureAgcAzureAuthMode,
      azureAgcClusterAuthMode,
      azureAfdAuthMode,
      gcpAuthMode,
      k8sAuthMethod,
      providerApiValue,
    ],
  );
  const providerType = credential?.type === "DNS" ? "DNS" : "DEPLOYMENT";
  const providerOption = useMemo(
    () =>
      getCredentialReferenceProviderOptions(providerType).find(
        (item) => item.apiValue === providerApiValue,
      ) || null,
    [providerApiValue, providerType],
  );
  const providerTemplate = providerOption?.secretPayloadTemplate || "";
  const payloadTemplate = useMemo(
    () =>
      usesManagedCredentials
        ? getManagedCredentialJsonTemplate({
            type: providerType,
            providerApiValue,
            kubernetesAuthMethod: k8sAuthMethod as never,
            awsAcmAuthMode,
            awsElbAuthMode,
            awsApiGwAuthMode,
            awsCloudFrontAuthMode,
            azureKvAuthMode,
            azureAppGwAuthMode,
            azureAgcAzureAuthMode,
            azureAgcClusterAuthMode,
            azureAfdAuthMode,
            gcpAuthMode,
            fallbackTemplate: providerTemplate,
          })
        : getCredentialSecretPayloadTemplate({
            providerApiValue,
            kubernetesAuthMethod: k8sAuthMethod,
            awsAcmAuthMode,
            awsElbAuthMode,
            awsApiGwAuthMode,
            awsCloudFrontAuthMode,
            azureKvAuthMode,
            azureAppGwAuthMode,
            azureAgcAzureAuthMode,
            azureAgcClusterAuthMode,
            azureAfdAuthMode,
            gcpAuthMode,
            providerTemplate,
          }),
    [
      usesManagedCredentials,
      providerType,
      awsAcmAuthMode,
      awsElbAuthMode,
      awsApiGwAuthMode,
      awsCloudFrontAuthMode,
      azureKvAuthMode,
      azureAppGwAuthMode,
      azureAgcAzureAuthMode,
      azureAgcClusterAuthMode,
      azureAfdAuthMode,
      gcpAuthMode,
      k8sAuthMethod,
      providerApiValue,
      providerTemplate,
    ],
  );
  const isSaving = updateCredential.isPending;
  const isDirty = form.formState.isDirty;
  const [suppressUnsavedWarning, setSuppressUnsavedWarning] = useState(false);
  // Warn only when the user has actually changed something and we are not mid-save.
  useUnsavedChangesWarning(isDirty && !isSaving && !suppressUnsavedWarning);

  if (credentialQuery.isLoading) {
    return (
      <div className="mx-auto h-full w-full max-w-4xl space-y-4 p-6">
        <PageHeader title="Edit integration" />
        <Skeleton className="mx-auto h-full w-full! bg-card" />
      </div>
    );
  }

  if (!credential?.credentialXref) {
    return (
      <div className="space-y-4 p-6">
        <PageHeader title="Integration not found" />
        <Button asChild variant="outline">
          <Link href={connectionsListHref(credential?.type)}>
            Back to integrations
          </Link>
        </Button>
      </div>
    );
  }

  if (credential.type === "DNS" && !isDnsCredentialsEnabled) {
    return <FeatureDisabledPage featureKey={FEATURE_FLAGS.DNS_CREDENTIALS} />;
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <PageHeader
        title="Edit integration"
        subtitle={credential.description || credential.credentialXref}
        actions={
          <Button
            variant="outline"
            type="button"
            onClick={() => router.push(connectionsListHref(credential?.type))}
          >
            <span className="flex items-center justify-start gap-2">
              <ArrowLeftIcon className="h-4 w-4" />
              Back to integrations
            </span>
          </Button>
        }
      />
      <Card className="bg-card">
        <CardHeader>
          <CardTitle>Credential configuration</CardTitle>
        </CardHeader>
        <CardContent className="mx-auto w-full max-w-3xl">
          <Form {...form}>
            <NoAutofillForm
              className="space-y-4"
              onInvalid={(event) => {
                event.preventDefault();
                const message =
                  findFirstFormErrorMessage(form.formState.errors) ||
                  "Please fix the highlighted validation errors before saving.";
                toast.error(message);
              }}
              onSubmit={form.handleSubmit(async (values) => {
                const targetCredentialXref = credential.credentialXref;
                if (!targetCredentialXref) {
                  return;
                }
                const normalizedValues = usesManagedCredentials
                  ? {
                      ...normalizeCredentialAuthModesForAppMode(
                        values,
                        usesManagedCredentials,
                      ),
                      ...(isKubernetesProvider &&
                      !MANAGED_KUBERNETES_AUTH_METHODS.includes(
                        values.k8sAuthMethod as KubernetesAuthMethod,
                      )
                        ? { k8sAuthMethod: "AZURE" as const }
                        : {}),
                    }
                  : values;
                try {
                  const configJson = buildUpdatedConfigJson({
                    isKubernetesProvider,
                    isAwsAcmCredential,
                    isAwsLoadBalancerCredential,
                    isAwsApiGatewayCredential,
                    isAwsCloudFrontCredential,
                    isAzureKvCredential,
                    isAzureAppGwCredential,
                    isAzureAgcCredential,
                    isAzureAfdCredential,
                    isGcpCertManagerCredential,
                    isGcpProxyCredential,
                    isCloudflareEdgeCredential,
                    isAkamaiCpsCredential,
                    isF5BigipCredential,
                    values: normalizedValues,
                  });
                  const managedCredentialJson =
                    usesManagedCredentials || providerApiValue === "NAMECHEAP"
                      ? buildManagedCredentialJsonFromValues({
                          values: normalizedValues,
                          mode: "edit",
                          context: {
                            type: providerType,
                            providerApiValue,
                            kubernetesAuthMethod:
                              normalizedValues.k8sAuthMethod as never,
                            awsAcmAuthMode,
                            awsElbAuthMode,
                            awsApiGwAuthMode,
                            awsCloudFrontAuthMode,
                            azureKvAuthMode,
                            azureAppGwAuthMode,
                            azureAgcAzureAuthMode,
                            azureAgcClusterAuthMode,
                            azureAfdAuthMode,
                            gcpAuthMode,
                            fallbackTemplate: providerTemplate,
                          },
                        })
                      : undefined;

                  await updateCredential.mutateAsync({
                    credentialXref: targetCredentialXref,
                    ...(!usesManagedCredentials
                      ? {
                          ...buildCredentialSecretStoragePayload({
                            secretHandle: normalizedValues.secretHandle,
                            isKvPathRequired,
                          }),
                          ...(providerApiValue === "NAMECHEAP" &&
                          managedCredentialJson !== undefined
                            ? { credJson: managedCredentialJson }
                            : {}),
                        }
                      : {}),
                    ...(usesManagedCredentials &&
                    managedCredentialJson !== undefined
                      ? { credJson: managedCredentialJson, secretHandle: null }
                      : {}),
                    ...(configJson ? { configJson } : {}),
                  });
                } catch (error) {
                  if (error instanceof CredentialFieldError) {
                    form.setError(
                      error.field as keyof EditCredentialFormValues,
                      {
                        type: "custom",
                        message: error.message,
                      },
                    );
                    toast.error(error.message);
                  }
                  return;
                }
                // Clear "dirty" state before navigating so the unsaved-changes guard
                // won't interfere with the redirect.
                form.reset(values, { keepDirty: false });
                setSuppressUnsavedWarning(true);
                router.push(connectionsListHref(credential?.type));
                router.refresh();
              })}
            >
              {providerOption ? (
                <CredentialSelectedProviderBanner
                  label={providerOption.label}
                  description={providerOption.description}
                  docsUrl={providerOption.docs}
                  providerKey={providerOption.providerKey}
                  providerApiValue={providerOption.apiValue}
                />
              ) : null}

              <CredentialProviderFields
                form={form}
                providerApiValue={providerApiValue}
                kubernetesAuthMethod={k8sAuthMethod as never}
                awsAcmAuthMode={awsAcmAuthMode}
                awsElbAuthMode={awsElbAuthMode}
                awsApiGwAuthMode={awsApiGwAuthMode}
                awsCloudFrontAuthMode={awsCloudFrontAuthMode}
                azureKvAuthMode={azureKvAuthMode}
                azureAppGwAuthMode={azureAppGwAuthMode}
                azureAgcAzureAuthMode={azureAgcAzureAuthMode}
                azureAgcClusterAuthMode={azureAgcClusterAuthMode}
                azureAgcApiStyle={azureAgcApiStyle}
                azureAfdAuthMode={azureAfdAuthMode}
                gcpAuthMode={gcpAuthMode}
                showKubernetesStorageInstruction={!usesManagedCredentials}
                allowedKubernetesAuthMethods={
                  usesManagedCredentials
                    ? MANAGED_KUBERNETES_AUTH_METHODS
                    : undefined
                }
                usesManagedCredentials={usesManagedCredentials}
              />

              {usesManagedCredentials || providerApiValue === "NAMECHEAP" ? (
                <ManagedCredentialFields
                  form={form}
                  mode="edit"
                  type={providerType}
                  providerApiValue={providerApiValue}
                  kubernetesAuthMethod={k8sAuthMethod as never}
                  awsAcmAuthMode={awsAcmAuthMode}
                  awsElbAuthMode={awsElbAuthMode}
                  awsApiGwAuthMode={awsApiGwAuthMode}
                  awsCloudFrontAuthMode={awsCloudFrontAuthMode}
                  azureKvAuthMode={azureKvAuthMode}
                  azureAppGwAuthMode={azureAppGwAuthMode}
                  azureAgcAzureAuthMode={azureAgcAzureAuthMode}
                  azureAfdAuthMode={azureAfdAuthMode}
                  gcpAuthMode={gcpAuthMode}
                  usesManagedCredentials={usesManagedCredentials}
                />
              ) : null}

              {!usesManagedCredentials && isKvPathRequired ? (
                <FormField
                  control={form.control}
                  name="secretHandle"
                  render={({ field }) => (
                    <FormItem>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <FormLabel>Secret handle</FormLabel>
                        <CredentialProviderInfoDialog
                          providerApiValue={providerApiValue}
                        />
                      </div>
                      <FormControl>
                        <Input className="h-10 md:max-w-xl" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ) : !usesManagedCredentials ? (
                <Alert>
                  <AlertTitle>Secret handle not required</AlertTitle>
                  <AlertDescription>
                    This auth mode uses runtime identity and does not require a
                    secret handle.
                  </AlertDescription>
                </Alert>
              ) : null}

              {!usesManagedCredentials ? (
                <CredentialSecretPayloadCard
                  payloadTemplate={payloadTemplate}
                  providerApiValue={providerApiValue}
                  storageMode="kvPath"
                />
              ) : null}

              <CredentialPageActions
                isSaving={updateCredential.isPending}
                onCancel={() =>
                  router.push(connectionsListHref(credential?.type))
                }
                submitLabel={
                  updateCredential.isPending ? "Saving..." : "Save credential"
                }
              />
            </NoAutofillForm>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
