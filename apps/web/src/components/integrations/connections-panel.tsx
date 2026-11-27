// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useForm, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  KeyIcon,
  CircleNotchIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  TrashIcon,
} from "@phosphor-icons/react";

import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { useAuth } from "@/hooks/use-auth";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  useCredentials,
  useDeleteCredential,
  useUpdateCredential,
} from "@/hooks/credentials";
import {
  canCreateCredentials,
  canUpdateCredentials,
  canViewCredentials,
} from "@/lib/authz";
import {
  KUBERNETES_ALL_NAMESPACES,
  KUBERNETES_SECRETS_PROVIDER,
  getKubernetesAuthMethodInstruction,
  getKubernetesAuthMethodLabel,
  getKubernetesAuthMethodSecretTemplate,
  kubernetesCredentialConfigSchema,
  parseKubernetesCredentialConfig,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  AWS_ACM_AUTH_MODES,
  awsAcmCredentialConfigSchema,
  getAwsAcmAuthModeHelp,
  getAwsAcmAuthModeLabel,
  getAwsAcmAuthModeSecretTemplate,
  isAwsAcmKvPathRequired,
  isAwsAcmProvider,
  parseAwsAcmCredentialConfig,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import {
  AWS_CLOUDFRONT_AUTH_MODES,
  awsCloudFrontCredentialConfigSchema,
  getAwsCloudFrontAuthModeHelp,
  getAwsCloudFrontAuthModeLabel,
  getAwsCloudFrontAuthModeSecretTemplate,
  isAwsCloudFrontKvPathRequired,
  isAwsCloudFrontProvider,
  parseAwsCloudFrontCredentialConfig,
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import {
  AZURE_KV_AUTH_MODES,
  azureKvCredentialConfigSchema,
  getAzureKvAuthModeHelp,
  getAzureKvAuthModeLabel,
  getAzureKvAuthModeSecretTemplate,
  isAzureKvKvPathRequired,
  isAzureKvProvider,
  parseAzureKvCredentialConfig,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import {
  azureAppGwCredentialConfigSchema,
  isAzureAppGwKvPathRequired,
  isAzureAppGwProvider,
  parseAzureAppGwCredentialConfig,
  type AzureAppGwAuthMode,
} from "@/lib/credential-config-schemas/azure-app-gw";
import {
  azureAgcCredentialConfigSchema,
  isAzureAgcKvPathRequired,
  isAzureAgcProvider,
  parseAzureAgcCredentialConfig,
  type AzureAgcApiStyle,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import {
  azureAfdCredentialConfigSchema,
  isAzureAfdKvPathRequired,
  isAzureAfdProvider,
  parseAzureAfdCredentialConfig,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import {
  akamaiCpsCredentialConfigSchema,
  isAkamaiCpsProvider,
  parseAkamaiCpsCredentialConfig,
} from "@/lib/credential-config-schemas/akamai-cps";
import { MANAGED_CREDENTIAL_FIELD_DEFAULTS } from "@/lib/cert-manager/managed-credential-json";
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
import {
  getGcpAuthModeSecretTemplate,
  isGcpKvPathRequired,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";
import {
  K8S_AUTH_METHOD_OPTIONS,
  type EditCredentialValues,
  copyTextToClipboard,
  editCredentialSchema,
} from "@/lib/cert-manager/credentials-page-helpers";
import { CredentialAuthModeInfoDialog } from "@/components/cert-manager/credentials/credential-auth-mode-info-dialog";
import { StringListFormField } from "@/components/common/string-list-form-field";
import { CloudflareEdgeFields } from "@/components/cert-manager/credentials/providers/cloudflare-edge-fields";
import { AkamaiCpsFields } from "@/components/cert-manager/credentials/providers/akamai-cps-fields";
import { F5BigipFields } from "@/components/cert-manager/credentials/providers/f5-bigip-fields";
import { GcpCertManagerFields } from "@/components/cert-manager/credentials/providers/gcp-cert-manager-fields";
import { GcpProxyFields } from "@/components/cert-manager/credentials/providers/gcp-proxy-fields";
import { AzureFrontDoorFields } from "@/components/cert-manager/credentials/providers/azure-front-door-fields";
import { AzureAppGatewayFields } from "@/components/cert-manager/credentials/providers/azure-app-gateway-fields";
import { AzureAppGatewayContainersFields } from "@/components/cert-manager/credentials/providers/azure-app-gateway-containers-fields";
import {
  AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP,
  AzureServicePrincipalClientIdField,
} from "@/components/cert-manager/credentials/providers/azure-service-principal-client-id-field";
import { Unauthorised } from "@/components/common/unautorised";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  CredentialDetailsDialog,
  getCredentialTitle,
} from "@/components/cert-manager/credential-details-dialog";
import { CredentialInventory } from "@/components/cert-manager/credentials/credential-inventory";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input, NoAutofillForm } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { IntegrationsTabHeader } from "@/components/integrations/integrations-tab-header";
import {
  addConnectionHref,
  editConnectionHref,
  INTEGRATIONS_DEPLOYMENT_TARGETS_HREF,
  INTEGRATIONS_DNS_HREF,
} from "@/lib/integrations/routes";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import type { CredentialRecord } from "@/types/ssl";

/** The two categories of saved connection this panel can render. */
export type ConnectionType = "DNS" | "DEPLOYMENT";

/**
 * Per-category wording.
 *
 * The records are the same shape and the API still calls them credential
 * references, but a user does not think "I have a credential" - they think
 * "I connected Cloudflare" or "I added a deployment target". Everything the
 * user reads is keyed off the category here; "credential" survives only on
 * the secret itself, inside the add and edit forms.
 */
const CONNECTION_COPY: Record<
  ConnectionType,
  {
    href: string;
    title: string;
    description: string;
    addLabel: string;
    addHref: string;
    searchPlaceholder: string;
    inventoryLabel: string;
    emptyTitle: string;
    emptyDescription: string;
    noMatchTitle: string;
    noneActiveTitle: string;
    noneActiveDescription: string;
  }
> = {
  DNS: {
    href: INTEGRATIONS_DNS_HREF,
    title: "DNS Providers",
    description:
      "DNS accounts CertPing uses to prove domain control during ACME DNS-01 validation.",
    addLabel: "Connect DNS provider",
    addHref: addConnectionHref("DNS"),
    searchPlaceholder: "Search DNS providers, references, or secret handles",
    inventoryLabel: "DNS provider connections",
    emptyTitle: "No DNS providers connected",
    emptyDescription:
      "Connect a DNS provider here, then pick it when issuing a certificate that validates over DNS-01.",
    noMatchTitle: "No matching DNS providers",
    noneActiveTitle: "No active DNS providers",
    noneActiveDescription:
      "Every DNS provider here is inactive. Review them before starting a DNS-01 issuance.",
  },
  DEPLOYMENT: {
    href: INTEGRATIONS_DEPLOYMENT_TARGETS_HREF,
    title: "Deployment Targets",
    description:
      "Destinations CertPing delivers and installs issued certificates to.",
    addLabel: "Add deployment target",
    addHref: addConnectionHref("DEPLOYMENT"),
    searchPlaceholder:
      "Search deployment targets, references, or secret handles",
    inventoryLabel: "Deployment target connections",
    emptyTitle: "No deployment targets connected",
    emptyDescription:
      "Add a target here, then pick it when deploying a certificate to AWS, Azure, GCP, Kubernetes, or an edge provider.",
    noMatchTitle: "No matching deployment targets",
    noneActiveTitle: "No active deployment targets",
    noneActiveDescription:
      "Every target here is inactive. Review them before starting a deployment.",
  },
};

function EditCredentialDialog({
  credential,
  open,
  onOpenChange,
}: {
  credential: CredentialRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const updateCredential = useUpdateCredential();
  const parsedConfig = useMemo(
    () => parseKubernetesCredentialConfig(credential?.configJson),
    [credential?.configJson],
  );
  const parsedAwsAcmConfig = useMemo(
    () => parseAwsAcmCredentialConfig(credential?.configJson),
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
  const parsedAwsCloudFrontConfig = useMemo(
    () => parseAwsCloudFrontCredentialConfig(credential?.configJson),
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
  const form = useForm<EditCredentialValues>({
    resolver: zodResolver(
      editCredentialSchema,
    ) as Resolver<EditCredentialValues>,
    defaultValues: {
      provider: credential?.providerName || "",
      credentialStorage: "vault",
      secretHandle: credential?.secretHandle || "",
      credJson: "",
      ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
      k8sAuthMethod: parsedConfig?.authMethod || "SA_INCLUSTER",
      k8sClusterName: parsedConfig?.clusterName || "",
      k8sNamespaceMode:
        parsedConfig?.namespaces === KUBERNETES_ALL_NAMESPACES
          ? "all_namespaces"
          : "explicit",
      k8sNamespaces: Array.isArray(parsedConfig?.namespaces)
        ? parsedConfig.namespaces
        : [],
      awsAcmAuthMode: parsedAwsAcmConfig?.authMode || "STATIC_KEYS",
      awsAcmRegion: parsedAwsAcmConfig?.region || "",
      awsAcmRoleArn: parsedAwsAcmConfig?.roleArn || "",
      awsAcmExternalId: parsedAwsAcmConfig?.externalId || "",
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
      azureAgcClusterAuthMode: parsedAzureAgcConfig?.clusterAuthMode || "AZURE",
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
      azureAfdCustomDomains: Array.isArray(parsedAzureAfdConfig?.customDomains)
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
    values: {
      provider: credential?.providerName || "",
      credentialStorage: "vault",
      secretHandle: credential?.secretHandle || "",
      credJson: "",
      ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
      k8sAuthMethod: parsedConfig?.authMethod || "SA_INCLUSTER",
      k8sClusterName: parsedConfig?.clusterName || "",
      k8sNamespaceMode:
        parsedConfig?.namespaces === KUBERNETES_ALL_NAMESPACES
          ? "all_namespaces"
          : "explicit",
      k8sNamespaces: Array.isArray(parsedConfig?.namespaces)
        ? parsedConfig.namespaces
        : [],
      awsAcmAuthMode: parsedAwsAcmConfig?.authMode || "STATIC_KEYS",
      awsAcmRegion: parsedAwsAcmConfig?.region || "",
      awsAcmRoleArn: parsedAwsAcmConfig?.roleArn || "",
      awsAcmExternalId: parsedAwsAcmConfig?.externalId || "",
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
      azureAgcClusterAuthMode: parsedAzureAgcConfig?.clusterAuthMode || "AZURE",
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
      azureAfdCustomDomains: Array.isArray(parsedAzureAfdConfig?.customDomains)
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
  });
  const isKubernetesProvider =
    (credential?.providerName || "").toUpperCase() ===
    KUBERNETES_SECRETS_PROVIDER;
  const isAwsAcmCredential = isAwsAcmProvider(credential?.providerName);
  const isAwsCloudFrontCredential = isAwsCloudFrontProvider(
    credential?.providerName,
  );
  const isAzureKvCredential = isAzureKvProvider(credential?.providerName);
  const isAzureAppGwCredential = isAzureAppGwProvider(credential?.providerName);
  const isAzureAgcCredential = isAzureAgcProvider(credential?.providerName);
  const isAzureAfdCredential = isAzureAfdProvider(credential?.providerName);
  const isGcpCertManagerCredential = isGcpCertManagerProvider(
    credential?.providerName,
  );
  const isGcpProxyCredential = isGcpProxyProvider(credential?.providerName);
  const isCloudflareEdgeCredential = isCloudflareEdgeProvider(
    credential?.providerName,
  );
  const isAkamaiCpsCredential = isAkamaiCpsProvider(credential?.providerName);
  const isF5BigipCredential = isF5BigipProvider(credential?.providerName);
  const k8sAuthMethod = form.watch("k8sAuthMethod") || "SA_INCLUSTER";
  const k8sNamespaceMode = (form.watch("k8sNamespaceMode") || "explicit") as
    "explicit" | "all_namespaces";
  const isInClusterServiceAccount =
    isKubernetesProvider && k8sAuthMethod === "SA_INCLUSTER";
  const awsAcmAuthMode = (form.watch("awsAcmAuthMode") ||
    "STATIC_KEYS") as AwsAcmAuthMode;
  const awsCloudFrontAuthMode = (form.watch("awsCloudFrontAuthMode") ||
    "STATIC_KEYS") as AwsCloudFrontAuthMode;
  const azureKvAuthMode = (form.watch("azureKvAuthMode") ||
    "SERVICE_PRINCIPAL") as AzureKvAuthMode;
  const azureAppGwAuthMode = (form.watch("azureAppGwAuthMode") ||
    "SERVICE_PRINCIPAL") as AzureAppGwAuthMode;
  const azureAgcAzureAuthMode = (form.watch("azureAgcAzureAuthMode") ||
    "SERVICE_PRINCIPAL") as AzureAgcAuthMode;
  const azureAgcClusterAuthMode = (form.watch("azureAgcClusterAuthMode") ||
    "AZURE") as AzureAgcClusterAuthMode;
  const azureAgcApiStyle = (form.watch("azureAgcApiStyle") ||
    "GATEWAY_API") as AzureAgcApiStyle;
  const azureAfdAuthMode = (form.watch("azureAfdAuthMode") ||
    "SERVICE_PRINCIPAL") as AzureAfdAuthMode;
  const gcpAuthMode = (form.watch("gcpAuthMode") ||
    "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
  const k8sTemplate = getKubernetesAuthMethodSecretTemplate(k8sAuthMethod);
  const awsTemplate = getAwsAcmAuthModeSecretTemplate(awsAcmAuthMode);
  const awsCloudFrontTemplate = getAwsCloudFrontAuthModeSecretTemplate(
    awsCloudFrontAuthMode,
  );
  const azureTemplate = getAzureKvAuthModeSecretTemplate(azureKvAuthMode);
  const gcpTemplate = getGcpAuthModeSecretTemplate(gcpAuthMode);
  const isKvPathRequired = useMemo(() => {
    if (isInClusterServiceAccount) {
      return false;
    }
    if (isAwsAcmCredential) {
      return isAwsAcmKvPathRequired(awsAcmAuthMode);
    }
    if (isAwsCloudFrontCredential) {
      return isAwsCloudFrontKvPathRequired(awsCloudFrontAuthMode);
    }
    if (isAzureKvCredential) {
      return isAzureKvKvPathRequired(azureKvAuthMode);
    }
    if (isAzureAppGwCredential) {
      return isAzureAppGwKvPathRequired(azureAppGwAuthMode);
    }
    if (isAzureAgcCredential) {
      return isAzureAgcKvPathRequired({
        azureAuthMode: azureAgcAzureAuthMode,
        clusterAuthMode: azureAgcClusterAuthMode,
      });
    }
    if (isAzureAfdCredential) {
      return isAzureAfdKvPathRequired(azureAfdAuthMode);
    }
    if (isGcpCertManagerCredential || isGcpProxyCredential) {
      return isGcpKvPathRequired(gcpAuthMode);
    }
    return true;
  }, [
    awsAcmAuthMode,
    awsCloudFrontAuthMode,
    azureKvAuthMode,
    azureAppGwAuthMode,
    azureAgcAzureAuthMode,
    azureAgcClusterAuthMode,
    azureAfdAuthMode,
    gcpAuthMode,
    isAwsAcmCredential,
    isAwsCloudFrontCredential,
    isAzureKvCredential,
    isAzureAppGwCredential,
    isAzureAgcCredential,
    isAzureAfdCredential,
    isGcpCertManagerCredential,
    isGcpProxyCredential,
    isInClusterServiceAccount,
  ]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-hidden sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Update credential details</DialogTitle>
          <DialogDescription>
            Update deployment target settings. Changes are applied on the next
            issuance, renewal, or deployment operation.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <NoAutofillForm
            className="flex max-h-[calc(90vh-9rem)] flex-col"
            onSubmit={form.handleSubmit(async (values) => {
              if (!credential?.credentialXref) {
                return;
              }

              const secretHandle = values.secretHandle?.trim();
              let configJson = credential.configJson;
              if (isKubernetesProvider) {
                const namespaces =
                  values.k8sNamespaceMode === "all_namespaces"
                    ? KUBERNETES_ALL_NAMESPACES
                    : (values.k8sNamespaces || [])
                        .map((value) => value.trim())
                        .filter((value) => value.length > 0);
                const parsed = kubernetesCredentialConfigSchema.parse({
                  authMethod: values.k8sAuthMethod,
                  clusterName: values.k8sClusterName,
                  namespaces,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAwsAcmCredential) {
                const parsed = awsAcmCredentialConfigSchema.parse({
                  authMode: (values.awsAcmAuthMode ||
                    "STATIC_KEYS") as AwsAcmAuthMode,
                  region: values.awsAcmRegion,
                  roleArn: values.awsAcmRoleArn?.trim() || undefined,
                  externalId: values.awsAcmExternalId?.trim() || undefined,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAwsCloudFrontCredential) {
                const parsed = awsCloudFrontCredentialConfigSchema.parse({
                  authMode: (values.awsCloudFrontAuthMode ||
                    "STATIC_KEYS") as AwsCloudFrontAuthMode,
                  distributionId: values.awsCloudFrontDistributionId,
                  roleArn: values.awsCloudFrontRoleArn?.trim() || undefined,
                  externalId:
                    values.awsCloudFrontExternalId?.trim() || undefined,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAzureKvCredential) {
                const parsed = azureKvCredentialConfigSchema.parse({
                  authMode: (values.azureKvAuthMode ||
                    "SERVICE_PRINCIPAL") as AzureKvAuthMode,
                  tenantId: values.azureKvTenantId?.trim() || "",
                  vaultUri: values.azureKvVaultUri,
                  ...(values.azureKvClientId?.trim()
                    ? { clientId: values.azureKvClientId.trim() }
                    : {}),
                });
                configJson = JSON.stringify(parsed);
              } else if (isAzureAppGwCredential) {
                const listeners = (values.azureAppGwListeners || [])
                  .map((value: string) => value.trim())
                  .filter((value: string) => value.length > 0);
                const parsed = azureAppGwCredentialConfigSchema.parse({
                  authMode: (values.azureAppGwAuthMode ||
                    "SERVICE_PRINCIPAL") as AzureAppGwAuthMode,
                  tenantId: values.azureAppGwTenantId,
                  subscriptionId: values.azureAppGwSubscriptionId,
                  resourceGroup: values.azureAppGwResourceGroup,
                  appGateway: values.azureAppGwAppGateway,
                  listeners,
                  keyVaultUri: values.azureAppGwKeyVaultUri,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAzureAgcCredential) {
                const secretNamespaces = (values.azureAgcSecretNamespaces || [])
                  .map((value: string) => value.trim())
                  .filter((value: string) => value.length > 0);
                const parsed = azureAgcCredentialConfigSchema.parse({
                  azureAuthMode: (values.azureAgcAzureAuthMode ||
                    "SERVICE_PRINCIPAL") as AzureAgcAuthMode,
                  tenantId: values.azureAgcTenantId,
                  subscriptionId: values.azureAgcSubscriptionId,
                  resourceGroup: values.azureAgcResourceGroup,
                  clusterAuthMode: (values.azureAgcClusterAuthMode ||
                    "AZURE") as AzureAgcClusterAuthMode,
                  clusterName: values.azureAgcClusterName,
                  agcNamespace: values.azureAgcNamespace,
                  apiStyle: (values.azureAgcApiStyle ||
                    "GATEWAY_API") as AzureAgcApiStyle,
                  secretNamespaces,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAzureAfdCredential) {
                const customDomains = (values.azureAfdCustomDomains || [])
                  .map((value: string) => value.trim())
                  .filter((value: string) => value.length > 0);
                const parsed = azureAfdCredentialConfigSchema.parse({
                  authMode: (values.azureAfdAuthMode ||
                    "SERVICE_PRINCIPAL") as AzureAfdAuthMode,
                  tenantId: values.azureAfdTenantId,
                  subscriptionId: values.azureAfdSubscriptionId,
                  resourceGroup: values.azureAfdResourceGroup,
                  profileName: values.azureAfdProfileName,
                  keyVaultUri: values.azureAfdKeyVaultUri,
                  customDomains,
                });
                configJson = JSON.stringify(parsed);
              } else if (isGcpCertManagerCredential) {
                const parsed = gcpCertManagerCredentialConfigSchema.parse({
                  authMode: (values.gcpAuthMode ||
                    "SERVICE_ACCOUNT_KEY") as GcpAuthMode,
                  projectId: values.gcpProjectId,
                  location: values.gcpLocation,
                  impersonateServiceAccount:
                    values.gcpImpersonateServiceAccount?.trim() || undefined,
                  certificateMap:
                    values.gcpCertManagerCertificateMap?.trim() || undefined,
                });
                configJson = JSON.stringify(parsed);
              } else if (isGcpProxyCredential) {
                const provider = (credential?.providerName || "")
                  .trim()
                  .toUpperCase();
                const parsed = gcpProxyCredentialConfigSchema.parse({
                  authMode: (values.gcpAuthMode ||
                    "SERVICE_ACCOUNT_KEY") as GcpAuthMode,
                  projectId: values.gcpProjectId,
                  location: values.gcpLocation,
                  impersonateServiceAccount:
                    values.gcpImpersonateServiceAccount?.trim() || undefined,
                  ...(provider === "GCP_PROXY_NLB"
                    ? { targetSslProxy: values.gcpProxyTargetSslProxy }
                    : { targetProxy: values.gcpProxyTargetHttpsProxy }),
                });
                configJson = JSON.stringify(parsed);
              } else if (isCloudflareEdgeCredential) {
                const parsed = cloudflareEdgeCredentialConfigSchema.parse({
                  zoneId: values.cloudflareZoneId,
                });
                configJson = JSON.stringify(parsed);
              } else if (isAkamaiCpsCredential) {
                const parsed = akamaiCpsCredentialConfigSchema.parse({
                  host: values.akamaiHost,
                  enrollmentId: values.akamaiEnrollmentId,
                });
                configJson = JSON.stringify(parsed);
              } else if (isF5BigipCredential) {
                const parsed = f5BigipCredentialConfigSchema.parse({
                  bigipHost: values.f5BigipHost,
                  partition: values.f5BigipPartition,
                  clientSslProfiles: (values.f5BigipClientSslProfiles || [])
                    .map((value: string) => value.trim())
                    .filter((value: string) => value.length > 0),
                });
                configJson = JSON.stringify(parsed);
              }

              await updateCredential.mutateAsync({
                credentialXref: credential.credentialXref,
                ...(secretHandle ? { secretHandle } : {}),
                ...(configJson ? { configJson } : {}),
              });
              onOpenChange(false);
            })}
          >
            <div className="space-y-4 overflow-y-auto pr-1">
              {isKubernetesProvider ? (
                <div className="space-y-4 border-t pt-4">
                  <FormField
                    control={form.control}
                    name="k8sAuthMethod"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Auth method</FormLabel>
                        <Select
                          onValueChange={field.onChange}
                          value={field.value}
                        >
                          <FormControl>
                            <SelectTrigger className="h-10">
                              <SelectValue placeholder="Select auth method" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {K8S_AUTH_METHOD_OPTIONS.map((option) => (
                              <SelectItem
                                key={option.value}
                                value={option.value}
                              >
                                {option.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="k8sClusterName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Cluster name</FormLabel>
                        <FormControl>
                          <Input
                            className="h-10"
                            placeholder="aks-prod"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="k8sNamespaceMode"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Namespace scope</FormLabel>
                        <FormControl>
                          <RadioGroup
                            value={field.value}
                            onValueChange={field.onChange}
                            className="grid gap-2"
                          >
                            <div className="flex items-center gap-2">
                              <RadioGroupItem
                                value="explicit"
                                id="edit-k8s-ns-explicit"
                              />
                              <Label htmlFor="edit-k8s-ns-explicit">
                                Specific namespaces
                              </Label>
                            </div>
                            <div className="flex items-center gap-2">
                              <RadioGroupItem
                                value="all_namespaces"
                                id="edit-k8s-ns-all"
                              />
                              <Label htmlFor="edit-k8s-ns-all">
                                All namespaces
                              </Label>
                            </div>
                          </RadioGroup>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {k8sNamespaceMode !== "all_namespaces" ? (
                    <StringListFormField
                      form={form}
                      name={"k8sNamespaces" as never}
                      label="Namespaces"
                      placeholder="prod"
                      addLabel="Add namespace"
                    />
                  ) : null}

                  <Alert>
                    <AlertTitle>
                      {getKubernetesAuthMethodLabel(k8sAuthMethod)}
                    </AlertTitle>
                    <AlertDescription>
                      {getKubernetesAuthMethodInstruction(k8sAuthMethod)}
                    </AlertDescription>
                  </Alert>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => copyTextToClipboard(k8sTemplate)}
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={k8sTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isAwsAcmCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <div className="flex items-center justify-between">
                    <FormLabel>Auth mode</FormLabel>
                    <CredentialAuthModeInfoDialog provider="AWS_CLOUDFRONT" />
                  </div>
                  <FormField
                    control={form.control}
                    name="awsAcmAuthMode"
                    render={({ field }) => (
                      <FormItem>
                        <Select
                          onValueChange={field.onChange}
                          value={field.value}
                        >
                          <FormControl>
                            <SelectTrigger className="h-10">
                              <SelectValue placeholder="Select auth mode" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {AWS_ACM_AUTH_MODES.map((mode) => (
                              <SelectItem key={mode} value={mode}>
                                {getAwsAcmAuthModeLabel(mode)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          {getAwsAcmAuthModeHelp(
                            (field.value || "STATIC_KEYS") as AwsAcmAuthMode,
                          )}
                        </p>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="awsAcmRegion"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Region</FormLabel>
                        <FormControl>
                          <Input
                            className="h-10"
                            placeholder="us-east-1"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {awsAcmAuthMode === "ASSUME_ROLE" ? (
                    <>
                      <FormField
                        control={form.control}
                        name="awsAcmRoleArn"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Role ARN</FormLabel>
                            <FormControl>
                              <Input className="h-10" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="awsAcmExternalId"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>External ID (optional)</FormLabel>
                            <FormControl>
                              <Input className="h-10" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </>
                  ) : null}

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => copyTextToClipboard(awsTemplate)}
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={awsTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isAwsCloudFrontCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <div className="flex items-center justify-between">
                    <FormLabel>Auth mode</FormLabel>
                    <CredentialAuthModeInfoDialog provider="AWS_ACM" />
                  </div>
                  <FormField
                    control={form.control}
                    name="awsCloudFrontAuthMode"
                    render={({ field }) => (
                      <FormItem>
                        <Select
                          onValueChange={field.onChange}
                          value={field.value}
                        >
                          <FormControl>
                            <SelectTrigger className="h-10">
                              <SelectValue placeholder="Select auth mode" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {AWS_CLOUDFRONT_AUTH_MODES.map((mode) => (
                              <SelectItem key={mode} value={mode}>
                                {getAwsCloudFrontAuthModeLabel(mode)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          {getAwsCloudFrontAuthModeHelp(
                            (field.value ||
                              "STATIC_KEYS") as AwsCloudFrontAuthMode,
                          )}
                        </p>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="awsCloudFrontDistributionId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Distribution ID</FormLabel>
                        <FormControl>
                          <Input className="h-10" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {awsCloudFrontAuthMode === "ASSUME_ROLE" ? (
                    <>
                      <FormField
                        control={form.control}
                        name="awsCloudFrontRoleArn"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Role ARN</FormLabel>
                            <FormControl>
                              <Input className="h-10" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <FormField
                        control={form.control}
                        name="awsCloudFrontExternalId"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>External ID (optional)</FormLabel>
                            <FormControl>
                              <Input className="h-10" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </>
                  ) : null}

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          copyTextToClipboard(awsCloudFrontTemplate)
                        }
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={awsCloudFrontTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isAzureKvCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <div className="flex items-center justify-between">
                    <FormLabel>Auth mode</FormLabel>
                    <CredentialAuthModeInfoDialog provider="AZURE_KV" />
                  </div>
                  <FormField
                    control={form.control}
                    name="azureKvAuthMode"
                    render={({ field }) => (
                      <FormItem>
                        <Select
                          onValueChange={field.onChange}
                          value={field.value}
                        >
                          <FormControl>
                            <SelectTrigger className="h-10">
                              <SelectValue placeholder="Select auth mode" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {AZURE_KV_AUTH_MODES.map((mode) => (
                              <SelectItem key={mode} value={mode}>
                                {getAzureKvAuthModeLabel(mode)}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                          {getAzureKvAuthModeHelp(
                            (field.value ||
                              "SERVICE_PRINCIPAL") as AzureKvAuthMode,
                          )}
                        </p>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="azureKvVaultUri"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Vault URI</FormLabel>
                        <FormControl>
                          <Input className="h-10" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="azureKvTenantId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Tenant ID</FormLabel>
                        <FormControl>
                          <Input className="h-10" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {azureKvAuthMode === "WORKLOAD_IDENTITY" ? (
                    <AzureServicePrincipalClientIdField
                      description={AZURE_WORKLOAD_IDENTITY_CLIENT_ID_HELP}
                      form={form}
                      name="azureKvClientId"
                    />
                  ) : null}

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => copyTextToClipboard(azureTemplate)}
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={azureTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isAzureAfdCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <AzureFrontDoorFields
                    form={form}
                    authMode={azureAfdAuthMode}
                  />
                </div>
              ) : null}

              {isAzureAgcCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <AzureAppGatewayContainersFields
                    form={form}
                    azureAuthMode={azureAgcAzureAuthMode}
                    clusterAuthMode={azureAgcClusterAuthMode}
                    apiStyle={azureAgcApiStyle}
                  />
                </div>
              ) : null}

              {isAzureAppGwCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <AzureAppGatewayFields
                    form={form}
                    authMode={azureAppGwAuthMode}
                  />
                </div>
              ) : null}

              {isCloudflareEdgeCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <CloudflareEdgeFields form={form} />
                </div>
              ) : null}

              {isAkamaiCpsCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <AkamaiCpsFields form={form} />
                </div>
              ) : null}

              {isF5BigipCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <F5BigipFields form={form} />
                </div>
              ) : null}

              {isGcpCertManagerCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <GcpCertManagerFields form={form} authMode={gcpAuthMode} />

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => copyTextToClipboard(gcpTemplate)}
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={gcpTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isGcpProxyCredential ? (
                <div className="space-y-4 border-t pt-4">
                  <GcpProxyFields
                    form={form}
                    authMode={gcpAuthMode}
                    providerApiValue={credential?.providerName || ""}
                  />

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <FormLabel>Secret payload template</FormLabel>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => copyTextToClipboard(gcpTemplate)}
                      >
                        Copy template
                      </Button>
                    </div>
                    <Textarea
                      className="min-h-28 font-mono text-xs"
                      readOnly
                      value={gcpTemplate}
                    />
                  </div>
                </div>
              ) : null}

              {isKvPathRequired ? (
                <FormField
                  control={form.control}
                  name="secretHandle"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Secret handle</FormLabel>
                      <FormControl>
                        <Input className="h-10" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ) : (
                <Alert>
                  <AlertTitle>Secret handle not required</AlertTitle>
                  <AlertDescription>
                    {isInClusterServiceAccount
                      ? "In-cluster service account uses the agent pod identity and does not need a secret handle."
                      : "This auth mode uses runtime identity and does not need a secret handle."}
                  </AlertDescription>
                </Alert>
              )}
            </div>

            <DialogFooter className="mt-4 border-t pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button disabled={updateCredential.isPending} type="submit">
                {updateCredential.isPending ? (
                  <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                Save credential
              </Button>
            </DialogFooter>
          </NoAutofillForm>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteCredentialDialog({
  credential,
  open,
  onDeleted,
  onOpenChange,
}: {
  credential: CredentialRecord | null;
  open: boolean;
  onDeleted?: (credentialXref: string) => void;
  onOpenChange: (open: boolean) => void;
}) {
  const deleteCredential = useDeleteCredential();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete credential reference</DialogTitle>
          <DialogDescription>
            {credential
              ? `Delete ${getCredentialTitle(credential)}? Existing secrets in your secret manager will not be removed automatically.`
              : "Delete this credential reference?"}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={!credential?.credentialXref || deleteCredential.isPending}
            onClick={async () => {
              if (!credential?.credentialXref) {
                return;
              }

              await deleteCredential.mutateAsync(credential.credentialXref);
              onDeleted?.(credential.credentialXref);
              onOpenChange(false);
            }}
          >
            {deleteCredential.isPending ? (
              <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <TrashIcon className="h-4 w-4" />
            )}
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const DNS_CREDENTIALS_OFF_NOTE =
  "Connecting DNS providers isn't available. Ask your CertPing administrator.";

/**
 * One category of saved connection - DNS providers or deployment targets.
 *
 * These used to be one "Credentials" table with an All/DNS/Deployment tab
 * strip inside it. The category is the Integrations tab now, so this renders a
 * single type and the inner tab strip is gone; everything else (search, status
 * filter, pagination, the details/edit/delete dialogs) is unchanged.
 */
export function ConnectionsPanel({ type }: { type: ConnectionType }) {
  const copy = CONNECTION_COPY[type];
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, isLoading: isLoadingAuth } = useAuth();
  const isCertDeploymentEnabled = useIsFeatureEnabled("CERTIFICATE_DEPLOYMENT");
  const isDnsCredentialsEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.DNS_CREDENTIALS,
  );
  // DNS credentials stay listed while DNS_CREDENTIALS is off; only adding,
  // editing and deleting them stops.
  const canChangeThisType = type !== "DNS" || isDnsCredentialsEnabled;
  const canViewCredentialList = canViewCredentials(user);
  const canCreateCredential = canCreateCredentials(user) && canChangeThisType;
  const canUpdateCredential = canUpdateCredentials(user);
  const canEditCredential = canUpdateCredential && canChangeThisType;

  const [deleteCredential, setDeleteCredentialState] =
    useState<CredentialRecord | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<
    "all" | "ACTIVE" | "INACTIVE"
  >("all");
  const [selectedCredential, setSelectedCredential] =
    useState<CredentialRecord | null>(null);
  const previousCredentialParamRef = useRef("");

  const credentialsQuery = useCredentials({
    enabled: canViewCredentialList,
  });

  const credentials = useMemo(
    () => credentialsQuery.data || [],
    [credentialsQuery.data],
  );
  const isCredentialTypeVisible = useCallback(
    (candidate: CredentialRecord["type"]) =>
      candidate !== "DEPLOYMENT" || isCertDeploymentEnabled,
    [isCertDeploymentEnabled],
  );
  const credentialParam = searchParams.get("credential")?.trim() || "";
  const deepLinkedCredential = credentialParam.toLowerCase();

  const visibleCredentials = useMemo(() => {
    const query = (searchTerm || deepLinkedCredential).trim().toLowerCase();

    return credentials.filter((credential) => {
      if (credential.type !== type) {
        return false;
      }

      const matchesSearch =
        query.length === 0 ||
        [
          credential.credentialXref,
          credential.alias,
          credential.description,
          credential.providerDisplayName,
          credential.providerName,
          credential.secretHandle,
        ].some((value) => value?.toLowerCase().includes(query));

      const matchesStatus =
        statusFilter === "all" ||
        credential.status === statusFilter ||
        (statusFilter === "INACTIVE" &&
          credential.status === "PENDING_ROTATION");

      return matchesSearch && matchesStatus;
    });
  }, [credentials, deepLinkedCredential, searchTerm, statusFilter, type]);

  const PAGE_SIZE = 24;
  const totalPages = Math.max(
    1,
    Math.ceil(visibleCredentials.length / PAGE_SIZE),
  );
  const paginatedCredentials = useMemo(() => {
    const safePage = Math.min(currentPage, totalPages);
    const startIndex = (safePage - 1) * PAGE_SIZE;
    return visibleCredentials.slice(startIndex, startIndex + PAGE_SIZE);
  }, [currentPage, totalPages, visibleCredentials]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, statusFilter, type]);

  useEffect(() => {
    const previousCredentialParam = previousCredentialParamRef.current;
    previousCredentialParamRef.current = credentialParam;

    if (!credentialParam) {
      if (previousCredentialParam) {
        setSelectedCredential(null);
      }
      return;
    }

    const match = credentials.find(
      (credential) =>
        credential.credentialXref === credentialParam ||
        credential.alias === credentialParam,
    );

    // The deep link carries a reference, not a category, so it can land on the
    // wrong tab - Discovery links to deployment targets, an emailed link may
    // point at a DNS provider. Hop to the tab that actually holds it instead of
    // showing an empty table, and drop a reference that matches nothing.
    const otherType: ConnectionType = type === "DNS" ? "DEPLOYMENT" : "DNS";
    if (
      match?.type === otherType &&
      isCredentialTypeVisible(otherType) &&
      match.type !== type
    ) {
      setSelectedCredential(null);
      router.replace(
        `${CONNECTION_COPY[otherType].href}?credential=${encodeURIComponent(
          credentialParam,
        )}`,
        { scroll: false },
      );
      return;
    }

    const matchInThisCategory = match?.type === type ? match : undefined;
    setSelectedCredential(matchInThisCategory ?? null);
    if (!matchInThisCategory && credentials.length > 0) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete("credential");
      const query = params.toString();
      router.replace(query ? `${pathname}?${query}` : pathname, {
        scroll: false,
      });
    }
  }, [
    credentialParam,
    credentials,
    isCredentialTypeVisible,
    pathname,
    router,
    searchParams,
    type,
  ]);

  const openCredentialDetails = (credential: CredentialRecord) => {
    setSelectedCredential(credential);
    const params = new URLSearchParams(searchParams.toString());
    params.set("credential", credential.credentialXref || credential.alias);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
  };

  const closeCredentialDetails = () => {
    setSelectedCredential(null);
    const params = new URLSearchParams(searchParams.toString());
    params.delete("credential");
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {
      scroll: false,
    });
  };

  const clearCredentialQueryParam = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("credential");
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {
      scroll: false,
    });
  };

  if (isLoadingAuth || credentialsQuery.isLoading) {
    return <CredentialsSkeleton />;
  }

  // CREDENTIALS_MANAGEMENT (and CERTIFICATE_DEPLOYMENT for deployment
  // targets) is enforced by `FeatureRouteGate` (see feature-routes).
  if (!canViewCredentialList) {
    return <Unauthorised />;
  }

  const typedCredentials = credentials.filter(
    (credential) => credential.type === type,
  );
  const activeCount = typedCredentials.filter(
    (credential) => credential.status === "ACTIVE",
  ).length;

  return (
    <>
      <div className="space-y-4">
        <section className="overflow-hidden surface-panel">
          <IntegrationsTabHeader
            title={copy.title}
            description={copy.description}
            className="p-4 md:p-5"
            actions={
              canCreateCredential ? (
                <Button onClick={() => router.push(copy.addHref)}>
                  <PlusIcon />
                  {copy.addLabel}
                </Button>
              ) : null
            }
          />
          <div className="flex flex-col gap-3 border-t border-border/80 surface-muted p-3 lg:flex-row lg:items-center lg:justify-between lg:p-4">
            <div className="flex w-full flex-col gap-2 sm:flex-row lg:max-w-2xl lg:justify-end">
              <div className="relative min-w-0 flex-1">
                <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder={copy.searchPlaceholder}
                  aria-label={copy.searchPlaceholder}
                  className="pl-9"
                />
              </div>
              <Select
                value={statusFilter}
                onValueChange={(value) =>
                  setStatusFilter(value as typeof statusFilter)
                }
              >
                <SelectTrigger
                  aria-label="Filter by status"
                  className="w-full sm:w-44"
                >
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  <SelectItem value="ACTIVE">Active</SelectItem>
                  <SelectItem value="INACTIVE">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </section>

        {typedCredentials.length > 0 && !canChangeThisType ? (
          <Alert variant="info">
            <AlertDescription>{DNS_CREDENTIALS_OFF_NOTE}</AlertDescription>
          </Alert>
        ) : null}

        {visibleCredentials.length === 0 ? (
          <Alert className="bg-card">
            <KeyIcon className="h-4 w-4" />
            <AlertTitle>
              {typedCredentials.length === 0
                ? copy.emptyTitle
                : copy.noMatchTitle}
            </AlertTitle>
            <AlertDescription>
              {typedCredentials.length > 0
                ? "Adjust the current filters or search to widen the view."
                : canChangeThisType
                  ? copy.emptyDescription
                  : DNS_CREDENTIALS_OFF_NOTE}
            </AlertDescription>
          </Alert>
        ) : (
          <section
            aria-label={copy.inventoryLabel}
            className="overflow-hidden surface-panel"
          >
            <CredentialInventory
              credentials={paginatedCredentials}
              canEditCredential={canEditCredential}
              onDelete={setDeleteCredentialState}
              onEdit={(credential) =>
                router.push(
                  editConnectionHref(
                    credential.credentialXref || credential.alias,
                  ),
                )
              }
              onOpen={openCredentialDetails}
            />
            {visibleCredentials.length > PAGE_SIZE ? (
              <div className="flex items-center justify-between border-t border-border/80 surface-muted p-3">
                <p className="text-sm text-muted-foreground">
                  Page {Math.min(currentPage, totalPages)} of {totalPages}
                </p>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={currentPage <= 1}
                    onClick={() =>
                      setCurrentPage((page) => Math.max(1, page - 1))
                    }
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={currentPage >= totalPages}
                    onClick={() =>
                      setCurrentPage((page) => Math.min(totalPages, page + 1))
                    }
                  >
                    Next
                  </Button>
                </div>
              </div>
            ) : null}
          </section>
        )}

        {activeCount === 0 && typedCredentials.length > 0 ? (
          <Alert className="status-warning">
            <AlertTitle>{copy.noneActiveTitle}</AlertTitle>
            <AlertDescription>{copy.noneActiveDescription}</AlertDescription>
          </Alert>
        ) : null}
      </div>

      {canUpdateCredential ? (
        <>
          <CredentialDetailsDialog
            credential={selectedCredential}
            open={Boolean(selectedCredential)}
            canEditCredential={canEditCredential}
            onClose={closeCredentialDetails}
            onDelete={(credential) => {
              closeCredentialDetails();
              setDeleteCredentialState(credential);
            }}
            onEdit={(credential) => {
              closeCredentialDetails();
              router.push(
                editConnectionHref(
                  credential.credentialXref || credential.alias,
                ),
              );
            }}
          />
          <EditCredentialDialog
            credential={null}
            open={false}
            onOpenChange={() => {}}
          />
          <DeleteCredentialDialog
            credential={deleteCredential}
            open={Boolean(deleteCredential)}
            onDeleted={(deletedXref) => {
              setSelectedCredential(null);
              if (
                searchParams.get("credential") === deletedXref ||
                selectedCredential?.credentialXref === deletedXref
              ) {
                clearCredentialQueryParam();
              }
            }}
            onOpenChange={(open) => {
              if (!open) {
                setDeleteCredentialState(null);
              }
            }}
          />
        </>
      ) : null}
    </>
  );
}

function CredentialsSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-44 rounded-(--certping-radius-md)" />
      <div className="space-y-1 rounded-(--certping-radius-md) bg-card p-2">
        <Skeleton className="h-10" />
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
        <Skeleton className="h-14" />
      </div>
    </div>
  );
}
