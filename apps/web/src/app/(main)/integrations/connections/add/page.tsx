// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowLeftIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { useAddCredential } from "@/hooks/credentials";
import { useIsFeatureEnabled } from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useUnsavedChangesWarning } from "@/hooks/use-unsaved-changes-warning";
import { useAgentTransport } from "@/hooks/use-deployment-mode";
import {
  canChooseCredentialStorage,
  usesManagedStorage,
} from "@/lib/cert-manager/credential-storage";
import { CredentialStorageChoice } from "@/components/cert-manager/credentials/credential-storage-choice";
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
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import {
  awsApiGatewayCredentialConfigSchema,
  isAwsApiGatewayProvider,
  type AwsApiGwAuthMode,
} from "@/lib/credential-config-schemas/aws-api-gateway";
import {
  awsAcmCredentialConfigSchema,
  isAwsAcmProvider,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import {
  awsLoadBalancerCredentialConfigSchema,
  isAwsLoadBalancerProvider,
  type AwsLoadBalancerAuthMode,
} from "@/lib/credential-config-schemas/aws-load-balancer";
import {
  azureKvCredentialConfigSchema,
  isAzureKvProvider,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import {
  azureAppGwCredentialConfigSchema,
  isAzureAppGwProvider,
  type AzureAppGwAuthMode,
} from "@/lib/credential-config-schemas/azure-app-gw";
import {
  azureAgcCredentialConfigSchema,
  isAzureAgcProvider,
  type AzureAgcApiStyle,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import {
  azureAfdCredentialConfigSchema,
  isAzureAfdProvider,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import {
  akamaiCpsCredentialConfigSchema,
  isAkamaiCpsProvider,
} from "@/lib/credential-config-schemas/akamai-cps";
import {
  cloudflareEdgeCredentialConfigSchema,
  isCloudflareEdgeProvider,
} from "@/lib/credential-config-schemas/cloudflare-edge";
import {
  f5BigipCredentialConfigSchema,
  isF5BigipProvider,
} from "@/lib/credential-config-schemas/f5-bigip";
import {
  gcpCertManagerCredentialConfigSchema,
  isGcpCertManagerProvider,
} from "@/lib/credential-config-schemas/gcp-cert-manager";
import {
  gcpProxyCredentialConfigSchema,
  isGcpProxyProvider,
} from "@/lib/credential-config-schemas/gcp-proxy";
import { type GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";
import {
  KUBERNETES_ALL_NAMESPACES,
  MANAGED_KUBERNETES_AUTH_METHODS,
  KUBERNETES_SECRETS_PROVIDER,
  type KubernetesAuthMethod,
  kubernetesCredentialConfigSchema,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  createCredentialFormSchema,
  type CreateCredentialFormValues,
} from "@/lib/cert-manager/credential-form-schemas";
import { CredentialPageActions } from "@/components/cert-manager/credentials/credential-page-actions";
import { ManagedCredentialFields } from "@/components/cert-manager/credentials/managed-credential-fields";
import { CredentialProviderInfoDialog } from "@/components/cert-manager/credentials/credential-provider-info-dialog";
import { CredentialSelectedProviderBanner } from "@/components/cert-manager/credentials/credential-selected-provider-banner";
import { CredentialSecretPayloadCard } from "@/components/cert-manager/credentials/credential-secret-payload-card";
import { CredentialProviderFields } from "@/components/cert-manager/credentials/providers/provider-fields";
import { CredentialProviderSelector } from "@/components/cert-manager/credentials/credential-provider-selector";
import { FeatureDisabledPage } from "@/components/common/feature-disabled";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { CredentialReferenceType } from "@/types/cert-manager";
import { connectionsListHref } from "@/lib/integrations/routes";
import { safeReturnPath } from "@/lib/cert-manager/certificate-journeys";
import { cn } from "@/lib/utils";

/**
 * CREDENTIALS_MANAGEMENT is enforced by `FeatureRouteGate`; deployment
 * targets additionally need CERTIFICATE_DEPLOYMENT and DNS providers
 * DNS_CREDENTIALS, which depend on the type and so are checked here.
 */
export default function AddCredentialPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const isCertDeploymentEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT,
  );
  const isDnsCredentialsEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.DNS_CREDENTIALS,
  );
  const requestedTypeParam = searchParams.get("type");
  const returnTo = safeReturnPath(searchParams.get("returnTo"));
  const requestedType = requestedTypeParam === "DNS" ? "DNS" : "DEPLOYMENT";
  const initialType =
    requestedType === "DEPLOYMENT" && !isCertDeploymentEnabled
      ? "DNS"
      : requestedType;
  const createCredential = useAddCredential();
  const agentTransport = useAgentTransport();
  const canChooseStorage = canChooseCredentialStorage(agentTransport);
  const form = useForm<CreateCredentialFormValues>({
    resolver: zodResolver(createCredentialFormSchema),
    defaultValues: {
      type: initialType,
      provider: "",
      description: "",
      credentialStorage: "vault",
      secretHandle: "",
      credJson: "",
      ...MANAGED_CREDENTIAL_FIELD_DEFAULTS,
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
      k8sAuthMethod: "SA_INCLUSTER",
      k8sClusterName: "",
      k8sNamespaceMode: "explicit",
      k8sNamespaces: [],
    },
  });

  const credentialStorage = form.watch("credentialStorage") ?? "vault";
  const usesManagedCredentials = usesManagedStorage({ credentialStorage });

  // Self-hosted installs default to pasting the secret: there may be no vault at all.
  useEffect(() => {
    if (canChooseStorage && !form.getFieldState("credentialStorage").isDirty) {
      form.setValue("credentialStorage", "managed", { shouldDirty: false });
    }
  }, [canChooseStorage, form]);

  const type = form.watch("type");
  const provider = form.watch("provider");
  const selectedK8sAuthMethod = form.watch("k8sAuthMethod");
  const k8sAuthMethod =
    usesManagedCredentials &&
    provider === KUBERNETES_SECRETS_PROVIDER &&
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

  const providerOptions = useMemo(
    () => getCredentialReferenceProviderOptions(type),
    [type],
  );

  const selectedProviderOption = useMemo(
    () => providerOptions.find((option) => option.apiValue === provider),
    [provider, providerOptions],
  );

  const isKvPathRequired = useMemo(
    () =>
      isCredentialKvPathRequired({
        providerApiValue: provider,
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
      provider,
    ],
  );
  const payloadTemplate = useMemo(
    () =>
      usesManagedCredentials
        ? getManagedCredentialJsonTemplate({
            type,
            providerApiValue: provider,
            kubernetesAuthMethod: k8sAuthMethod as KubernetesAuthMethod,
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
            fallbackTemplate:
              selectedProviderOption?.secretPayloadTemplate || "",
          })
        : getCredentialSecretPayloadTemplate({
            providerApiValue: provider,
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
            providerTemplate:
              selectedProviderOption?.secretPayloadTemplate || "",
          }),
    [
      usesManagedCredentials,
      type,
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
      provider,
      selectedProviderOption?.secretPayloadTemplate,
    ],
  );
  const isSaving = createCredential.isPending;
  const isDirty = form.formState.isDirty;
  // When redirecting after a successful save, suppress navigation guards so the
  // App Router pushState interceptor doesn't prompt.
  const [suppressUnsavedWarning, setSuppressUnsavedWarning] = useState(false);
  // Warn only when the user has actually changed something and we are not mid-save.
  useUnsavedChangesWarning(
    Boolean(selectedProviderOption) &&
      isDirty &&
      !isSaving &&
      !suppressUnsavedWarning,
  );

  useEffect(() => {
    if (type === "DEPLOYMENT" && !isCertDeploymentEnabled) {
      form.setValue("type", "DNS", {
        shouldDirty: false,
        shouldTouch: false,
        shouldValidate: true,
      });
      return;
    }

    // Changing the "type" tab should reset provider selection without
    // triggering the unsaved-changes warning.
    form.setValue("provider", "", { shouldDirty: false, shouldTouch: false });
    form.setValue("credJson", "", { shouldDirty: false, shouldTouch: false });
    Object.entries(MANAGED_CREDENTIAL_FIELD_DEFAULTS).forEach(
      ([field, value]) => {
        form.setValue(
          field as keyof typeof MANAGED_CREDENTIAL_FIELD_DEFAULTS,
          value,
          {
            shouldDirty: false,
            shouldTouch: false,
          },
        );
      },
    );
  }, [form, isCertDeploymentEnabled, type]);

  if (
    requestedTypeParam === "DEPLOYMENT" &&
    requestedType === "DEPLOYMENT" &&
    !isCertDeploymentEnabled
  ) {
    return (
      <FeatureDisabledPage featureKey={FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT} />
    );
  }

  if (type === "DNS" && !isDnsCredentialsEnabled) {
    return <FeatureDisabledPage featureKey={FEATURE_FLAGS.DNS_CREDENTIALS} />;
  }

  return (
    <div
      className={cn(
        "space-y-6 p-6",
        selectedProviderOption && "mx-auto max-w-4xl",
      )}
    >
      <PageHeader
        title="Add integration"
        subtitle="Connect a DNS provider or add a deployment target"
        actions={
          <Button
            variant="outline"
            type="button"
            onClick={() => router.push(connectionsListHref(type))}
          >
            <span className="flex items-center justify-start gap-2">
              <ArrowLeftIcon className="h-4 w-4" />
              Back to integrations
            </span>
          </Button>
        }
      />
      <Card
        className={cn(
          "py-4",
          selectedProviderOption ? "bg-card" : "bg-secondary",
        )}
      >
        <CardContent className="w-full">
          <Form {...form}>
            <NoAutofillForm
              className="space-y-5"
              onSubmit={form.handleSubmit(async (payload) => {
                const normalizedPayload = usesManagedCredentials
                  ? {
                      ...normalizeCredentialAuthModesForAppMode(
                        payload,
                        usesManagedCredentials,
                      ),
                      ...(payload.provider === KUBERNETES_SECRETS_PROVIDER &&
                      !MANAGED_KUBERNETES_AUTH_METHODS.includes(
                        payload.k8sAuthMethod as KubernetesAuthMethod,
                      )
                        ? { k8sAuthMethod: "AZURE" as const }
                        : {}),
                    }
                  : payload;
                try {
                  const managedCredentialJson =
                    usesManagedCredentials ||
                    normalizedPayload.provider === "NAMECHEAP"
                      ? buildManagedCredentialJsonFromValues({
                          values: normalizedPayload,
                          mode: "create",
                          context: {
                            type: normalizedPayload.type,
                            providerApiValue: normalizedPayload.provider,
                            kubernetesAuthMethod:
                              normalizedPayload.k8sAuthMethod as KubernetesAuthMethod,
                            awsAcmAuthMode:
                              normalizedPayload.awsAcmAuthMode as AwsAcmAuthMode,
                            awsElbAuthMode:
                              normalizedPayload.awsElbAuthMode as AwsLoadBalancerAuthMode,
                            awsApiGwAuthMode:
                              normalizedPayload.awsApiGwAuthMode as AwsApiGwAuthMode,
                            awsCloudFrontAuthMode:
                              normalizedPayload.awsCloudFrontAuthMode as AwsCloudFrontAuthMode,
                            azureKvAuthMode:
                              normalizedPayload.azureKvAuthMode as AzureKvAuthMode,
                            azureAppGwAuthMode:
                              normalizedPayload.azureAppGwAuthMode as AzureAppGwAuthMode,
                            azureAgcAzureAuthMode:
                              normalizedPayload.azureAgcAzureAuthMode as AzureAgcAuthMode,
                            azureAgcClusterAuthMode:
                              normalizedPayload.azureAgcClusterAuthMode as AzureAgcClusterAuthMode,
                            azureAfdAuthMode:
                              normalizedPayload.azureAfdAuthMode as AzureAfdAuthMode,
                            gcpAuthMode:
                              normalizedPayload.gcpAuthMode as GcpAuthMode,
                            fallbackTemplate:
                              selectedProviderOption?.secretPayloadTemplate ||
                              "",
                          },
                        })
                      : undefined;
                  const storagePayload = usesManagedCredentials
                    ? {
                        credJson: managedCredentialJson || {},
                        secretHandle: null,
                      }
                    : {
                        ...buildCredentialSecretStoragePayload({
                          secretHandle: normalizedPayload.secretHandle,
                          isKvPathRequired,
                        }),
                        ...(normalizedPayload.provider === "NAMECHEAP"
                          ? { credJson: managedCredentialJson }
                          : {}),
                      };

                  if (
                    normalizedPayload.provider === KUBERNETES_SECRETS_PROVIDER
                  ) {
                    const namespaces =
                      normalizedPayload.k8sNamespaceMode === "all_namespaces"
                        ? KUBERNETES_ALL_NAMESPACES
                        : (normalizedPayload.k8sNamespaces || []).reduce<
                            string[]
                          >((namespaces, value) => {
                            const namespace = value.trim();
                            if (namespace) {
                              namespaces.push(namespace);
                            }
                            return namespaces;
                          }, []);
                    const config = kubernetesCredentialConfigSchema.parse({
                      authMethod: normalizedPayload.k8sAuthMethod,
                      clusterName: normalizedPayload.k8sClusterName,
                      namespaces,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAwsAcmProvider(normalizedPayload.provider)) {
                    const authMode = (normalizedPayload.awsAcmAuthMode ||
                      "STATIC_KEYS") as AwsAcmAuthMode;
                    const config = awsAcmCredentialConfigSchema.parse({
                      authMode,
                      region: normalizedPayload.awsAcmRegion,
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsAcmRoleArn?.trim()
                        ? { roleArn: normalizedPayload.awsAcmRoleArn.trim() }
                        : {}),
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsAcmExternalId?.trim()
                        ? {
                            externalId:
                              normalizedPayload.awsAcmExternalId.trim(),
                          }
                        : {}),
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (
                    isAwsLoadBalancerProvider(normalizedPayload.provider)
                  ) {
                    const listeners = (normalizedPayload.awsElbListeners || [])
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const authMode = (normalizedPayload.awsElbAuthMode ||
                      "STATIC_KEYS") as AwsLoadBalancerAuthMode;
                    const config = awsLoadBalancerCredentialConfigSchema.parse({
                      authMode,
                      region: normalizedPayload.awsElbRegion,
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsElbRoleArn?.trim()
                        ? { roleArn: normalizedPayload.awsElbRoleArn.trim() }
                        : {}),
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsElbExternalId?.trim()
                        ? {
                            externalId:
                              normalizedPayload.awsElbExternalId.trim(),
                          }
                        : {}),
                      listeners,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (
                    isAwsApiGatewayProvider(normalizedPayload.provider)
                  ) {
                    const customDomains = (
                      normalizedPayload.awsApiGwCustomDomains || []
                    )
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const authMode = (normalizedPayload.awsApiGwAuthMode ||
                      "STATIC_KEYS") as AwsApiGwAuthMode;
                    const config = awsApiGatewayCredentialConfigSchema.parse({
                      authMode,
                      region: normalizedPayload.awsApiGwRegion,
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsApiGwRoleArn?.trim()
                        ? { roleArn: normalizedPayload.awsApiGwRoleArn.trim() }
                        : {}),
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsApiGwExternalId?.trim()
                        ? {
                            externalId:
                              normalizedPayload.awsApiGwExternalId.trim(),
                          }
                        : {}),
                      customDomains,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (
                    isAwsCloudFrontProvider(normalizedPayload.provider)
                  ) {
                    const authMode = (normalizedPayload.awsCloudFrontAuthMode ||
                      "STATIC_KEYS") as AwsCloudFrontAuthMode;
                    const config = awsCloudFrontCredentialConfigSchema.parse({
                      authMode,
                      distributionId:
                        normalizedPayload.awsCloudFrontDistributionId,
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsCloudFrontRoleArn?.trim()
                        ? {
                            roleArn:
                              normalizedPayload.awsCloudFrontRoleArn.trim(),
                          }
                        : {}),
                      ...(authMode === "ASSUME_ROLE" &&
                      normalizedPayload.awsCloudFrontExternalId?.trim()
                        ? {
                            externalId:
                              normalizedPayload.awsCloudFrontExternalId.trim(),
                          }
                        : {}),
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAzureKvProvider(normalizedPayload.provider)) {
                    const config = azureKvCredentialConfigSchema.parse({
                      authMode: (normalizedPayload.azureKvAuthMode ||
                        "SERVICE_PRINCIPAL") as AzureKvAuthMode,
                      tenantId: normalizedPayload.azureKvTenantId?.trim() || "",
                      vaultUri: normalizedPayload.azureKvVaultUri,
                      ...(normalizedPayload.azureKvClientId?.trim()
                        ? {
                            clientId: normalizedPayload.azureKvClientId.trim(),
                          }
                        : {}),
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAzureAppGwProvider(normalizedPayload.provider)) {
                    const listeners = (
                      normalizedPayload.azureAppGwListeners || []
                    )
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const config = azureAppGwCredentialConfigSchema.parse({
                      authMode: (normalizedPayload.azureAppGwAuthMode ||
                        "SERVICE_PRINCIPAL") as AzureAppGwAuthMode,
                      tenantId: normalizedPayload.azureAppGwTenantId,
                      subscriptionId:
                        normalizedPayload.azureAppGwSubscriptionId,
                      ...(normalizedPayload.azureAppGwClientId?.trim()
                        ? {
                            clientId:
                              normalizedPayload.azureAppGwClientId.trim(),
                          }
                        : {}),
                      resourceGroup: normalizedPayload.azureAppGwResourceGroup,
                      appGateway: normalizedPayload.azureAppGwAppGateway,
                      listeners,
                      keyVaultUri: normalizedPayload.azureAppGwKeyVaultUri,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAzureAgcProvider(normalizedPayload.provider)) {
                    const secretNamespaces = (
                      normalizedPayload.azureAgcSecretNamespaces || []
                    )
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const config = azureAgcCredentialConfigSchema.parse({
                      azureAuthMode: (normalizedPayload.azureAgcAzureAuthMode ||
                        "SERVICE_PRINCIPAL") as AzureAgcAuthMode,
                      tenantId: normalizedPayload.azureAgcTenantId,
                      subscriptionId: normalizedPayload.azureAgcSubscriptionId,
                      resourceGroup: normalizedPayload.azureAgcResourceGroup,
                      ...(normalizedPayload.azureAgcClientId?.trim()
                        ? {
                            clientId: normalizedPayload.azureAgcClientId.trim(),
                          }
                        : {}),
                      clusterAuthMode:
                        (normalizedPayload.azureAgcClusterAuthMode ||
                          "AZURE") as AzureAgcClusterAuthMode,
                      clusterName: normalizedPayload.azureAgcClusterName,
                      agcNamespace: normalizedPayload.azureAgcNamespace,
                      apiStyle: (normalizedPayload.azureAgcApiStyle ||
                        "GATEWAY_API") as AzureAgcApiStyle,
                      secretNamespaces,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAzureAfdProvider(normalizedPayload.provider)) {
                    const customDomains = (
                      normalizedPayload.azureAfdCustomDomains || []
                    )
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const config = azureAfdCredentialConfigSchema.parse({
                      authMode: (normalizedPayload.azureAfdAuthMode ||
                        "SERVICE_PRINCIPAL") as AzureAfdAuthMode,
                      tenantId: normalizedPayload.azureAfdTenantId,
                      subscriptionId: normalizedPayload.azureAfdSubscriptionId,
                      ...(normalizedPayload.azureAfdClientId?.trim()
                        ? {
                            clientId: normalizedPayload.azureAfdClientId.trim(),
                          }
                        : {}),
                      resourceGroup: normalizedPayload.azureAfdResourceGroup,
                      profileName: normalizedPayload.azureAfdProfileName,
                      keyVaultUri: normalizedPayload.azureAfdKeyVaultUri,
                      customDomains,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (
                    isGcpCertManagerProvider(normalizedPayload.provider)
                  ) {
                    const authMode = (normalizedPayload.gcpAuthMode ||
                      "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
                    const config = gcpCertManagerCredentialConfigSchema.parse({
                      authMode,
                      projectId: normalizedPayload.gcpProjectId,
                      location: normalizedPayload.gcpLocation,
                      ...(authMode === "IMPERSONATE_SERVICE_ACCOUNT" &&
                      normalizedPayload.gcpImpersonateServiceAccount?.trim()
                        ? {
                            impersonateServiceAccount:
                              normalizedPayload.gcpImpersonateServiceAccount.trim(),
                          }
                        : {}),
                      ...(normalizedPayload.gcpCertManagerCertificateMap?.trim()
                        ? {
                            certificateMap:
                              normalizedPayload.gcpCertManagerCertificateMap.trim(),
                          }
                        : {}),
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isGcpProxyProvider(normalizedPayload.provider)) {
                    const normalized = normalizedPayload.provider
                      .trim()
                      .toUpperCase();
                    const authMode = (normalizedPayload.gcpAuthMode ||
                      "SERVICE_ACCOUNT_KEY") as GcpAuthMode;
                    const config = gcpProxyCredentialConfigSchema.parse({
                      authMode,
                      projectId: normalizedPayload.gcpProjectId,
                      location: normalizedPayload.gcpLocation,
                      ...(authMode === "IMPERSONATE_SERVICE_ACCOUNT" &&
                      normalizedPayload.gcpImpersonateServiceAccount?.trim()
                        ? {
                            impersonateServiceAccount:
                              normalizedPayload.gcpImpersonateServiceAccount.trim(),
                          }
                        : {}),
                      ...(normalized === "GCP_PROXY_NLB"
                        ? {
                            targetSslProxy:
                              normalizedPayload.gcpProxyTargetSslProxy,
                          }
                        : {
                            targetProxy:
                              normalizedPayload.gcpProxyTargetHttpsProxy,
                          }),
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (
                    isCloudflareEdgeProvider(normalizedPayload.provider)
                  ) {
                    const config = cloudflareEdgeCredentialConfigSchema.parse({
                      zoneId: normalizedPayload.cloudflareZoneId,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isAkamaiCpsProvider(normalizedPayload.provider)) {
                    const config = akamaiCpsCredentialConfigSchema.parse({
                      host: normalizedPayload.akamaiHost,
                      enrollmentId: normalizedPayload.akamaiEnrollmentId,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else if (isF5BigipProvider(normalizedPayload.provider)) {
                    const clientSslProfiles = (
                      normalizedPayload.f5BigipClientSslProfiles || []
                    )
                      .map((value) => value.trim())
                      .filter((value) => value.length > 0);
                    const config = f5BigipCredentialConfigSchema.parse({
                      bigipHost: normalizedPayload.f5BigipHost,
                      partition: normalizedPayload.f5BigipPartition,
                      clientSslProfiles,
                    });
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                      configJson: config,
                    });
                  } else {
                    await createCredential.mutateAsync({
                      type: normalizedPayload.type,
                      provider: normalizedPayload.provider,
                      description: normalizedPayload.description,
                      ...storagePayload,
                    });
                  }
                } catch (error) {
                  if (error instanceof CredentialFieldError) {
                    form.setError(
                      error.field as keyof CreateCredentialFormValues,
                      {
                        type: "custom",
                        message: error.message,
                      },
                    );
                    toast.error(error.message);
                  }
                  return;
                }

                // Clear "dirty" state before navigating so the unsaved-changes guard won't interfere.
                form.reset(payload, { keepDirty: false });
                setSuppressUnsavedWarning(true);
                router.push(returnTo ?? connectionsListHref(type));
                router.refresh();
              })}
            >
              {!selectedProviderOption ? (
                <Tabs
                  value={type}
                  onValueChange={(value) =>
                    form.setValue("type", value as CredentialReferenceType, {
                      shouldDirty: false,
                    })
                  }
                >
                  <TabsList className="w-fit">
                    {isCertDeploymentEnabled ? (
                      <TabsTrigger value="DEPLOYMENT">Deployment</TabsTrigger>
                    ) : null}
                    {isDnsCredentialsEnabled ? (
                      <TabsTrigger value="DNS">DNS</TabsTrigger>
                    ) : null}
                  </TabsList>
                </Tabs>
              ) : null}

              {!selectedProviderOption ? (
                <div className="space-y-2">
                  <CredentialProviderSelector
                    options={providerOptions}
                    selectedProviderApiValue={provider}
                    onSelectProvider={(apiValue) => {
                      form.setValue("provider", apiValue, {
                        shouldDirty: false,
                        shouldValidate: true,
                      });
                      form.setValue("credJson", "", {
                        shouldDirty: false,
                        shouldTouch: false,
                      });
                      Object.entries(MANAGED_CREDENTIAL_FIELD_DEFAULTS).forEach(
                        ([field, value]) => {
                          form.setValue(
                            field as keyof typeof MANAGED_CREDENTIAL_FIELD_DEFAULTS,
                            value,
                            {
                              shouldDirty: false,
                              shouldTouch: false,
                            },
                          );
                        },
                      );
                    }}
                  />
                  <FormField
                    control={form.control}
                    name="provider"
                    render={() => <FormMessage />}
                  />
                </div>
              ) : null}

              {selectedProviderOption ? (
                <>
                  <div className="flex w-full flex-col gap-3">
                    <CredentialSelectedProviderBanner
                      label={selectedProviderOption.label}
                      description={selectedProviderOption.description}
                      docsUrl={selectedProviderOption.docs}
                      providerKey={selectedProviderOption.providerKey}
                      providerApiValue={selectedProviderOption.apiValue}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="w-fit shrink-0"
                      onClick={() => {
                        form.setValue("provider", "", {
                          shouldDirty: false,
                          shouldTouch: false,
                        });
                        form.setValue("credJson", "", {
                          shouldDirty: false,
                          shouldTouch: false,
                        });
                        Object.entries(
                          MANAGED_CREDENTIAL_FIELD_DEFAULTS,
                        ).forEach(([field, value]) => {
                          form.setValue(
                            field as keyof typeof MANAGED_CREDENTIAL_FIELD_DEFAULTS,
                            value,
                            {
                              shouldDirty: false,
                              shouldTouch: false,
                            },
                          );
                        });
                      }}
                    >
                      <ArrowLeftIcon className="mr-1 h-3.5 w-3.5" />
                      Change target
                    </Button>
                  </div>

                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Name</FormLabel>
                        <FormControl>
                          <Input className="h-10 md:max-w-xl" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {canChooseStorage ? (
                    <CredentialStorageChoice
                      value={credentialStorage}
                      onChange={(next) =>
                        form.setValue("credentialStorage", next, {
                          shouldDirty: true,
                          shouldValidate: false,
                        })
                      }
                    />
                  ) : null}

                  <CredentialProviderFields
                    form={form}
                    providerApiValue={provider}
                    kubernetesAuthMethod={k8sAuthMethod as KubernetesAuthMethod}
                    awsAcmAuthMode={awsAcmAuthMode as AwsAcmAuthMode}
                    awsElbAuthMode={awsElbAuthMode as AwsLoadBalancerAuthMode}
                    awsApiGwAuthMode={awsApiGwAuthMode as AwsApiGwAuthMode}
                    awsCloudFrontAuthMode={
                      awsCloudFrontAuthMode as AwsCloudFrontAuthMode
                    }
                    azureKvAuthMode={azureKvAuthMode as AzureKvAuthMode}
                    azureAppGwAuthMode={
                      azureAppGwAuthMode as AzureAppGwAuthMode
                    }
                    azureAgcAzureAuthMode={
                      azureAgcAzureAuthMode as AzureAgcAuthMode
                    }
                    azureAgcClusterAuthMode={
                      azureAgcClusterAuthMode as AzureAgcClusterAuthMode
                    }
                    azureAgcApiStyle={azureAgcApiStyle as AzureAgcApiStyle}
                    azureAfdAuthMode={azureAfdAuthMode as AzureAfdAuthMode}
                    gcpAuthMode={gcpAuthMode as GcpAuthMode}
                    showKubernetesStorageInstruction={!usesManagedCredentials}
                    allowedKubernetesAuthMethods={
                      usesManagedCredentials
                        ? MANAGED_KUBERNETES_AUTH_METHODS
                        : undefined
                    }
                    usesManagedCredentials={usesManagedCredentials}
                  />

                  {usesManagedCredentials || provider === "NAMECHEAP" ? (
                    <ManagedCredentialFields
                      form={form}
                      mode="create"
                      type={type}
                      providerApiValue={provider}
                      kubernetesAuthMethod={
                        k8sAuthMethod as KubernetesAuthMethod
                      }
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
                              providerApiValue={provider}
                            />
                          </div>
                          <FormControl>
                            <Input
                              className="h-10 md:max-w-xl"
                              placeholder="https://<vault>.vault.azure.net/secrets/<name>/<version>"
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ) : !usesManagedCredentials ? (
                    <Alert>
                      <AlertTitle>Secret handle not required</AlertTitle>
                      <AlertDescription>
                        This auth mode uses runtime identity and does not
                        require a secret handle.
                      </AlertDescription>
                    </Alert>
                  ) : null}

                  {!usesManagedCredentials ? (
                    <CredentialSecretPayloadCard
                      payloadTemplate={payloadTemplate}
                      providerApiValue={provider}
                      storageMode="kvPath"
                    />
                  ) : null}

                  <CredentialPageActions
                    isSaving={createCredential.isPending}
                    onCancel={() => router.push(connectionsListHref(type))}
                    submitLabel={
                      createCredential.isPending
                        ? "Saving..."
                        : "Save credential"
                    }
                  />
                </>
              ) : null}
            </NoAutofillForm>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
