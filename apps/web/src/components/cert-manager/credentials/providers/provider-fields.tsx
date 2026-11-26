// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

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
import type { AzureAfdAuthMode } from "@/lib/credential-config-schemas/azure-afd";
import type { AzureKvAuthMode } from "@/lib/credential-config-schemas/azure-kv";
import type { GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";
import type { KubernetesAuthMethod } from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  getManagedAwsAuthModes,
  getManagedAzureAuthModes,
  getManagedGcpAuthModes,
} from "@/lib/cert-manager/deployment-auth-mode-policy";
import { AwsAcmFields } from "@/components/cert-manager/credentials/providers/aws-acm-fields";
import { AwsAlbFields } from "@/components/cert-manager/credentials/providers/aws-alb-fields";
import { AwsApiGwHttpFields } from "@/components/cert-manager/credentials/providers/aws-api-gw-http-fields";
import { AwsApiGwRestFields } from "@/components/cert-manager/credentials/providers/aws-api-gw-rest-fields";
import { AwsCloudFrontFields } from "@/components/cert-manager/credentials/providers/aws-cloudfront-fields";
import { AwsNlbFields } from "@/components/cert-manager/credentials/providers/aws-nlb-fields";
import { AzureAppGatewayContainersFields } from "@/components/cert-manager/credentials/providers/azure-app-gateway-containers-fields";
import { AzureAppGatewayFields } from "@/components/cert-manager/credentials/providers/azure-app-gateway-fields";
import { AzureFrontDoorFields } from "@/components/cert-manager/credentials/providers/azure-front-door-fields";
import { AzureKvFields } from "@/components/cert-manager/credentials/providers/azure-kv-fields";
import { AkamaiCpsFields } from "@/components/cert-manager/credentials/providers/akamai-cps-fields";
import { CloudflareEdgeFields } from "@/components/cert-manager/credentials/providers/cloudflare-edge-fields";
import { F5BigipFields } from "@/components/cert-manager/credentials/providers/f5-bigip-fields";
import { KubernetesSecretsFields } from "@/components/cert-manager/credentials/providers/kubernetes-secrets-fields";
import { KvOnlyFields } from "@/components/cert-manager/credentials/providers/kv-only-fields";
import { GcpCertManagerFields } from "@/components/cert-manager/credentials/providers/gcp-cert-manager-fields";
import { GcpProxyFields } from "@/components/cert-manager/credentials/providers/gcp-proxy-fields";

export function CredentialProviderFields<TFieldValues extends FieldValues>({
  form,
  providerApiValue,
  kubernetesAuthMethod,
  awsAcmAuthMode,
  awsElbAuthMode,
  awsApiGwAuthMode,
  awsCloudFrontAuthMode,
  azureKvAuthMode,
  azureAppGwAuthMode,
  azureAgcAzureAuthMode,
  azureAgcClusterAuthMode,
  azureAgcApiStyle,
  azureAfdAuthMode,
  gcpAuthMode,
  showKubernetesStorageInstruction = true,
  allowedKubernetesAuthMethods,
  usesManagedCredentials = false,
}: {
  form: UseFormReturn<TFieldValues>;
  providerApiValue: string;
  kubernetesAuthMethod: KubernetesAuthMethod;
  awsAcmAuthMode: AwsAcmAuthMode;
  awsElbAuthMode: AwsLoadBalancerAuthMode;
  awsApiGwAuthMode: AwsApiGwAuthMode;
  awsCloudFrontAuthMode: AwsCloudFrontAuthMode;
  azureKvAuthMode: AzureKvAuthMode;
  azureAppGwAuthMode: AzureAppGwAuthMode;
  azureAgcAzureAuthMode: AzureAgcAuthMode;
  azureAgcClusterAuthMode: AzureAgcClusterAuthMode;
  azureAgcApiStyle: AzureAgcApiStyle;
  azureAfdAuthMode: AzureAfdAuthMode;
  gcpAuthMode: GcpAuthMode;
  showKubernetesStorageInstruction?: boolean;
  allowedKubernetesAuthMethods?: readonly KubernetesAuthMethod[];
  usesManagedCredentials?: boolean;
}) {
  const allowedAwsAuthModes = getManagedAwsAuthModes(usesManagedCredentials);
  const allowedAzureAuthModes = getManagedAzureAuthModes(
    usesManagedCredentials,
  );
  const allowedGcpAuthModes = getManagedGcpAuthModes(usesManagedCredentials);

  switch ((providerApiValue || "").trim().toUpperCase()) {
    case "KUBERNETES_SECRETS":
      return (
        <KubernetesSecretsFields
          form={form}
          authMethod={kubernetesAuthMethod}
          showStorageInstruction={showKubernetesStorageInstruction}
          allowedAuthMethods={allowedKubernetesAuthMethods}
        />
      );
    case "AWS_ACM":
      return (
        <AwsAcmFields
          form={form}
          authMode={awsAcmAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "AZURE_KV":
      return (
        <AzureKvFields
          form={form}
          authMode={azureKvAuthMode}
          allowedAuthModes={allowedAzureAuthModes}
        />
      );
    case "AZURE_APP_GW":
      return (
        <AzureAppGatewayFields
          form={form}
          authMode={azureAppGwAuthMode}
          allowedAuthModes={allowedAzureAuthModes}
          showServicePrincipalClientId={usesManagedCredentials}
        />
      );
    case "AZURE_APP_GW_CONTAINERS":
      return (
        <AzureAppGatewayContainersFields
          form={form}
          azureAuthMode={azureAgcAzureAuthMode}
          clusterAuthMode={azureAgcClusterAuthMode}
          apiStyle={azureAgcApiStyle}
          allowedAzureAuthModes={allowedAzureAuthModes}
          showServicePrincipalClientId={usesManagedCredentials}
        />
      );
    case "AZURE_AFD":
      return (
        <AzureFrontDoorFields
          form={form}
          authMode={azureAfdAuthMode}
          allowedAuthModes={allowedAzureAuthModes}
          showServicePrincipalClientId={usesManagedCredentials}
        />
      );
    case "AWS_ALB":
      return (
        <AwsAlbFields
          form={form}
          authMode={awsElbAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "AWS_NLB":
      return (
        <AwsNlbFields
          form={form}
          authMode={awsElbAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "AWS_API_GW_REST":
      return (
        <AwsApiGwRestFields
          form={form}
          authMode={awsApiGwAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "AWS_API_GW_HTTP":
      return (
        <AwsApiGwHttpFields
          form={form}
          authMode={awsApiGwAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "AWS_CLOUDFRONT":
      return (
        <AwsCloudFrontFields
          form={form}
          authMode={awsCloudFrontAuthMode}
          allowedAuthModes={allowedAwsAuthModes}
        />
      );
    case "GCP_CERT_MANAGER":
      return (
        <GcpCertManagerFields
          form={form}
          authMode={gcpAuthMode}
          allowedAuthModes={allowedGcpAuthModes}
        />
      );
    case "GCP_ALB":
    case "GCP_API_GW":
    case "GCP_CLOUD_CDN":
    case "GCP_PROXY_NLB":
      return (
        <GcpProxyFields
          form={form}
          authMode={gcpAuthMode}
          providerApiValue={providerApiValue}
          allowedAuthModes={allowedGcpAuthModes}
        />
      );
    case "CLOUDFLARE_EDGE":
      return <CloudflareEdgeFields form={form} />;
    case "AKAMAI_CPS":
      return <AkamaiCpsFields form={form} />;
    case "F5_BIGIP":
      return <F5BigipFields form={form} />;
    default:
      return <KvOnlyFields />;
  }
}
