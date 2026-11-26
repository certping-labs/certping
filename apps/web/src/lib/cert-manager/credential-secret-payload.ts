// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  getAwsApiGatewayAuthModeSecretTemplate,
  isAwsApiGatewayKvPathRequired,
  isAwsApiGatewayProvider,
  type AwsApiGwAuthMode,
} from "@/lib/credential-config-schemas/aws-api-gateway";
import {
  getAwsCloudFrontAuthModeSecretTemplate,
  isAwsCloudFrontKvPathRequired,
  isAwsCloudFrontProvider,
  type AwsCloudFrontAuthMode,
} from "@/lib/credential-config-schemas/aws-cloudfront";
import {
  getAwsAcmAuthModeSecretTemplate,
  isAwsAcmKvPathRequired,
  isAwsAcmProvider,
  type AwsAcmAuthMode,
} from "@/lib/credential-config-schemas/aws-acm";
import {
  getAwsLoadBalancerAuthModeSecretTemplate,
  isAwsLoadBalancerKvPathRequired,
  isAwsLoadBalancerProvider,
  type AwsLoadBalancerAuthMode,
} from "@/lib/credential-config-schemas/aws-load-balancer";
import {
  getAzureKvAuthModeSecretTemplate,
  isAzureKvKvPathRequired,
  isAzureKvProvider,
  type AzureKvAuthMode,
} from "@/lib/credential-config-schemas/azure-kv";
import {
  isAzureAppGwKvPathRequired,
  isAzureAppGwProvider,
  type AzureAppGwAuthMode,
} from "@/lib/credential-config-schemas/azure-app-gw";
import {
  isAzureAgcKvPathRequired,
  isAzureAgcProvider,
  type AzureAgcAuthMode,
  type AzureAgcClusterAuthMode,
} from "@/lib/credential-config-schemas/azure-agc";
import {
  isAzureAfdKvPathRequired,
  isAzureAfdProvider,
  type AzureAfdAuthMode,
} from "@/lib/credential-config-schemas/azure-afd";
import {
  getGcpAuthModeSecretTemplate,
  isGcpKvPathRequired,
  type GcpAuthMode,
} from "@/lib/credential-config-schemas/gcp-shared";
import { isGcpCertManagerProvider } from "@/lib/credential-config-schemas/gcp-cert-manager";
import { isGcpProxyProvider } from "@/lib/credential-config-schemas/gcp-proxy";
import {
  getKubernetesAuthMethodSecretTemplate,
  isKubernetesSecretsTarget,
  type KubernetesAuthMethod,
} from "@/lib/credential-config-schemas/kubernetes-secrets";

export function isCredentialKvPathRequired(params: {
  providerApiValue?: string | null;
  kubernetesAuthMethod?: KubernetesAuthMethod | null;
  awsAcmAuthMode?: AwsAcmAuthMode | null;
  awsElbAuthMode?: AwsLoadBalancerAuthMode | null;
  awsApiGwAuthMode?: AwsApiGwAuthMode | null;
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode | null;
  azureKvAuthMode?: AzureKvAuthMode | null;
  azureAppGwAuthMode?: AzureAppGwAuthMode | null;
  azureAgcAzureAuthMode?: AzureAgcAuthMode | null;
  azureAgcClusterAuthMode?: AzureAgcClusterAuthMode | null;
  azureAfdAuthMode?: AzureAfdAuthMode | null;
  gcpAuthMode?: GcpAuthMode | null;
}): boolean {
  const provider = (params.providerApiValue || "").trim();

  if (isKubernetesSecretsTarget(provider)) {
    return (params.kubernetesAuthMethod || "SA_INCLUSTER") !== "SA_INCLUSTER";
  }
  if (isAwsAcmProvider(provider)) {
    return isAwsAcmKvPathRequired(params.awsAcmAuthMode || "STATIC_KEYS");
  }
  if (isAwsLoadBalancerProvider(provider)) {
    return isAwsLoadBalancerKvPathRequired(
      params.awsElbAuthMode || "STATIC_KEYS",
    );
  }
  if (isAwsApiGatewayProvider(provider)) {
    return isAwsApiGatewayKvPathRequired(
      params.awsApiGwAuthMode || "STATIC_KEYS",
    );
  }
  if (isAwsCloudFrontProvider(provider)) {
    return isAwsCloudFrontKvPathRequired(
      params.awsCloudFrontAuthMode || "STATIC_KEYS",
    );
  }
  if (isAzureKvProvider(provider)) {
    return isAzureKvKvPathRequired(
      params.azureKvAuthMode || "SERVICE_PRINCIPAL",
    );
  }
  if (isAzureAppGwProvider(provider)) {
    return isAzureAppGwKvPathRequired(
      params.azureAppGwAuthMode || "SERVICE_PRINCIPAL",
    );
  }
  if (isAzureAgcProvider(provider)) {
    return isAzureAgcKvPathRequired({
      azureAuthMode: params.azureAgcAzureAuthMode || "SERVICE_PRINCIPAL",
      clusterAuthMode: params.azureAgcClusterAuthMode || "AZURE",
    });
  }
  if (isAzureAfdProvider(provider)) {
    return isAzureAfdKvPathRequired(
      params.azureAfdAuthMode || "SERVICE_PRINCIPAL",
    );
  }
  if (isGcpCertManagerProvider(provider) || isGcpProxyProvider(provider)) {
    return isGcpKvPathRequired(params.gcpAuthMode || "SERVICE_ACCOUNT_KEY");
  }

  return true;
}

export function getCredentialSecretPayloadTemplate(params: {
  providerApiValue?: string | null;
  kubernetesAuthMethod?: KubernetesAuthMethod | null;
  awsAcmAuthMode?: AwsAcmAuthMode | null;
  awsElbAuthMode?: AwsLoadBalancerAuthMode | null;
  awsApiGwAuthMode?: AwsApiGwAuthMode | null;
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode | null;
  azureKvAuthMode?: AzureKvAuthMode | null;
  azureAppGwAuthMode?: AzureAppGwAuthMode | null;
  azureAgcAzureAuthMode?: AzureAgcAuthMode | null;
  azureAgcClusterAuthMode?: AzureAgcClusterAuthMode | null;
  azureAfdAuthMode?: AzureAfdAuthMode | null;
  gcpAuthMode?: GcpAuthMode | null;
  providerTemplate?: string | null;
}): string {
  const provider = (params.providerApiValue || "").trim();

  if (isKubernetesSecretsTarget(provider)) {
    if ((params.kubernetesAuthMethod || "SA_INCLUSTER") === "SA_INCLUSTER") {
      return "";
    }
    return getKubernetesAuthMethodSecretTemplate(
      (params.kubernetesAuthMethod || "SA_INCLUSTER") as KubernetesAuthMethod,
    );
  }
  if (isAwsAcmProvider(provider)) {
    if ((params.awsAcmAuthMode || "STATIC_KEYS") === "INSTANCE_PROFILE") {
      return "";
    }
    return getAwsAcmAuthModeSecretTemplate(
      params.awsAcmAuthMode || "STATIC_KEYS",
    );
  }
  if (isAwsLoadBalancerProvider(provider)) {
    if ((params.awsElbAuthMode || "STATIC_KEYS") === "INSTANCE_PROFILE") {
      return "";
    }
    return getAwsLoadBalancerAuthModeSecretTemplate(
      params.awsElbAuthMode || "STATIC_KEYS",
    );
  }
  if (isAwsApiGatewayProvider(provider)) {
    if ((params.awsApiGwAuthMode || "STATIC_KEYS") === "INSTANCE_PROFILE") {
      return "";
    }
    return getAwsApiGatewayAuthModeSecretTemplate(
      params.awsApiGwAuthMode || "STATIC_KEYS",
    );
  }
  if (isAwsCloudFrontProvider(provider)) {
    if (
      (params.awsCloudFrontAuthMode || "STATIC_KEYS") === "INSTANCE_PROFILE"
    ) {
      return "";
    }
    return getAwsCloudFrontAuthModeSecretTemplate(
      params.awsCloudFrontAuthMode || "STATIC_KEYS",
    );
  }
  if (isAzureKvProvider(provider)) {
    if (
      (params.azureKvAuthMode || "SERVICE_PRINCIPAL") === "WORKLOAD_IDENTITY"
    ) {
      return "";
    }
    return getAzureKvAuthModeSecretTemplate(
      params.azureKvAuthMode || "SERVICE_PRINCIPAL",
    );
  }
  if (isAzureAppGwProvider(provider)) {
    if (
      (params.azureAppGwAuthMode || "SERVICE_PRINCIPAL") === "WORKLOAD_IDENTITY"
    ) {
      return "";
    }
    return getAzureKvAuthModeSecretTemplate("SERVICE_PRINCIPAL");
  }
  if (isAzureAgcProvider(provider)) {
    const azureAuthMode = params.azureAgcAzureAuthMode || "SERVICE_PRINCIPAL";
    const clusterAuthMode = params.azureAgcClusterAuthMode || "AZURE";
    if (!isAzureAgcKvPathRequired({ azureAuthMode, clusterAuthMode })) {
      return "";
    }
    return getAzureKvAuthModeSecretTemplate("SERVICE_PRINCIPAL");
  }
  if (isAzureAfdProvider(provider)) {
    if (
      (params.azureAfdAuthMode || "SERVICE_PRINCIPAL") === "WORKLOAD_IDENTITY"
    ) {
      return "";
    }
    return getAzureKvAuthModeSecretTemplate("SERVICE_PRINCIPAL");
  }
  if (isGcpCertManagerProvider(provider) || isGcpProxyProvider(provider)) {
    const authMode = params.gcpAuthMode || "SERVICE_ACCOUNT_KEY";
    if (authMode !== "SERVICE_ACCOUNT_KEY") {
      return "";
    }
    return getGcpAuthModeSecretTemplate(authMode);
  }

  return params.providerTemplate || "";
}
