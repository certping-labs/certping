// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { InfoIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getKubernetesAuthMethodInstruction,
  getKubernetesAuthMethodLabel,
  type KubernetesAuthMethod,
} from "@/lib/credential-config-schemas/kubernetes-secrets";

const PROVIDER_GUIDANCE: Record<string, readonly string[]> = {
  AZURE_KV: [
    "Grant Key Vault Certificates Officer on the target Key Vault, or use a custom role with certificate import/create/update access.",
    "If the agent only reads deployment secrets from Key Vault, grant its runtime identity Key Vault Secrets User separately.",
  ],
  AZURE_APP_GW: [
    "Grant Key Vault certificate import access and Application Gateway read/write access, including Microsoft.Network/applicationGateways/read and Microsoft.Network/applicationGateways/write.",
    "Network Contributor is a practical built-in role for Application Gateway updates, but a scoped custom role is preferred.",
    "The Application Gateway managed identity must also be able to read the certificate secret from Key Vault.",
  ],
  AZURE_AFD: [
    "Grant Key Vault certificate import access and read/write access to the target Azure Front Door profile secrets and custom domains under Microsoft.Cdn/profiles/...",
    "Authorize Azure Front Door to retrieve the certificate from Key Vault.",
  ],
  AZURE_APP_GW_CONTAINERS: [
    "For AKS authentication, grant Azure Kubernetes Service Cluster User Role so the identity can obtain cluster user credentials.",
    "Also grant Kubernetes secret-writer RBAC in every target namespace: get, create, update, and delete secrets.",
    getPrivateKubernetesConnectivityGuidance(),
  ],
  AWS_ACM: [
    "Grant acm:ImportCertificate on the intended AWS Certificate Manager resources.",
    "For certificate discovery, also grant the read-only acm:ListCertificates and acm:DescribeCertificate.",
    "acm:GetCertificate is optional - discovery uses it only to resolve the key algorithm of imported certificates; without it those rows show the key algorithm as Unknown.",
    "Limit access to the intended AWS account and region.",
  ],
  AWS_ALB: [
    "Grant acm:ImportCertificate, elasticloadbalancing:AddListenerCertificates, and elasticloadbalancing:RemoveListenerCertificates.",
    "Limit access to the intended AWS account, region, and listeners.",
  ],
  AWS_NLB: [
    "Grant acm:ImportCertificate, elasticloadbalancing:AddListenerCertificates, and elasticloadbalancing:RemoveListenerCertificates.",
    "Limit access to the intended AWS account, region, and listeners.",
  ],
  AWS_API_GW_REST: [
    "Grant acm:ImportCertificate, apigateway:GET, and apigateway:PATCH.",
    "Limit access to the intended AWS account, region, and domain names.",
  ],
  AWS_API_GW_HTTP: [
    "Grant acm:ImportCertificate and apigateway:PATCH.",
    "Limit access to the intended AWS account, region, and domain names.",
  ],
  AWS_CLOUDFRONT: [
    "Grant acm:ImportCertificate, acm:DeleteCertificate, cloudfront:GetDistribution, cloudfront:GetDistributionConfig, and cloudfront:UpdateDistribution.",
    "CloudFront certificates must be stored in the us-east-1 AWS region.",
  ],
  GCP_CERT_MANAGER: [
    "Grant Certificate Manager Editor, or a custom role that can create, update, and delete certificates and manage selected certificate map entries.",
    "Limit access to the intended Google Cloud project and resources.",
  ],
  GCP_ALB: [
    "Grant a custom Compute role that can create, get, and delete SSL certificates and get and update the selected HTTPS proxy. If the proxy has a certificate map, also grant Certificate Manager Editor in the map's project.",
    "Limit access to the intended Google Cloud project and proxy.",
  ],
  GCP_API_GW: [
    "Grant a custom Compute role that can create, get, and delete SSL certificates and get and update the selected HTTPS proxy. If the proxy has a certificate map, also grant Certificate Manager Editor in the map's project.",
    "Limit access to the intended Google Cloud project and proxy.",
  ],
  GCP_CLOUD_CDN: [
    "Grant a custom Compute role that can create, get, and delete SSL certificates and get and update the selected HTTPS proxy. If the proxy has a certificate map, also grant Certificate Manager Editor in the map's project.",
    "Limit access to the intended Google Cloud project and proxy.",
  ],
  GCP_PROXY_NLB: [
    "Grant a custom Compute role that can create, get, and delete SSL certificates and get and update the selected target SSL proxy. If the proxy has a certificate map, also grant Certificate Manager Editor in the map's project.",
    "Limit access to the intended Google Cloud project and proxy.",
  ],
  CLOUDFLARE_EDGE: [
    "Create a restricted Cloudflare API token with Zone read access and SSL and Certificates edit access.",
    "Restrict the token to the exact accounts and zones this credential will manage. Do not use the global API key.",
  ],
  AKAMAI_CPS: [
    "Create an EdgeGrid API client authorized for the selected CPS enrollments and contracts.",
    "Grant only the access needed to read enrollment state and activate certificate changes on the selected network.",
  ],
  F5_BIGIP: [
    "Use a dedicated BIG-IP account that can upload and install certificates and update client SSL profiles in the selected partitions.",
    "Confirm the agent can reach the BIG-IP management endpoint.",
  ],
};

const DEFAULT_GUIDANCE = [
  "Choose the least-privileged identity that can update this deployment target.",
  "Use a dedicated credential, restrict it to the selected resources, and confirm the agent can reach private endpoints.",
] as const;

function getPrivateKubernetesConnectivityGuidance() {
  return "For private clusters, confirm the agent can resolve and reach the Kubernetes API endpoint.";
}

function GuidanceList({ items }: { items: readonly string[] }) {
  return (
    <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function KubernetesContent({
  authMethod,
}: {
  authMethod?: KubernetesAuthMethod;
}) {
  const kubernetesItems =
    authMethod === "AZURE"
      ? [
          "Grant Azure Kubernetes Service Cluster User Role so the Azure identity can obtain AKS user credentials.",
          "Also grant Kubernetes secret-writer RBAC in every target namespace: get, create, update, and delete secrets.",
          "For AKS with Azure RBAC for Kubernetes Authorization, use an appropriately scoped Azure Kubernetes Service RBAC role or a custom role that permits secret operations.",
          getPrivateKubernetesConnectivityGuidance(),
        ]
      : [
          "Grant Kubernetes secret-writer RBAC in every target namespace: get, create, update, and delete secrets.",
          "When deploying to all namespaces, also grant permission to list namespaces.",
          "Prefer namespace-scoped Role and RoleBinding objects; use ClusterRole only for all-namespaces or deliberate cluster-wide deployments.",
          getPrivateKubernetesConnectivityGuidance(),
        ];

  return (
    <div className="space-y-4">
      {authMethod ? (
        <div className="space-y-1">
          <p className="text-sm font-medium">
            {getKubernetesAuthMethodLabel(authMethod)}
          </p>
          <p className="text-sm text-muted-foreground">
            {getKubernetesAuthMethodInstruction(authMethod)}
          </p>
        </div>
      ) : null}
      <GuidanceList items={kubernetesItems} />
    </div>
  );
}

function Content({
  kubernetesAuthMethod,
  provider,
}: {
  kubernetesAuthMethod?: KubernetesAuthMethod;
  provider: string;
}) {
  if (provider === "KUBERNETES_SECRETS") {
    return <KubernetesContent authMethod={kubernetesAuthMethod} />;
  }

  return (
    <GuidanceList items={PROVIDER_GUIDANCE[provider] ?? DEFAULT_GUIDANCE} />
  );
}

export function CredentialProviderInfoDialog({
  kubernetesAuthMethod,
  providerApiValue,
}: {
  kubernetesAuthMethod?: KubernetesAuthMethod;
  providerApiValue?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const provider = (providerApiValue || "").trim().toUpperCase();

  return (
    <>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="h-9 gap-2"
        onClick={() => setOpen(true)}
        aria-label="Open credential setup guidance"
      >
        <InfoIcon className="h-4 w-4" />
        <span className="text-xs">Setup help</span>
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Credential setup guidance</DialogTitle>
            <DialogDescription>
              Authentication, permissions, and connectivity required for this
              deployment target.
            </DialogDescription>
          </DialogHeader>
          <Content
            kubernetesAuthMethod={kubernetesAuthMethod}
            provider={provider}
          />
        </DialogContent>
      </Dialog>
    </>
  );
}
