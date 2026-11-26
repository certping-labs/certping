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

type SupportedProvider = "AWS_ACM" | "AWS_CLOUDFRONT" | "AZURE_KV" | "GCP";

function ProviderContent({ provider }: { provider: SupportedProvider }) {
  if (provider === "AWS_ACM" || provider === "AWS_CLOUDFRONT") {
    return (
      <div className="space-y-4 text-sm">
        <div className="space-y-1">
          <p className="font-medium">STATIC_KEYS</p>
          <p className="text-muted-foreground">
            Store AWS access keys in your secret manager and provide the secret
            URI. Use when you cannot use a runtime identity.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>Secret fields: accessKeyId, secretAccessKey</li>
            <li>
              Permissions: IAM policy allowing the AWS API actions shown in
              Setup help for the selected deployment target
            </li>
          </ul>
        </div>

        <div className="space-y-1">
          <p className="font-medium">ASSUME_ROLE</p>
          <p className="text-muted-foreground">
            Uses the agent runtime AWS identity to assume the specified role at
            runtime. Recommended for cross-account deployments.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>Config fields: roleArn (required), externalId (optional)</li>
            <li>
              IAM trust policy: allow the base principal to assume the role (and
              require externalId if you use it)
            </li>
          </ul>
        </div>

        <div className="space-y-1">
          <p className="font-medium">INSTANCE_PROFILE</p>
          <p className="text-muted-foreground">
            Uses the agent runtime identity. No stored AWS key secret is
            required.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>
              EC2/ECS: instance/task role with the required AWS permissions
            </li>
            <li>
              EKS: IRSA (service account role) with the required AWS permissions
            </li>
          </ul>
        </div>

        <p className="text-xs text-muted-foreground">
          Where to set up: AWS IAM (role + policies), and optionally EKS IRSA or
          instance/task roles.
        </p>
      </div>
    );
  }

  if (provider === "GCP") {
    return (
      <div className="space-y-4 text-sm">
        <div className="space-y-1">
          <p className="font-medium">SERVICE_ACCOUNT_KEY</p>
          <p className="text-muted-foreground">
            Store a GCP service account key in your secret manager and provide
            the secret handle.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>
              Secret field: serviceAccountKeyJson (service account key JSON
              object)
            </li>
            <li>Config fields: projectId, location</li>
          </ul>
        </div>

        <div className="space-y-1">
          <p className="font-medium">WORKLOAD_IDENTITY</p>
          <p className="text-muted-foreground">
            Uses Application Default Credentials (GKE Workload Identity /
            metadata server). No stored service account key secret is required.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>Config fields: projectId, location</li>
          </ul>
        </div>

        <div className="space-y-1">
          <p className="font-medium">IMPERSONATE_SERVICE_ACCOUNT</p>
          <p className="text-muted-foreground">
            Uses ADC and then impersonates a service account. No stored service
            account key secret is required.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground">
            <li>
              Config fields: projectId, location, impersonateServiceAccount
            </li>
          </ul>
        </div>

        <p className="text-xs text-muted-foreground">
          Where to set up: GCP IAM (service account, permissions), GKE Workload
          Identity (if used), and Certificate Manager / Compute permissions for
          your target.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4 text-sm">
      <div className="space-y-1">
        <p className="font-medium">SERVICE_PRINCIPAL</p>
        <p className="text-muted-foreground">
          Store Azure application credentials in your secret manager and provide
          the secret handle. Use when workload identity is not available.
        </p>
        <ul className="list-disc pl-5 text-muted-foreground">
          <li>Secret fields: clientId, clientSecret</li>
          <li>Config fields: tenantId (required), vaultUri</li>
          <li>
            Role/permissions: Key Vault access (RBAC role or access policy) for
            cert operations you use
          </li>
        </ul>
      </div>

      <div className="space-y-1">
        <p className="font-medium">WORKLOAD_IDENTITY</p>
        <p className="text-muted-foreground">
          Uses the agent runtime identity. No stored Azure client secret is
          required.
        </p>
        <ul className="list-disc pl-5 text-muted-foreground">
          <li>AKS: Workload Identity / Managed Identity bound to the pod</li>
          <li>
            Assign the identity access to the Key Vault (RBAC or access policy)
          </li>
          <li>Config field: vaultUri</li>
        </ul>
      </div>

      <p className="text-xs text-muted-foreground">
        Where to set up: Azure Entra ID (app/identity), AKS Workload Identity,
        and Key Vault permissions (RBAC or access policies).
      </p>
    </div>
  );
}

export function CredentialAuthModeInfoDialog({
  provider,
}: {
  provider: SupportedProvider;
}) {
  const [open, setOpen] = React.useState(false);

  return (
    <>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="h-9 gap-2"
        onClick={() => setOpen(true)}
        aria-label="Auth modes info"
      >
        <InfoIcon className="h-4 w-4" />
        <span className="text-xs">Auth help</span>
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>
              Auth modes -{" "}
              {provider === "AWS_ACM"
                ? "AWS ACM"
                : provider === "AWS_CLOUDFRONT"
                  ? "AWS CloudFront"
                  : provider === "GCP"
                    ? "GCP"
                    : "Azure Key Vault"}
            </DialogTitle>
            <DialogDescription>
              Choose an auth mode based on where your agent runs and how you
              want to grant it access.
            </DialogDescription>
          </DialogHeader>
          <ProviderContent provider={provider} />
        </DialogContent>
      </Dialog>
    </>
  );
}
