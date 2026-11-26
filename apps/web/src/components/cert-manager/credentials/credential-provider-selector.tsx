// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Image from "next/image";
import React, { useMemo, useState } from "react";
import { CheckIcon } from "@phosphor-icons/react";

import type { CredentialReferenceProviderDefinition } from "@/lib/credential-providers";
import { CREDENTIAL_PROVIDER_CONFIG } from "@/lib/credential-providers";
import {
  BETA_INTEGRATION_DESCRIPTION,
  isBetaProviderApiValue,
} from "@/lib/integration-maturity";
import { BetaBadge } from "@/components/common/beta-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type ProviderCardDefinition = {
  label: string;
  serviceLogo: string;
  providerLogo?: string;
};

type ProviderGroupOption = {
  kind: "group";
  groupId: "AWS_API_GATEWAY" | "AWS_LOAD_BALANCER";
  card: ProviderCardDefinition;
  description: string;
  choices: Array<{
    label: string;
    apiValue: string;
  }>;
};

type ProviderSingleOption = {
  kind: "single";
  apiValue: string;
  card: ProviderCardDefinition;
};

type ProviderUiOption = ProviderGroupOption | ProviderSingleOption;

function ProviderCard({
  active,
  card,
  beta,
  onClick,
}: {
  active: boolean;
  card: ProviderCardDefinition;
  beta: boolean;
  onClick: () => void;
}) {
  const showProviderLogo =
    card.providerLogo && card.providerLogo !== card.serviceLogo;

  return (
    <button
      type="button"
      onClick={onClick}
      title={beta ? BETA_INTEGRATION_DESCRIPTION : undefined}
      className={`group aspect-square rounded-lg border bg-secondary p-3 text-left transition ${
        active
          ? "border-primary bg-primary/5"
          : "border-border hover:border-primary/40 hover:bg-muted/30"
      }`}
    >
      <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
        <div className="relative">
          <Image
            src={card.serviceLogo}
            alt=""
            width={44}
            height={44}
            className="h-12 w-12 shrink-0 object-contain"
          />
          {showProviderLogo ? (
            <div className="absolute -right-2 -bottom-2 rounded-full border bg-background p-1">
              <Image
                src={card.providerLogo as string}
                alt=""
                width={20}
                height={20}
                className="h-5 w-5 object-contain"
              />
            </div>
          ) : null}
        </div>
        <div className="flex items-center gap-1.5">
          <p className="text-sm font-medium">{card.label}</p>
          {active ? <CheckIcon className="h-3.5 w-3.5 text-primary" /> : null}
        </div>
        {beta ? <BetaBadge /> : null}
      </div>
    </button>
  );
}

function getProviderLogo(providerKey: string): string | undefined {
  if (providerKey === "aws") {
    return CREDENTIAL_PROVIDER_CONFIG.aws.logo;
  }
  if (providerKey === "azure") {
    return CREDENTIAL_PROVIDER_CONFIG.azure.logo;
  }
  if (providerKey === "gcp") {
    return CREDENTIAL_PROVIDER_CONFIG.gcp.logo;
  }
  if (providerKey === "cloudflare") {
    return CREDENTIAL_PROVIDER_CONFIG.cloudflare.logo;
  }
  if (providerKey === "godaddy") {
    return CREDENTIAL_PROVIDER_CONFIG.godaddy.logo;
  }
  if (providerKey === "namecom") {
    return CREDENTIAL_PROVIDER_CONFIG.namecom.logo;
  }
  if (providerKey === "kubernetes") {
    return CREDENTIAL_PROVIDER_CONFIG.kubernetes.logo;
  }
  if (providerKey === "akamai") {
    return CREDENTIAL_PROVIDER_CONFIG.akamai.logo;
  }
  if (providerKey === "f5") {
    return CREDENTIAL_PROVIDER_CONFIG.f5.logo;
  }
  return undefined;
}

function getServiceLogo(apiValue: string): string | undefined {
  switch (apiValue) {
    case "AWS_ACM":
      return "/assets/aws-acm.svg";
    case "AWS_API_GW_REST":
    case "AWS_API_GW_HTTP":
      return "/assets/aws-api-gateway.svg";
    case "AWS_ALB":
    case "AWS_NLB":
      return "/assets/aws-lb.svg";
    case "AWS_CLOUDFRONT":
      return "/assets/cloudfront.svg";
    case "AZURE_KV":
      return "/assets/azure-kv.svg";
    case "AZURE_AFD":
      return "/assets/azure-frontdoor.svg";
    case "AZURE_APP_GW":
      return "/assets/azure-app-gateway.svg";
    case "AZURE_APP_GW_CONTAINERS":
      return "/assets/azure-app-gateway-containers.svg";
    case "GCP_CERT_MANAGER":
      return "/assets/gcp-cert_manager.svg";
    case "GCP_ALB":
      return "/assets/gcp-lb.svg";
    case "GCP_PROXY_NLB":
      return "/assets/gcp-lb.svg";
    case "GCP_API_GW":
      return "/assets/gcp-api-gateway.svg";
    case "GCP_CLOUD_CDN":
      return "/assets/gcp-cdn.svg";
    default:
      return undefined;
  }
}

function getCardDefinition(
  option: CredentialReferenceProviderDefinition,
): ProviderCardDefinition {
  const providerLogo = getProviderLogo(option.providerKey);
  const serviceLogo =
    getServiceLogo(option.apiValue) || providerLogo || option.logo;
  return {
    label: option.label,
    serviceLogo,
    providerLogo,
  };
}

function isApiGatewayOption(
  option: CredentialReferenceProviderDefinition,
): boolean {
  return (
    option.apiValue === "AWS_API_GW_REST" ||
    option.apiValue === "AWS_API_GW_HTTP"
  );
}

function isLoadBalancerOption(
  option: CredentialReferenceProviderDefinition,
): boolean {
  return option.apiValue === "AWS_ALB" || option.apiValue === "AWS_NLB";
}

function buildUiOptions(
  options: CredentialReferenceProviderDefinition[],
): ProviderUiOption[] {
  const uiOptions: ProviderUiOption[] = [];

  const apiGwChoices = options.filter(isApiGatewayOption);
  const lbChoices = options.filter(isLoadBalancerOption);
  let didAddApiGwGroup = false;
  let didAddLoadBalancerGroup = false;

  for (const option of options) {
    if (isApiGatewayOption(option)) {
      if (!didAddApiGwGroup && apiGwChoices.length > 0) {
        didAddApiGwGroup = true;
        uiOptions.push({
          kind: "group",
          groupId: "AWS_API_GATEWAY",
          card: {
            label: "AWS API Gateway",
            serviceLogo: "/assets/aws-api-gateway.svg",
            providerLogo: getProviderLogo(apiGwChoices[0].providerKey),
          },
          description: "Choose the API Gateway type you are targeting.",
          choices: apiGwChoices.map((choice) => ({
            label: choice.label,
            apiValue: choice.apiValue,
          })),
        });
      }
      continue;
    }

    if (isLoadBalancerOption(option)) {
      if (!didAddLoadBalancerGroup && lbChoices.length > 0) {
        didAddLoadBalancerGroup = true;
        uiOptions.push({
          kind: "group",
          groupId: "AWS_LOAD_BALANCER",
          card: {
            label: "AWS Load Balancer",
            serviceLogo: "/assets/aws-lb.svg",
            providerLogo: getProviderLogo(lbChoices[0].providerKey),
          },
          description: "Choose the load balancer type you are targeting.",
          choices: lbChoices.map((choice) => ({
            label: choice.label,
            apiValue: choice.apiValue,
          })),
        });
      }
      continue;
    }

    uiOptions.push({
      kind: "single",
      apiValue: option.apiValue,
      card: getCardDefinition(option),
    });
  }

  return uiOptions;
}

export function CredentialProviderSelector({
  options,
  selectedProviderApiValue,
  onSelectProvider,
}: {
  options: CredentialReferenceProviderDefinition[];
  selectedProviderApiValue: string;
  onSelectProvider: (apiValue: string) => void;
}) {
  const uiOptions = useMemo(() => buildUiOptions(options), [options]);

  const [pendingGroup, setPendingGroup] = useState<ProviderGroupOption | null>(
    null,
  );

  return (
    <>
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8">
        {uiOptions.map((option) => {
          if (option.kind === "single") {
            return (
              <ProviderCard
                key={option.apiValue}
                active={selectedProviderApiValue === option.apiValue}
                onClick={() => onSelectProvider(option.apiValue)}
                card={option.card}
                beta={isBetaProviderApiValue(option.apiValue)}
              />
            );
          }

          const isActive = option.choices.some(
            (choice) => choice.apiValue === selectedProviderApiValue,
          );
          return (
            <ProviderCard
              key={option.groupId}
              active={isActive}
              onClick={() => setPendingGroup(option)}
              card={option.card}
              beta={option.choices.some((choice) =>
                isBetaProviderApiValue(choice.apiValue),
              )}
            />
          );
        })}
      </div>

      <Dialog
        open={pendingGroup !== null}
        onOpenChange={(nextOpen) => {
          if (!nextOpen) {
            setPendingGroup(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Select a provider</DialogTitle>
            <DialogDescription>
              {pendingGroup?.description ?? ""}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            {(pendingGroup?.choices || []).map((choice) => (
              <Button
                key={choice.apiValue}
                type="button"
                variant="outline"
                className="justify-between"
                onClick={() => {
                  onSelectProvider(choice.apiValue);
                  setPendingGroup(null);
                }}
              >
                <span className="flex items-center gap-2">
                  <span>{choice.label}</span>
                  {isBetaProviderApiValue(choice.apiValue) ? (
                    <BetaBadge />
                  ) : null}
                </span>
                {selectedProviderApiValue === choice.apiValue ? (
                  <CheckIcon className="h-4 w-4 text-primary" />
                ) : null}
              </Button>
            ))}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="secondary"
              onClick={() => setPendingGroup(null)}
            >
              Cancel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
