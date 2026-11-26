// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Image from "next/image";
import React from "react";
import { CREDENTIAL_PROVIDER_CONFIG } from "@/lib/credential-providers";
import type { CredentialProvider } from "@/types/ssl";
import { cn } from "@/lib/utils";

interface ProviderIconProps {
  provider: CredentialProvider;
  serviceApiValue?: string;
  className?: string;
  size?: number;
}

function getServiceLogo(apiValue: string): string | undefined {
  switch (apiValue.trim().toUpperCase()) {
    case "AWS_ACM":
    case "AWS_ORGANIZATION":
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
    default:
      return undefined;
  }
}

export function ProviderIcon({
  provider,
  serviceApiValue,
  className,
  size = 16,
}: ProviderIconProps) {
  const config = CREDENTIAL_PROVIDER_CONFIG[provider];
  const serviceLogo = serviceApiValue
    ? getServiceLogo(serviceApiValue)
    : undefined;
  const shouldShowServiceLogo = Boolean(
    serviceLogo && serviceLogo !== config.logo,
  );

  if (!shouldShowServiceLogo) {
    return (
      <Image
        src={config.logo}
        alt={`${config.label} logo`}
        width={size}
        height={size}
        className={cn("object-contain", className)}
      />
    );
  }

  const overlaySize = Math.max(12, Math.round(size * 0.62));
  const overlayPadding = Math.max(1, Math.round(size * 0.08));

  return (
    <span className={cn("relative inline-block", className)} aria-hidden="true">
      <Image
        src={serviceLogo as string}
        alt=""
        width={size}
        height={size}
        className="object-contain"
      />
      <span
        className="absolute right-0 bottom-0 translate-x-1/4 translate-y-1/4 rounded-full border bg-background shadow-xs"
        style={{ padding: overlayPadding }}
      >
        <Image
          src={config.logo}
          alt=""
          width={overlaySize}
          height={overlaySize}
          className="object-contain"
        />
      </span>
    </span>
  );
}
