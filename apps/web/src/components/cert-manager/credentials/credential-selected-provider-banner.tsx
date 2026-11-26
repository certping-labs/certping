// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { ArrowSquareOutIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { ProviderIcon } from "@/components/common/provider-icon";
import type { CredentialProvider } from "@/types/ssl";

export function CredentialSelectedProviderBanner({
  label,
  description,
  docsUrl,
  providerKey,
  providerApiValue,
}: {
  label: string;
  description?: string;
  docsUrl?: string;
  providerKey: CredentialProvider;
  providerApiValue: string;
}) {
  return (
    <div className="flex flex-1 flex-col gap-3 rounded-md border bg-muted/10 p-3 md:flex-row md:items-center md:justify-between">
      <div className="flex items-start gap-3">
        <ProviderIcon
          provider={providerKey}
          serviceApiValue={providerApiValue}
          size={44}
          className="mt-0.5 shrink-0"
        />
        <div className="space-y-0.5">
          <p className="text-sm font-medium">{label}</p>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
        </div>
      </div>

      {docsUrl ? (
        <Button
          asChild
          variant="outline"
          size="sm"
          className="w-fit"
          type="button"
        >
          <a href={docsUrl} target="_blank" rel="noreferrer">
            <ArrowSquareOutIcon className="h-4 w-4" />
            Docs
          </a>
        </Button>
      ) : null}
    </div>
  );
}
