// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { toast } from "sonner";
import { CopyIcon, InfoIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { CredentialProviderInfoDialog } from "@/components/cert-manager/credentials/credential-provider-info-dialog";

export function CredentialSecretPayloadCard({
  payloadTemplate,
  providerApiValue,
  storageMode = "kvPath",
}: {
  payloadTemplate: string;
  providerApiValue?: string;
  storageMode?: "kvPath" | "credJson";
}) {
  const formattedTemplate = React.useMemo(() => {
    if (!payloadTemplate) {
      return "";
    }

    try {
      const parsed = JSON.parse(payloadTemplate);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return payloadTemplate;
    }
  }, [payloadTemplate]);

  if (!payloadTemplate) {
    return null;
  }

  const copyPayload = async () => {
    try {
      await navigator.clipboard.writeText(payloadTemplate);
      toast.success("Secret template copied");
    } catch {
      toast.error("Could not copy Secret Template payload");
    }
  };

  return (
    <div className="space-y-2 rounded-md border bg-muted/10 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <InfoIcon className="h-4 w-4 text-muted-foreground" />
          <p className="text-sm font-medium">
            Secret template for {providerApiValue?.replaceAll("_", " ")}{" "}
            credentials
          </p>
        </div>
        <div className="flex items-center gap-2">
          <CredentialProviderInfoDialog providerApiValue={providerApiValue} />
          <Button
            type="button"
            variant="iconSm"
            size="iconSm"
            onClick={copyPayload}
            aria-label="Copy secret template"
          >
            <CopyIcon />
          </Button>
        </div>
      </div>
      <pre className="max-h-56 overflow-auto rounded-md border bg-background/70 p-3 text-xs leading-relaxed">
        <code className="font-mono">{formattedTemplate}</code>
      </pre>
      <p className="text-xs text-muted-foreground">
        {storageMode === "credJson"
          ? "Use this as a reference only. CertPing builds this secret from the form fields below and stores it in the managed credential vault for you."
          : "Store this JSON in your secret manager first, then paste that secret version URI into the secret handle field."}
      </p>
    </div>
  );
}
