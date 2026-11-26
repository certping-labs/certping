// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useMemo, useState } from "react";
import { WarningIcon, PlusIcon, CrosshairIcon } from "@phosphor-icons/react";

import { BetaBadge } from "@/components/common/beta-badge";
import { ProviderIcon } from "@/components/common/provider-icon";
import { isBetaIntegration } from "@/lib/integration-maturity";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/ui/select";
import { useTriggerDiscovery } from "@/hooks/discovery";
import { useCanAddCredential } from "@/hooks/credentials";
import {
  AWS_ACM_DISCOVERY_COVERAGE_HELP,
  credentialDisplayLabel,
  credentialProviderKey,
  credentialServiceApiValue,
  credentialSubLabel,
  formatDiscoveryTargetLabel,
  isDiscoverableTargetType,
} from "@/lib/cert-manager/discovery-display";
import type { DiscoveryRunResponse } from "@/types/discovery";
import type { CredentialRecord } from "@/types/ssl";

function DiscoveryCredentialOption({
  credential,
  iconSize = 24,
}: {
  credential: CredentialRecord;
  iconSize?: number;
}) {
  const xref = credential.credentialXref ?? "";
  const subLabel = credentialSubLabel(credential);

  return (
    <div className="flex min-w-0 items-start gap-3">
      <ProviderIcon
        provider={credentialProviderKey(credential)}
        serviceApiValue={credentialServiceApiValue(credential)}
        size={iconSize}
        className="mt-0.5 shrink-0"
      />
      <div className="flex min-w-0 flex-col gap-0.5 text-left">
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium">
            {credentialDisplayLabel(credential)}
          </span>
          {isBetaIntegration(
            "DISCOVERY",
            credentialServiceApiValue(credential),
          ) ? (
            <BetaBadge />
          ) : null}
        </span>
        {subLabel ? (
          <span className="text-xs text-muted-foreground">{subLabel}</span>
        ) : null}
        {xref ? (
          <span className="truncate font-mono text-xs text-muted-foreground">
            {xref}
          </span>
        ) : null}
      </div>
    </div>
  );
}

export function TriggerDiscoveryDialog({
  open,
  onOpenChange,
  credentials: allCredentials,
  onScanDispatched,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  credentials: CredentialRecord[];
  onScanDispatched?: (info: {
    targetType: string;
    credentialLabel: string;
    result: DiscoveryRunResponse;
  }) => void;
}) {
  const triggerDiscovery = useTriggerDiscovery();
  const canAddDeploymentCredential = useCanAddCredential("DEPLOYMENT");
  const [selectedXref, setSelectedXref] = useState<string | null>(null);
  // Offer only targets the agent really discovers (AWS ACM, AWS Organization,
  // Azure Key Vault, Kubernetes), whatever the caller passes in.
  const credentials = useMemo(
    () =>
      allCredentials.filter((credential) =>
        isDiscoverableTargetType(credentialServiceApiValue(credential)),
      ),
    [allCredentials],
  );

  const selectedCredential = useMemo(
    () =>
      credentials.find(
        (credential) => credential.credentialXref === selectedXref,
      ) ?? credentials[0],
    [credentials, selectedXref],
  );
  const selectedCredentialXref = selectedCredential?.credentialXref ?? "";
  const targetType = selectedCredential
    ? credentialServiceApiValue(selectedCredential)
    : "";

  const handleTrigger = async () => {
    if (!selectedCredentialXref || !selectedCredential) return;

    const selectedTargetType = credentialServiceApiValue(selectedCredential);
    const result = await triggerDiscovery.mutateAsync({
      targetType: selectedTargetType,
      credentialXref: selectedCredentialXref,
    });

    onScanDispatched?.({
      targetType: selectedTargetType,
      credentialLabel: credentialDisplayLabel(selectedCredential),
      result,
    });
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Trigger discovery scan</DialogTitle>
          <DialogDescription>
            Dispatches a scan for the selected deployment target.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {credentials.length === 0 ? (
            <Alert className="bg-muted/40">
              <WarningIcon className="h-4 w-4" />
              <AlertTitle>No credentials available for discovery</AlertTitle>
              <AlertDescription>
                Add an AWS ACM, AWS Organization, Azure Key Vault, or Kubernetes
                Secrets deployment target that is configured for discovery.
              </AlertDescription>
            </Alert>
          ) : null}
          <p className="text-xs text-muted-foreground">
            Discovery reads AWS ACM (one region), AWS Organization ACM, Azure
            Key Vault and Kubernetes. {AWS_ACM_DISCOVERY_COVERAGE_HELP}
          </p>

          <div className="">
            <div className="mb-2 flex items-center justify-between gap-3">
              <label className="text-sm font-semibold">Credential</label>
              {targetType ? (
                <span className="text-xs text-muted-foreground">
                  Target: {formatDiscoveryTargetLabel(targetType)}
                </span>
              ) : null}
            </div>
            <Select
              value={selectedCredentialXref}
              onValueChange={setSelectedXref}
              disabled={credentials.length === 0}
            >
              <SelectTrigger
                aria-label="Select a deployment target"
                className="h-auto min-h-12 min-w-0 justify-start py-2"
              >
                {selectedCredential ? (
                  <DiscoveryCredentialOption
                    credential={selectedCredential}
                    iconSize={22}
                  />
                ) : (
                  <span className="text-muted-foreground">
                    Select a deployment target
                  </span>
                )}
              </SelectTrigger>
              <SelectContent>
                {credentials.map((credential) => {
                  const xref = credential.credentialXref ?? "";
                  return (
                    <SelectItem key={xref} value={xref}>
                      <DiscoveryCredentialOption credential={credential} />
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
            {canAddDeploymentCredential ? (
              <Button asChild variant="outline" className="mt-2">
                <Link href="/integrations/connections/add?type=DEPLOYMENT">
                  <PlusIcon className="h-4 w-4" aria-hidden="true" />
                  Add deployment target
                </Link>
              </Button>
            ) : null}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleTrigger}
            disabled={
              credentials.length === 0 ||
              !selectedCredentialXref ||
              triggerDiscovery.isPending
            }
            isPending={triggerDiscovery.isPending}
          >
            {!triggerDiscovery.isPending && (
              <CrosshairIcon className="h-4 w-4" aria-hidden="true" />
            )}
            Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
