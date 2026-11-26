// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import {
  CircleNotchIcon,
  ArrowClockwiseIcon,
  BinocularsIcon,
  TrashIcon,
} from "@phosphor-icons/react";

import { ProviderIcon } from "@/components/common/provider-icon";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { useCredentials } from "@/hooks/credentials";
import {
  useDeleteDiscoveryConfig,
  useDiscoveryConfigs,
  useRerunAllDiscoveryConfigs,
  useRerunDiscoveryConfig,
} from "@/hooks/discovery";
import { formatDiscoveryTargetLabel } from "@/lib/cert-manager/discovery-display";
import {
  discoveryConfigStatusLabel,
  discoveryConfigStatusMessage,
  discoveryConfigStatusVariant,
  isActiveDiscoveryConfigStatus,
} from "@/lib/cert-manager/discovery-status";
import { resolveCredentialProviderFromApiValue } from "@/lib/credential-providers";
import { formatDateTimeCompact } from "@/lib/utils";
import type { DiscoveryRunResponse } from "@/types/discovery";

function ConfigRow({
  config,
  credentialLabel,
  canManage,
  canDelete,
  onDelete,
}: {
  config: DiscoveryRunResponse;
  credentialLabel: string;
  canManage: boolean;
  canDelete: boolean;
  onDelete: (config: DiscoveryRunResponse) => void;
}) {
  const rerun = useRerunDiscoveryConfig();
  const isRunning = isActiveDiscoveryConfigStatus(config.status);
  const lastRun = config.completedAt ?? config.startedAt;
  const targetLabel = formatDiscoveryTargetLabel(config.targetType);

  return (
    <li className="grid gap-3 border-b border-border px-3 py-3 last:border-b-0 md:grid-cols-[minmax(0,1fr)_9rem_8rem] md:items-center">
      <div className="flex min-w-0 gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-border bg-background">
          <ProviderIcon
            provider={
              resolveCredentialProviderFromApiValue(config.targetType) ?? "aws"
            }
            serviceApiValue={config.targetType}
            size={24}
          />
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-foreground">
            {credentialLabel}
          </div>
          <p className="truncate text-xs text-muted-foreground">
            {targetLabel}
          </p>
          {lastRun ? (
            <p className="mt-1 text-xs text-muted-foreground/70">
              Last run {formatDateTimeCompact(lastRun)}
            </p>
          ) : null}
          {config.status === "PARTIAL" ? (
            <p className="mt-1 text-xs text-warning">
              {discoveryConfigStatusMessage(config)}
            </p>
          ) : null}
        </div>
      </div>

      <div>
        <Badge variant={discoveryConfigStatusVariant(config.status)}>
          {discoveryConfigStatusLabel(config.status)}
        </Badge>
      </div>

      <div className="flex shrink-0 items-center gap-1.5 md:justify-end">
        {canDelete ? (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground hover:text-destructive"
            disabled={config.configId == null}
            onClick={() => onDelete(config)}
            aria-label="Remove discovery configuration"
          >
            <TrashIcon className="h-4 w-4" aria-hidden="true" />
          </Button>
        ) : null}
        {canManage ? (
          <Button
            size="sm"
            variant={"outline"}
            disabled={isRunning || rerun.isPending || config.configId == null}
            onClick={() => {
              if (config.configId != null) rerun.mutate(config.configId);
            }}
            title={isRunning ? "A scan is already running" : "Run this scan"}
          >
            {rerun.isPending ? (
              <CircleNotchIcon
                className="h-4 w-4 animate-spin"
                aria-hidden="true"
              />
            ) : (
              <ArrowClockwiseIcon className="h-4 w-4" aria-hidden="true" />
            )}
            Run
          </Button>
        ) : null}
      </div>
    </li>
  );
}

export function DiscoveryConfigsDialog({
  open,
  onOpenChange,
  canManage,
  canDelete,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  canManage: boolean;
  canDelete: boolean;
}) {
  const { data: configs, isLoading } = useDiscoveryConfigs({ enabled: open });
  const credentialsQuery = useCredentials({ enabled: open });
  const rerunAll = useRerunAllDiscoveryConfigs();
  const deleteConfig = useDeleteDiscoveryConfig();
  const [configToDelete, setConfigToDelete] =
    React.useState<DiscoveryRunResponse | null>(null);

  const credentialLabelByXref = React.useMemo(() => {
    const map = new Map<string, string>();
    for (const credential of credentialsQuery.data ?? []) {
      if (credential.credentialXref) {
        map.set(
          credential.credentialXref,
          credential.description ||
            credential.alias ||
            credential.credentialXref,
        );
      }
    }
    return map;
  }, [credentialsQuery.data]);

  const items = configs ?? [];

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>Saved discovery scans</DialogTitle>
            <DialogDescription>
              Discovery Provider targets saved for your organization.
            </DialogDescription>
          </DialogHeader>

          {canManage && items.length > 0 ? (
            <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-muted/30 px-3 py-2">
              <div>
                <p className="text-sm font-semibold text-foreground">
                  {items.length} saved {items.length === 1 ? "scan" : "scans"}
                </p>
                <p className="text-xs text-muted-foreground">
                  Running all skips duplicate dispatches when a scan is already
                  active.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                disabled={rerunAll.isPending}
                onClick={() => rerunAll.mutate()}
              >
                {rerunAll.isPending ? (
                  <CircleNotchIcon
                    className="h-4 w-4 animate-spin"
                    aria-hidden="true"
                  />
                ) : (
                  <ArrowClockwiseIcon className="h-4 w-4" aria-hidden="true" />
                )}
                Run all
              </Button>
            </div>
          ) : null}

          <div className="max-h-[60vh] overflow-y-auto rounded-md border border-border">
            {isLoading ? (
              <div
                className="space-y-2 p-3"
                role="status"
                aria-label="Loading scans"
              >
                {Array.from({ length: 3 }).map((_, index) => (
                  <Skeleton key={index} className="h-16 w-full rounded-lg" />
                ))}
              </div>
            ) : items.length === 0 ? (
              <Alert className="border-0 bg-card">
                <BinocularsIcon className="h-4 w-4" />
                <AlertTitle>No saved discovery scans yet</AlertTitle>
                <AlertDescription>
                  Trigger a scan to save a discovery configuration here.
                </AlertDescription>
              </Alert>
            ) : (
              <ul>
                {items.map((config) => (
                  <ConfigRow
                    key={config.configId ?? config.credentialXref}
                    config={config}
                    credentialLabel={
                      (config.credentialXref &&
                        credentialLabelByXref.get(config.credentialXref)) ||
                      config.credentialXref ||
                      "Unknown credential"
                    }
                    canManage={canManage}
                    canDelete={canDelete}
                    onDelete={setConfigToDelete}
                  />
                ))}
              </ul>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={configToDelete !== null}
        onOpenChange={(value) => {
          if (!value) setConfigToDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove discovery configuration?</AlertDialogTitle>
            <AlertDialogDescription>
              This stops the saved scan from running. Already discovered
              certificates are kept.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteConfig.isPending}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={deleteConfig.isPending}
              onClick={(event) => {
                event.preventDefault();
                const id = configToDelete?.configId;
                if (id == null) return;
                deleteConfig.mutate(id, {
                  onSuccess: () => setConfigToDelete(null),
                });
              }}
            >
              {deleteConfig.isPending ? (
                <CircleNotchIcon
                  className="h-4 w-4 animate-spin"
                  aria-hidden="true"
                />
              ) : null}
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
