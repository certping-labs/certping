// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CircleNotchIcon } from "@phosphor-icons/react";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ProviderIcon } from "@/components/common/provider-icon";
import {
  formatProviderLabel,
  getProviderPresentation,
} from "@/lib/credential-providers";
import { formatDateTimeDetailed } from "@/lib/utils";
import type { CredentialRecord } from "@/types/ssl";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";

export const getCredentialTitle = (credential: CredentialRecord) =>
  credential.description || credential.credentialXref || credential.alias;

export const getCredentialSubtitle = (credential: CredentialRecord) =>
  credential.providerDisplayName ||
  formatProviderLabel(credential.providerName) ||
  "Credential";

export const getCredentialTypeBadgeVariant = (
  type?: string,
): BadgeProps["variant"] => {
  switch ((type || "").toUpperCase()) {
    case "DNS":
      return "info";
    case "DEPLOYMENT":
      return "warning";
    default:
      return "secondary";
  }
};

export const getCredentialStatusBadgeVariant = (
  status?: string,
): BadgeProps["variant"] => {
  switch ((status || "").toUpperCase()) {
    case "ACTIVE":
      return "success";
    case "INACTIVE":
    case "DELETED":
      return "destructive";
    default:
      return "warning";
  }
};

export interface CredentialDetailsDialogProps {
  credential: CredentialRecord | null;
  open: boolean;
  loading?: boolean;
  canEditCredential?: boolean;
  onClose: () => void;
  onDelete?: (credential: CredentialRecord) => void;
  onEdit?: (credential: CredentialRecord) => void;
}

export function CredentialDetailsDialog({
  credential,
  open,
  loading = false,
  canEditCredential = false,
  onClose,
  onDelete,
  onEdit,
}: CredentialDetailsDialogProps) {
  const providerPresentation = getProviderPresentation(
    credential?.providerName,
    credential?.provider,
  );

  const showEditActions = canEditCredential && (onEdit || onDelete);
  const isEnterpriseMode = isEnterpriseAppMode();
  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !nextOpen && onClose()}>
      <DialogContent className="max-w-2xl">
        {!credential && loading ? (
          <>
            <DialogHeader>
              <DialogTitle>Loading credential…</DialogTitle>
              <DialogDescription>
                Fetching the saved reference details.
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-center justify-center py-10">
              <CircleNotchIcon className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : !credential ? (
          <>
            <DialogHeader>
              <DialogTitle>Credential not found</DialogTitle>
              <DialogDescription>
                This reference is no longer available or you do not have
                permission to view it.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>
                <span className="flex items-center gap-3">
                  {credential.provider ? (
                    <ProviderIcon
                      provider={credential.provider}
                      serviceApiValue={credential.providerName || ""}
                      size={28}
                      className="shrink-0"
                    />
                  ) : null}
                  <span className="min-w-0 truncate">
                    {getCredentialTitle(credential)}
                  </span>
                </span>
              </DialogTitle>
              <DialogDescription>
                Saved{" "}
                {credential.type === "DNS"
                  ? "DNS automation"
                  : "deployment target"}{" "}
                reference.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={getCredentialTypeBadgeVariant(credential.type)}
                  textOnly
                >
                  {credential.type || "Unknown"}
                </Badge>
                <Badge
                  variant={getCredentialStatusBadgeVariant(credential.status)}
                  textOnly
                >
                  {credential.status || "UNKNOWN"}
                </Badge>
                {credential.lastError ? (
                  <Badge variant="destructive" textOnly>
                    Refused by target
                  </Badge>
                ) : null}
                <Badge variant="secondary" textOnly>
                  {providerPresentation.label ||
                    getCredentialSubtitle(credential)}
                </Badge>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <DetailField label="Reference">
                  {credential.credentialXref || credential.alias}
                </DetailField>
                <DetailField label="Updated">
                  {formatDateTimeDetailed(credential.updatedAt || null)}
                </DetailField>
                <DetailField label="Provider">
                  {getCredentialSubtitle(credential)}
                </DetailField>
                <DetailField label="Type">
                  {credential.type || "Unknown"}
                </DetailField>
              </div>

              {credential.lastError ? (
                <DetailField label="Last deployment error">
                  {credential.lastError}
                </DetailField>
              ) : null}

              {isEnterpriseMode && (
                <DetailField label="Secret handle" mono>
                  {credential.secretHandle || "Not set"}
                </DetailField>
              )}
              {credential.configJson ? (
                <DetailField label="Config JSON" mono>
                  {credential.configJson}
                </DetailField>
              ) : null}

              <DialogFooter>
                <Button variant="outline" onClick={onClose}>
                  Close
                </Button>
                {showEditActions ? (
                  <>
                    {onEdit ? (
                      <Button
                        variant="outline"
                        onClick={() => onEdit(credential)}
                      >
                        Update credential
                      </Button>
                    ) : null}
                    {onDelete ? (
                      <Button
                        variant="destructive"
                        onClick={() => onDelete(credential)}
                      >
                        Delete
                      </Button>
                    ) : null}
                  </>
                ) : null}
              </DialogFooter>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function DetailField({
  children,
  label,
  mono = false,
}: {
  children: React.ReactNode;
  label: string;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div
        className={
          mono
            ? "rounded-lg bg-muted px-3 py-2 font-mono text-xs break-all text-foreground"
            : "text-sm text-foreground"
        }
      >
        {children}
      </div>
    </div>
  );
}
