// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Image from "next/image";
import * as React from "react";

import { ProviderIcon } from "@/components/common/provider-icon";
import { CredentialActions } from "@/components/cert-manager/credentials/credential-actions";
import {
  getCredentialStatusBadgeVariant,
  getCredentialSubtitle,
  getCredentialTitle,
} from "@/components/cert-manager/credential-details-dialog";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getProviderPresentation } from "@/lib/credential-providers";
import { formatDate } from "@/lib/utils";
import type { CredentialRecord } from "@/types/ssl";

interface CredentialInventoryProps {
  canEditCredential: boolean;
  credentials: CredentialRecord[];
  onDelete: (credential: CredentialRecord) => void;
  onEdit: (credential: CredentialRecord) => void;
  onOpen: (credential: CredentialRecord) => void;
}

export function CredentialInventory({
  canEditCredential,
  credentials,
  onDelete,
  onEdit,
  onOpen,
}: CredentialInventoryProps) {
  return (
    <Table className="min-w-[720px]">
      <TableHeader>
        <TableRow>
          <TableHead>Credential</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Reference</TableHead>
          <TableHead>Updated</TableHead>
          <TableHead className="w-12">
            <span className="sr-only">Actions</span>
          </TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {credentials.map((credential) => {
          const providerPresentation = getProviderPresentation(
            credential.providerName,
            credential.provider,
          );
          const title = getCredentialTitle(credential);

          return (
            <TableRow key={credential.credentialXref || credential.alias}>
              <TableCell className="min-w-64">
                <button
                  type="button"
                  className="flex min-w-0 items-center gap-3 text-left outline-hidden focus-visible:rounded-md focus-visible:ring-4 focus-visible:ring-brand"
                  aria-label={`View credential ${title}`}
                  onClick={() => onOpen(credential)}
                >
                  {credential.provider ? (
                    <ProviderIcon
                      provider={credential.provider}
                      serviceApiValue={credential.providerName || ""}
                      size={28}
                      className="shrink-0"
                    />
                  ) : providerPresentation.logo ? (
                    <Image
                      src={providerPresentation.logo}
                      alt=""
                      width={28}
                      height={28}
                      className="size-7 shrink-0 object-contain"
                    />
                  ) : null}
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold text-foreground">
                      {title}
                    </span>
                    <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                      {getCredentialSubtitle(credential)}
                    </span>
                  </span>
                </button>
              </TableCell>
              <TableCell className="text-xs font-medium text-muted-foreground">
                {credential.type || "Unknown"}
              </TableCell>
              <TableCell>
                <Badge
                  includeDot
                  variant={getCredentialStatusBadgeVariant(credential.status)}
                >
                  {credential.status || "UNKNOWN"}
                </Badge>
                {credential.lastError ? (
                  <Badge
                    includeDot
                    variant="destructive"
                    className="ml-1"
                    title={credential.lastError}
                  >
                    Refused by target
                  </Badge>
                ) : null}
              </TableCell>
              <TableCell>
                <code className="text-xs text-muted-foreground">
                  {credential.credentialXref || credential.alias}
                </code>
              </TableCell>
              <TableCell className="text-sm whitespace-nowrap text-muted-foreground">
                {formatDate(credential.updatedAt || null)}
              </TableCell>
              <TableCell>
                {canEditCredential ? (
                  <CredentialActions
                    credential={credential}
                    onDelete={onDelete}
                    onEdit={onEdit}
                  />
                ) : null}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
