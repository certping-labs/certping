// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { ProviderIcon } from "@/components/machine-identity/provider-label";
import { Badge } from "@/components/ui/badge";
import {
  PROFILE_CONTROL_MODE_LABELS,
  PROFILE_LIFECYCLE_LABELS,
  PROFILE_PROVIDER_SYNC_STATUS_LABELS,
  profileLifecycleVariant,
  profileProviderSyncStatusVariant,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type { CertificateProfileResponse } from "@/types/machine-identity-backend";

export const PROFILE_COLUMNS: ColumnDef<CertificateProfileResponse>[] = [
  {
    accessorKey: "name",
    id: "profile",
    header: "Profile",
    size: 240,
    cell: ({ row }) => (
      <div className="max-w-[18rem]">
        <Link
          href={`/machine-identity/profiles/${row.original.profileXref}`}
          className="block truncate font-medium hover:text-primary"
          onClick={(event) => event.stopPropagation()}
        >
          {row.original.name}
        </Link>
        <span className="mt-0.5 flex items-center gap-1 truncate text-xs text-muted-foreground">
          <ProviderIcon provider={row.original.provider} />
          <span className="truncate">{row.original.sourceDisplayName}</span>
        </span>
      </div>
    ),
  },
  {
    accessorKey: "targetPlatform",
    id: "target",
    header: "Target",
    size: 140,
    cell: ({ row }) => (
      <span>
        {humanizeConstant(row.original.targetPlatform, "—")}
        {row.original.targetVariant ? (
          <span className="block text-xs text-muted-foreground">
            {humanizeConstant(row.original.targetVariant)}
          </span>
        ) : null}
      </span>
    ),
  },
  {
    accessorKey: "profileKind",
    id: "kind",
    header: "Kind",
    size: 170,
    cell: ({ row }) => humanizeConstant(row.original.profileKind),
  },
  {
    accessorKey: "enrollmentMethod",
    id: "enrollment",
    header: "Enrollment",
    size: 110,
    cell: ({ row }) =>
      row.original.enrollmentMethod ?? (
        <span className="text-muted-foreground">—</span>
      ),
  },
  {
    accessorKey: "lifecycleStatus",
    id: "lifecycle",
    header: "Lifecycle",
    size: 110,
    cell: ({ row }) => (
      <Badge variant={profileLifecycleVariant(row.original.lifecycleStatus)}>
        {PROFILE_LIFECYCLE_LABELS[row.original.lifecycleStatus]}
      </Badge>
    ),
  },
  {
    accessorKey: "controlMode",
    id: "control",
    header: "Control",
    size: 140,
    cell: ({ row }) => (
      <Badge variant="secondary">
        {PROFILE_CONTROL_MODE_LABELS[row.original.controlMode]}
      </Badge>
    ),
  },
  {
    accessorKey: "providerSyncStatus",
    id: "sync",
    header: "Provider sync",
    size: 130,
    cell: ({ row }) => (
      <Badge
        variant={profileProviderSyncStatusVariant(
          row.original.providerSyncStatus,
        )}
      >
        {PROFILE_PROVIDER_SYNC_STATUS_LABELS[row.original.providerSyncStatus]}
      </Badge>
    ),
  },
  {
    accessorKey: "updatedAt",
    id: "updated",
    header: "Updated",
    size: 150,
    cell: ({ row }) => (
      <span className="whitespace-nowrap text-muted-foreground">
        {formatDateTimeCompact(row.original.updatedAt)}
      </span>
    ),
  },
];
