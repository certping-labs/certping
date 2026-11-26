// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { ProviderIcon } from "@/components/machine-identity/provider-label";
import { Badge } from "@/components/ui/badge";
import {
  complianceStateLabel,
  complianceStateVariant,
  DEVICE_CLASS_LABELS,
  DEVICE_STATUS_LABELS,
  deviceStatusVariant,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type { DeviceListItem } from "@/types/machine-identity-backend";

/**
 * Resolves a device row's platform vendor.
 *
 * <p>`DeviceListItem` carries no provider or `sourceXref` - only
 * `platformDisplayName`, which is the *source's* display name, not a platform.
 * The source list is already cached for the filter bar, so the vendor is
 * looked up from it by display name; a source we cannot resolve simply renders
 * without a mark rather than guessing one.
 */
export type ProviderByDisplayName = ReadonlyMap<string, string>;

interface DeviceColumnOptions {
  providerByDisplayName: ProviderByDisplayName;
}

/**
 * Device inventory table columns.
 *
 * <p>Status and compliance are closed enums on the backend
 * (`DeviceStatus`, `ComplianceState`), so they carry semantic colour: an
 * orphaned device still holding a certificate is a revocation candidate and
 * must not look identical to a healthy one.
 */
export function buildDeviceColumns({
  providerByDisplayName,
}: DeviceColumnOptions): ColumnDef<DeviceListItem>[] {
  return [
    {
      accessorKey: "deviceName",
      id: "device",
      header: "Device",
      size: 240,
      cell: ({ row }) => (
        <div className="max-w-[16rem]">
          <Link
            href={`/machine-identity/devices/${row.original.deviceXref}`}
            className="block truncate font-medium text-foreground hover:text-primary"
            onClick={(event) => event.stopPropagation()}
          >
            {row.original.deviceName ?? "Unnamed device"}
          </Link>
          <span className="block truncate font-mono text-xs text-muted-foreground">
            {row.original.serialNumber ?? "No serial reported"}
          </span>
        </div>
      ),
    },
    {
      accessorKey: "platformDisplayName",
      id: "source",
      header: "Source",
      size: 180,
      cell: ({ row }) => {
        const displayName = row.original.platformDisplayName;
        if (!displayName) {
          return <span className="text-muted-foreground">Unknown source</span>;
        }
        const provider = providerByDisplayName.get(displayName);
        return (
          <span className="flex min-w-0 items-center gap-1.5">
            {provider ? <ProviderIcon provider={provider} /> : null}
            <span className="truncate">{displayName}</span>
          </span>
        );
      },
    },
    {
      accessorKey: "deviceClass",
      id: "class",
      header: "Class",
      size: 150,
      cell: ({ row }) => {
        const deviceClass = row.original.deviceClass;
        if (!deviceClass) {
          return <span className="text-muted-foreground">-</span>;
        }
        return (
          DEVICE_CLASS_LABELS[deviceClass] ?? humanizeConstant(deviceClass)
        );
      },
    },
    {
      accessorKey: "operatingSystem",
      id: "os",
      header: "Operating system",
      size: 160,
      cell: ({ row }) =>
        row.original.operatingSystem ? (
          <span>
            {row.original.operatingSystem}
            {row.original.osVersion ? (
              <span className="block text-xs text-muted-foreground">
                {row.original.osVersion}
              </span>
            ) : null}
          </span>
        ) : (
          <span className="text-muted-foreground">Not reported</span>
        ),
    },
    {
      accessorKey: "model",
      id: "model",
      header: "Model",
      size: 150,
      cell: ({ row }) =>
        row.original.model ?? <span className="text-muted-foreground">-</span>,
    },
    {
      accessorKey: "ownerDisplayName",
      id: "owner",
      header: "Owner",
      size: 160,
      cell: ({ row }) =>
        row.original.ownerDisplayName ??
        row.original.ownerUpn ?? (
          <span className="text-muted-foreground">Not collected</span>
        ),
    },
    {
      accessorKey: "complianceState",
      id: "compliance",
      header: "Compliance",
      size: 150,
      cell: ({ row }) => (
        <Badge variant={complianceStateVariant(row.original.complianceState)}>
          {complianceStateLabel(row.original.complianceState)}
        </Badge>
      ),
    },
    {
      accessorKey: "status",
      id: "status",
      header: "Status",
      size: 150,
      cell: ({ row }) => {
        const status = row.original.status;
        return (
          <Badge variant={deviceStatusVariant(status)}>
            {status ? DEVICE_STATUS_LABELS[status] : "Unknown"}
          </Badge>
        );
      },
    },
    {
      accessorKey: "lastSeenInSourceAt",
      id: "lastSeen",
      header: "Last seen",
      size: 150,
      cell: ({ row }) => (
        <span className="whitespace-nowrap text-muted-foreground">
          {row.original.lastSeenInSourceAt
            ? formatDateTimeCompact(row.original.lastSeenInSourceAt)
            : "Never"}
        </span>
      ),
    },
  ];
}

/**
 * Columns the inventory hides until an operator asks for them.
 *
 * <p>`owner` stays hidden because the only live connector (Intune v1) does not
 * request user or owner data, so the column is empty for every row today - an
 * always-blank column reads as missing data rather than as a deliberate scope
 * decision. It remains available from the Columns menu for sources that do
 * report an owner.
 */
export const DEVICE_DEFAULT_HIDDEN_COLUMNS = ["owner"];
