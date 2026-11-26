// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";
import type { ColumnDef } from "@tanstack/react-table";

import { CaConnectorLabel } from "@/components/machine-identity/ca-connector-label";
import { Badge } from "@/components/ui/badge";
import {
  CERTIFICATE_RENEWAL_STATE_LABELS,
  certificateRenewalStateVariant,
  certificateStatusLabel,
  certificateStatusVariant,
  formatKeyStrength,
  formatRemainingLifetime,
  isRenewalStateSurfaced,
  nudgeOutcomeLabel,
} from "@/lib/machine-identity/backend-display";
import { formatDate } from "@/lib/utils";
import type { CertificateListItem } from "@/types/machine-identity-backend";

/**
 * Columns the inventory hides until the viewer asks for them. Chosen so the
 * default table fits a tablet: the issuer DN is a longer restatement of the CA
 * column, and both validity dates are summarised by "Remaining".
 */
export const CERTIFICATE_DEFAULT_HIDDEN_COLUMNS = [
  "issuer",
  "valid-from",
  "key",
];

export const CERTIFICATE_COLUMNS: ColumnDef<CertificateListItem>[] = [
  {
    accessorKey: "commonName",
    id: "certificate",
    header: "Certificate / CN",
    size: 240,
    cell: ({ row }) => (
      <div className="max-w-[16rem]">
        <Link
          href={`/machine-identity/device-certificates/${row.original.certificateXref}`}
          className="block truncate font-medium hover:text-primary"
          onClick={(event) => event.stopPropagation()}
        >
          {row.original.commonName}
        </Link>
        <span className="block truncate font-mono text-xs text-muted-foreground">
          {row.original.serialNumber}
        </span>
      </div>
    ),
  },
  {
    accessorKey: "device",
    id: "device",
    header: "Device",
    size: 170,
    cell: ({ row }) =>
      row.original.device ? (
        <span className="flex min-w-0 items-center gap-1.5">
          <Link
            href={`/machine-identity/devices/${row.original.device.deviceXref}`}
            className="block max-w-48 truncate hover:text-primary"
            onClick={(event) => event.stopPropagation()}
          >
            {row.original.device.deviceName ?? "Unknown device"}
          </Link>
          {/* An archived device is out of the inventory, not unknown. Saying "Unmatched" here sends
              an operator hunting a certificate nobody lost. */}
          {row.original.device.archived ? (
            <span className="shrink-0 text-xs text-muted-foreground">
              (archived)
            </span>
          ) : null}
        </span>
      ) : (
        <span className="text-muted-foreground">Unmatched</span>
      ),
  },
  {
    accessorKey: "caProvider",
    id: "ca",
    header: "CA",
    size: 150,
    cell: ({ row }) => (
      <CaConnectorLabel caProvider={row.original.caProvider} />
    ),
  },
  {
    accessorKey: "issuerDn",
    id: "issuer",
    header: "Issuer DN",
    size: 200,
    cell: ({ row }) => (
      <span className="block max-w-56 truncate font-mono text-xs">
        {row.original.issuerDn}
      </span>
    ),
  },
  {
    accessorKey: "profile",
    id: "profile",
    header: "Profile",
    size: 170,
    cell: ({ row }) =>
      row.original.profile ? (
        <Link
          href={`/machine-identity/profiles/${row.original.profile.profileXref}`}
          className="block max-w-48 truncate hover:text-primary"
          onClick={(event) => event.stopPropagation()}
        >
          {row.original.profile.name}
        </Link>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
  },
  {
    id: "key",
    header: "Key",
    size: 110,
    cell: ({ row }) => (
      <span className="whitespace-nowrap">
        {formatKeyStrength(row.original)}
      </span>
    ),
  },
  {
    accessorKey: "status",
    id: "status",
    header: "Status",
    // Wide enough for the longest pill ("Revoke failed"); a narrower column
    // clipped it, since badges never wrap.
    size: 140,
    cell: ({ row }) => (
      <Badge variant={certificateStatusVariant(row.original.status)}>
        {certificateStatusLabel(row.original.status)}
      </Badge>
    ),
  },
  {
    accessorKey: "renewalState",
    id: "renewal",
    header: "Renewal",
    size: 150,
    cell: ({ row }) => {
      const { renewalState, lastNudgeOutcome } = row.original;
      // `NONE` is the resting state of almost every healthy certificate, so a
      // badge on each one would be noise the eye has to filter past.
      if (!isRenewalStateSurfaced(renewalState)) {
        return <span className="text-muted-foreground">—</span>;
      }
      return (
        <span className="flex flex-col items-start gap-0.5">
          <Badge variant={certificateRenewalStateVariant(renewalState)}>
            {CERTIFICATE_RENEWAL_STATE_LABELS[renewalState]}
          </Badge>
          {renewalState === "NUDGING" && lastNudgeOutcome ? (
            <span className="max-w-36 truncate text-xs text-muted-foreground">
              {nudgeOutcomeLabel(lastNudgeOutcome)}
            </span>
          ) : null}
        </span>
      );
    },
  },
  {
    accessorKey: "validFrom",
    id: "valid-from",
    header: "Valid from",
    size: 110,
    cell: ({ row }) => (
      <span className="whitespace-nowrap text-muted-foreground">
        {formatDate(row.original.validFrom)}
      </span>
    ),
  },
  {
    accessorKey: "validTo",
    id: "valid-to",
    header: "Valid to",
    size: 110,
    cell: ({ row }) => (
      <span className="whitespace-nowrap text-muted-foreground">
        {formatDate(row.original.validTo)}
      </span>
    ),
  },
  {
    accessorKey: "remainingDays",
    id: "remaining",
    header: "Remaining",
    size: 130,
    cell: ({ row }) => (
      <span className="whitespace-nowrap">
        {formatRemainingLifetime(row.original.remainingDays)}
      </span>
    ),
  },
];
