// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import {
  CaretDownIcon,
  DownloadSimpleIcon,
  CircleNotchIcon,
} from "@phosphor-icons/react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { AuditTrailExportFormat } from "@/types/audit-trail";

const FORMATS: readonly { format: AuditTrailExportFormat; label: string }[] = [
  { format: "csv", label: "CSV (spreadsheet)" },
  { format: "json", label: "JSON" },
];

interface AuditTrailExportMenuProps {
  /** What is exported, as the menu says it: "event" or "entry". */
  noun: string;
  disabled: boolean;
  isExporting: boolean;
  onExport: (format: AuditTrailExportFormat) => void;
}

export function AuditTrailExportMenu({
  noun,
  disabled,
  isExporting,
  onExport,
}: AuditTrailExportMenuProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" disabled={disabled || isExporting}>
          {isExporting ? (
            <CircleNotchIcon className="animate-spin" aria-hidden />
          ) : (
            <DownloadSimpleIcon aria-hidden />
          )}
          {isExporting ? "Exporting" : "Export"}
          <CaretDownIcon aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          Every {noun} the filters match, up to 10,000
        </DropdownMenuLabel>
        {FORMATS.map(({ format, label }) => (
          <DropdownMenuItem key={format} onSelect={() => onExport(format)}>
            {label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
