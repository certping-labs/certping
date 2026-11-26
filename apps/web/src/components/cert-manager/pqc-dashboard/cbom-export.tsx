// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { useState } from "react";
import {
  DownloadSimpleIcon,
  FileCodeIcon,
} from "@phosphor-icons/react/dist/ssr";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useCbomDownload } from "@/hooks/use-cbom-pqc-dashboard";
import { saveBlob } from "@/lib/download";
import type { CbomDocument } from "@/types/cbom-pqc";

const CBOM_SPEC_VERSION = "1.6";

interface CbomExportProps {
  totalCertificates?: number;
  isLoading: boolean;
}

export function CbomExport({ totalCertificates, isLoading }: CbomExportProps) {
  const [isOpen, setIsOpen] = useState(false);
  const cbom = useCbomDownload();

  const exportCbom = () => cbom.mutate(undefined, { onSuccess: saveCbom });
  const viewJson = () =>
    cbom.mutate(undefined, { onSuccess: () => setIsOpen(true) });

  return (
    <>
      <Card className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">
            CycloneDX cryptography inventory
          </h2>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            {describeInventory(totalCertificates, isLoading)}
          </p>
          {cbom.isError ? (
            <p role="alert" className="mt-1 text-xs leading-5 text-destructive">
              The CBOM document could not be generated. Try again.
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={isLoading || cbom.isPending}
            onClick={viewJson}
          >
            <FileCodeIcon aria-hidden="true" /> View JSON
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={isLoading || cbom.isPending}
            isPending={cbom.isPending}
            onClick={exportCbom}
          >
            <DownloadSimpleIcon aria-hidden="true" /> Export CBOM
          </Button>
        </div>
      </Card>

      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>CBOM JSON payload</DialogTitle>
            <DialogDescription>
              Full CycloneDX report for downstream cryptographic inventory
              tools.
            </DialogDescription>
          </DialogHeader>
          <pre className="max-h-[70vh] overflow-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-xs leading-relaxed text-muted-foreground">
            {cbom.data?.text || "No CBOM payload yet."}
          </pre>
        </DialogContent>
      </Dialog>
    </>
  );
}

function describeInventory(
  totalCertificates: number | undefined,
  isLoading: boolean,
): string {
  if (isLoading) return "Loading report metadata…";
  if (totalCertificates === undefined) {
    return `Certificate count unavailable · spec ${CBOM_SPEC_VERSION}`;
  }
  return `${totalCertificates.toLocaleString()} certificates · spec ${CBOM_SPEC_VERSION}`;
}

function saveCbom(cbom: CbomDocument) {
  saveBlob(
    new Blob([cbom.text], { type: "application/json" }),
    "certping-cryptography-inventory.json",
  );
}
