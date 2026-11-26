// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { PqcReadinessCertificate } from "@/types/cbom-pqc";
import { PQC_STATUS_COPY } from "./pqc-status";

interface CertificateDetailsDialogProps {
  certificate: PqcReadinessCertificate | null;
  onOpenChange: (open: boolean) => void;
}

export function CertificateDetailsDialog({
  certificate,
  onOpenChange,
}: CertificateDetailsDialogProps) {
  return (
    <Dialog open={Boolean(certificate)} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {certificate?.commonName || "Certificate details"}
          </DialogTitle>
          <DialogDescription>
            Algorithm context, transition status, and remediation guidance.
          </DialogDescription>
        </DialogHeader>
        {certificate ? (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={PQC_STATUS_COPY[certificate.quantumStatus].variant}
                includeDot
              >
                {PQC_STATUS_COPY[certificate.quantumStatus].label}
              </Badge>
              <Badge
                variant={
                  certificate.hndlRisk === "HIGH" ? "destructive" : "secondary"
                }
                includeDot
              >
                {certificate.hndlRisk === "HIGH"
                  ? "High HNDL risk"
                  : `${certificate.hndlRisk.toLowerCase()} HNDL risk`}
              </Badge>
            </div>
            <dl className="grid gap-4 sm:grid-cols-2">
              <Detail
                label={
                  certificate.source === "DISCOVERED"
                    ? "Discovered at"
                    : "Certificate reference"
                }
                value={certificate.certificateXref}
                mono
              />
              <Detail label="Public key" value={formatKey(certificate)} />
              <Detail
                label="Signature"
                value={certificate.signatureAlgorithm || "Unknown"}
              />
              <Detail
                label="Compliance reference"
                value={certificate.complianceRef || "Not provided"}
              />
              <Detail
                label="Deprecation year"
                value={
                  certificate.deprecationYear?.toString() || "Not provided"
                }
              />
              <Detail
                label="Disallowed year"
                value={certificate.disallowedYear?.toString() || "Not provided"}
              />
            </dl>
            <div className="rounded-md border border-border bg-muted/30 p-4">
              <p className="text-[11px] font-semibold text-muted-foreground">
                Remediation guidance
              </p>
              <p className="mt-2 text-sm leading-6 text-foreground">
                {certificate.remediationAdvice ||
                  "No remediation guidance was provided by the readiness API."}
              </p>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function Detail({
  label,
  mono = false,
  value,
}: {
  label: string;
  mono?: boolean;
  value: string;
}) {
  return (
    <div>
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd
        className={
          mono ? "mt-1 font-mono text-sm break-all" : "mt-1 text-sm font-medium"
        }
      >
        {value}
      </dd>
    </div>
  );
}

function formatKey(certificate: PqcReadinessCertificate): string {
  return [
    certificate.keyAlgorithm || "Unknown",
    certificate.keySize ? `${certificate.keySize}-bit` : "",
    certificate.curve,
  ]
    .filter(Boolean)
    .join(" · ");
}
