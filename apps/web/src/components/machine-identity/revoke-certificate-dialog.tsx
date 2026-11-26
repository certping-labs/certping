// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useRef, useState } from "react";
import { CircleNotchIcon, ShieldSlashIcon } from "@phosphor-icons/react";

import { ModuleNotice } from "@/components/machine-identity/module-notice";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useRevokeCertificate } from "@/hooks/machine-identity/use-machine-certificates";
import {
  REVOCATION_REASON_DESCRIPTIONS,
  REVOCATION_REASON_LABELS,
} from "@/lib/machine-identity/backend-display";
import {
  resolveIdempotencyKey,
  type PendingIdempotentRequest,
} from "@/lib/machine-identity/idempotency";
import type { IotRevocationReason } from "@/types/machine-identity-backend";

/** Server cap on `operatorNote`; enforced here so the field cannot 400. */
const OPERATOR_NOTE_MAX_LENGTH = 500;

const REASON_ORDER: IotRevocationReason[] = [
  "KEY_COMPROMISE",
  "SUPERSEDED",
  "CESSATION_OF_OPERATION",
  "AFFILIATION_CHANGED",
  "PRIVILEGES_WITHDRAWN",
  "UNSPECIFIED",
];

interface RevokeCertificateDialogProps {
  certificateXref: string;
  commonName: string;
  /** The device holding it, named in the confirmation so the blast radius is explicit. */
  deviceName: string | null;
  /** Disables the trigger; see `canRequestRevocation`. */
  disabled?: boolean;
  disabledReason?: string;
}

/**
 * Requests revocation of one device certificate.
 *
 * <p>Revocation is not reversible and is not coordinated with the device: the
 * CA stops vouching for the certificate, and the device keeps presenting it
 * until it next enrolls. The copy says so, because the operator's real question
 * is "what breaks", not "are you sure".
 */
export function RevokeCertificateDialog({
  certificateXref,
  commonName,
  deviceName,
  disabled,
  disabledReason,
}: RevokeCertificateDialogProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [reason, setReason] = useState<IotRevocationReason>("SUPERSEDED");
  const [operatorNote, setOperatorNote] = useState("");
  const revokeCertificate = useRevokeCertificate();

  /**
   * The key survives a failed submit so a retry replays the same request
   * rather than opening a second revocation operation for one the CA may
   * already have taken. Changing the reason or the note changes the
   * fingerprint, which correctly mints a new key.
   */
  const pendingRequest = useRef<PendingIdempotentRequest | null>(null);

  const trimmedNote = operatorNote.trim();
  const fingerprint = JSON.stringify({ certificateXref, reason, trimmedNote });

  const submit = () => {
    const key = resolveIdempotencyKey(pendingRequest.current, fingerprint);
    pendingRequest.current = { fingerprint, key };
    revokeCertificate.mutate(
      {
        certificateXref,
        input: {
          reason,
          ...(trimmedNote ? { operatorNote: trimmedNote } : {}),
        },
        idempotencyKey: key,
      },
      {
        onSuccess: () => {
          pendingRequest.current = null;
          setOperatorNote("");
          setIsOpen(false);
        },
      },
    );
  };

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => {
        if (revokeCertificate.isPending) return;
        setIsOpen(open);
      }}
    >
      <DialogTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          disabled={disabled}
          title={disabled ? disabledReason : undefined}
        >
          <ShieldSlashIcon className="size-4" aria-hidden="true" />
          Revoke
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Revoke {commonName}?</DialogTitle>
          <DialogDescription>
            The CA stops vouching for this certificate and publishes it to its
            CRL and OCSP responder. You cannot undo this. Getting the device a
            working certificate again means a new enrollment.
          </DialogDescription>
        </DialogHeader>

        <ModuleNotice tone="warning">
          {deviceName
            ? `${deviceName} keeps presenting this certificate until it next enrolls, and every service that checks revocation will start rejecting it.`
            : "The device holding this certificate keeps presenting it until it next enrolls, and every service that checks revocation will start rejecting it."}
        </ModuleNotice>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="revocation-reason">Reason</Label>
            <Select
              value={reason}
              onValueChange={(value) => setReason(value as IotRevocationReason)}
            >
              <SelectTrigger id="revocation-reason" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REASON_ORDER.map((value) => (
                  <SelectItem key={value} value={value}>
                    {REVOCATION_REASON_LABELS[value]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {/* The reason is written into the CRL entry and relying parties act
                on it, so what it means matters more than what it is called. */}
            <p className="text-xs text-muted-foreground">
              {REVOCATION_REASON_DESCRIPTIONS[reason]}
            </p>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="revocation-note">
              Note <span className="text-muted-foreground">(optional)</span>
            </Label>
            <Textarea
              id="revocation-note"
              value={operatorNote}
              maxLength={OPERATOR_NOTE_MAX_LENGTH}
              rows={3}
              placeholder="Why you are revoking this certificate. Kept on the audit record."
              onChange={(event) => setOperatorNote(event.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {operatorNote.length}/{OPERATOR_NOTE_MAX_LENGTH}
            </p>
          </div>
        </div>

        <DialogFooter className="flex-col-reverse gap-2 sm:flex-row">
          <Button
            variant="outline"
            disabled={revokeCertificate.isPending}
            onClick={() => setIsOpen(false)}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={revokeCertificate.isPending}
            onClick={submit}
          >
            {revokeCertificate.isPending ? (
              <CircleNotchIcon
                className="size-4 animate-spin"
                aria-hidden="true"
              />
            ) : null}
            Revoke certificate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
