// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { CopyIcon, CircleNotchIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { copyToClipboard } from "@/lib/utils";
import type { CertificateTxtRecord } from "@/types/cert-manager";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export interface ManualTxtRecordsDialogState {
  certificateXref: string;
  domain: string;
  txtRecords: CertificateTxtRecord[];
}

interface ManualTxtRecordsDialogProps {
  open: boolean;
  draft: ManualTxtRecordsDialogState | null;
  isValidating?: boolean;
  onOpenChange: (open: boolean) => void;
  onValidate?: (draft: ManualTxtRecordsDialogState) => Promise<void> | void;
}

export function ManualTxtRecordsDialog({
  open,
  draft,
  isValidating = false,
  onOpenChange,
  onValidate,
}: ManualTxtRecordsDialogProps) {
  const handleCopy = (label: string, value: string) => {
    try {
      copyToClipboard(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error(`Failed to copy ${label.toLowerCase()}`);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>Publish TXT records</DialogTitle>
          <DialogDescription>
            Add these TXT records for {draft?.domain ?? "this certificate"} and
            then trigger validation to continue the issuance workflow.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {(draft?.txtRecords ?? []).map((record) => (
            <Card key={`${record.domain}:${record.recordName}`}>
              <CardContent className="space-y-3 p-4">
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    Record name
                  </div>
                  <div className="mt-1 flex items-start gap-2 rounded-md bg-muted px-3 py-2 font-mono text-sm">
                    <span className="flex-1 break-all">
                      {record.recordName}
                    </span>
                    <Button
                      size="icon"
                      type="button"
                      variant="ghost"
                      aria-label="Copy record name"
                      onClick={() =>
                        handleCopy("Record name", record.recordName)
                      }
                    >
                      <CopyIcon className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-medium text-muted-foreground">
                    Record value
                  </div>
                  <div className="mt-1 flex items-start gap-2 rounded-md bg-muted px-3 py-2 font-mono text-sm">
                    <span className="flex-1 break-all">
                      {record.recordValue}
                    </span>
                    <Button
                      size="icon"
                      type="button"
                      variant="ghost"
                      aria-label="Copy record value"
                      onClick={() =>
                        handleCopy("Record value", record.recordValue)
                      }
                    >
                      <CopyIcon className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <DialogFooter className="gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
          >
            Close
          </Button>
          {onValidate ? (
            <Button
              disabled={!draft || isValidating}
              type="button"
              onClick={() => draft && onValidate(draft)}
            >
              {isValidating ? (
                <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Validate DNS
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
