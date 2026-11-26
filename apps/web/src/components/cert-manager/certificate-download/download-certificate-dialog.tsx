// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useCallback, useMemo, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Form } from "@/components/ui/form";
import {
  useExportCertificate,
  useIsKeyHeldExternally,
} from "@/hooks/certificate-export";
import type { CertificateExportError } from "@/lib/cert-manager/certificate-export-errors";
import {
  certificateExportFormSchema,
  getDefaultExportFormValues,
  getExportFormatOptions,
  toCertificateExportRequest,
  type CertificateExportFormValues,
} from "@/lib/cert-manager/certificate-export-form";
import type { CertificateDownloadTarget } from "@/types/certificate-export";
import { ExportErrorAlert } from "./export-error-alert";
import { ExportFormatField } from "./export-format-field";
import { PfxPasswordFields } from "./pfx-password-fields";

export interface DownloadCertificateDialogProps {
  target: CertificateDownloadTarget;
  /** From `canExportPrivateKey`; without it only the key-free formats are offered. */
  canDownloadPrivateKey: boolean;
  onClose: () => void;
}

/**
 * Lets the user pick a file format and, for PFX, a password, then downloads
 * the certificate. Failures stay inline until the user edits or retries.
 * Mounted only while open, so the form, password included, is discarded on
 * close; the password fields are also cleared after every request.
 */
export function DownloadCertificateDialog({
  target,
  canDownloadPrivateKey,
  onClose,
}: DownloadCertificateDialogProps) {
  const isKeyRefused = useIsKeyHeldExternally(target.certificateXref);
  // Set when the backend answers EXPORT_KEY_NOT_PERMITTED: the session's
  // permissions are older than the server's, so trust the server.
  const [isKeyForbidden, setIsKeyForbidden] = useState(false);
  const withoutPrivateKey =
    isKeyRefused ||
    isKeyForbidden ||
    !canDownloadPrivateKey ||
    target.keyCustody === "CUSTOMER_HELD";
  const options = useMemo(
    () => getExportFormatOptions(target.formats, { withoutPrivateKey }),
    [target.formats, withoutPrivateKey],
  );
  const form = useForm<CertificateExportFormValues>({
    resolver: zodResolver(certificateExportFormSchema),
    defaultValues: getDefaultExportFormValues(options),
    mode: "onTouched",
    shouldFocusError: true,
  });
  const [exportErrorMessage, setExportErrorMessage] = useState<string | null>(
    null,
  );
  const clearExportError = () => setExportErrorMessage(null);

  const showExportError = useCallback(
    (error: CertificateExportError) => {
      setExportErrorMessage(error.message);
      if (error.isKeyNotPermitted) {
        setIsKeyForbidden(true);
      }
      if (error.isKeyHeldExternally || error.isKeyNotPermitted) {
        const [keyFreeOption] = getExportFormatOptions(target.formats, {
          withoutPrivateKey: true,
        });
        if (keyFreeOption) {
          form.setValue("format", keyFreeOption.format);
        }
      }
    },
    [form, target.formats],
  );
  const { exportAndSave, isPending } = useExportCertificate({
    onInlineError: showExportError,
  });
  const format = useWatch({ control: form.control, name: "format" });
  const selectedOption = options.find((option) => option.format === format);

  const clearPasswordFields = () => {
    form.resetField("password");
    form.resetField("confirmPassword");
  };

  const handleFormatChange = (nextFormat: string) => {
    clearExportError();
    if (nextFormat !== "PKCS12") {
      clearPasswordFields();
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (!open && !isPending) {
      onClose();
    }
  };

  const submitExport = form.handleSubmit((values) => {
    exportAndSave(
      {
        certificateXref: target.certificateXref,
        fileNameSource: {
          domain: target.domain,
          isWildcard: target.isWildcard === true,
        },
        request: toCertificateExportRequest(values),
      },
      { onSuccess: onClose, onSettled: clearPasswordFields },
    );
  });

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    clearExportError();
    void submitExport(event);
  };

  return (
    <Dialog open onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Download certificate</DialogTitle>
          <DialogDescription>
            Choose the format your server expects for{" "}
            <span className="font-medium break-all text-foreground">
              {target.domain}
            </span>
            .
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form noValidate onSubmit={handleSubmit} className="space-y-5">
            <ExportFormatField
              control={form.control}
              options={options}
              disabled={isPending}
              onFormatChange={handleFormatChange}
            />
            <div aria-live="polite">
              {selectedOption?.containsPrivateKey ? (
                <p className="flex items-start gap-2 rounded-[10px] border border-border px-3.5 py-2.5 text-sm text-muted-foreground">
                  <KeyIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
                  Contains the private key. Store it securely and don&apos;t
                  share it.
                </p>
              ) : null}
            </div>
            {selectedOption?.format === "PKCS12" ? (
              <PfxPasswordFields
                control={form.control}
                disabled={isPending}
                onEdit={clearExportError}
              />
            ) : null}
            <ExportErrorAlert message={exportErrorMessage} />
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                className="h-11 sm:h-10"
                disabled={isPending}
                onClick={onClose}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                className="h-11 sm:h-10"
                isPending={isPending}
                disabled={isPending || options.length === 0}
              >
                Download
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
