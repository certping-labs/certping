// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { WarningCircleIcon } from "@phosphor-icons/react";

interface ExportErrorAlertProps {
  message: string | null;
}

/**
 * Why the last download failed, in the critical tone. The live region is
 * always rendered and only its text changes, so screen readers announce each
 * new failure; an empty region takes no space.
 */
export function ExportErrorAlert({ message }: ExportErrorAlertProps) {
  return (
    <div role="alert" aria-atomic="true">
      {message ? (
        <p className="flex items-start gap-2 rounded-[10px] border border-l-2 border-danger-border border-l-danger bg-danger-soft px-3.5 py-2.5 text-sm text-danger-foreground">
          <WarningCircleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span className="min-w-0 wrap-break-word">{message}</span>
        </p>
      ) : null}
    </div>
  );
}
