// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { WarningCircleIcon } from "@phosphor-icons/react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

export function SomethingWentWrong({
  title,
  description,
  reference,
  onRetry,
}: {
  title?: string;
  description?: string;
  reference?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex justify-center py-8">
      <Alert variant="destructive" className="w-full max-w-lg">
        <WarningCircleIcon aria-hidden />
        <div>
          <AlertTitle>{title ?? "Something went wrong"}</AlertTitle>
          <AlertDescription className="space-y-3">
            {description ? <p>{description}</p> : null}
            {reference ? (
              <p className="text-xs">
                Reference: <span className="font-mono">{reference}</span>
              </p>
            ) : null}
            {onRetry ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={onRetry}
              >
                Try again
              </Button>
            ) : null}
          </AlertDescription>
        </div>
      </Alert>
    </div>
  );
}
