// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { WarningIcon } from "@phosphor-icons/react/dist/ssr";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface DashboardDataAlertProps {
  isPqcReadinessError: boolean;
}

export function DashboardDataAlert({
  isPqcReadinessError,
}: DashboardDataAlertProps) {
  if (!isPqcReadinessError) return null;

  return (
    <Alert variant="destructive" className="bg-card">
      <WarningIcon aria-hidden="true" className="size-4" />
      <AlertTitle>Could not load PQC readiness data</AlertTitle>
      <AlertDescription>
        The readiness report is unavailable. Refresh the dashboard to try again.
      </AlertDescription>
    </Alert>
  );
}
