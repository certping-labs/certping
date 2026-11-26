// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { ShieldWarningIcon } from "@phosphor-icons/react/dist/ssr";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

interface UnauthorisedProps {
  title?: string;
  description?: string;
  children?: React.ReactNode;
}

export function Unauthorised({
  title = "Access restricted",
  description = "You do not have permission to access this page.",
  children,
}: UnauthorisedProps) {
  return (
    <Alert variant="warning" className="mx-auto max-w-md">
      <ShieldWarningIcon aria-hidden />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>{description}</p>
        {children}
      </AlertDescription>
    </Alert>
  );
}
