// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { CircleNotchIcon, DotsThreeIcon } from "@phosphor-icons/react/dist/ssr";

import { Button, type ButtonProps } from "@/components/ui/button";

export const RowActionsTrigger = React.forwardRef<
  HTMLButtonElement,
  Omit<ButtonProps, "children" | "variant" | "size"> & {
    label: string;
    isPending?: boolean;
  }
>(function RowActionsTrigger({ label, isPending, ...props }, ref) {
  return (
    <Button
      ref={ref}
      variant="ghost"
      size="iconSm"
      aria-label={`Actions for ${label}`}
      {...props}
    >
      {isPending ? (
        <CircleNotchIcon className="animate-spin" aria-hidden />
      ) : (
        <DotsThreeIcon aria-hidden />
      )}
    </Button>
  );
});
