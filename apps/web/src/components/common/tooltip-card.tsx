// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  TooltipContent,
  TooltipTrigger,
  Tooltip,
  TooltipProvider,
} from "../ui/tooltip";
import React, { JSX } from "react";

export function ToolTipCard(props: {
  delay?: number;
  value: string | JSX.Element;
  children: JSX.Element;
}) {
  return (
    <TooltipProvider>
      <Tooltip delayDuration={props.delay ?? 50}>
        <TooltipTrigger asChild>{props.children}</TooltipTrigger>
        <TooltipContent>
          <span>{props.value}</span>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
