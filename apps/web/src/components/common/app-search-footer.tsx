// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { Kbd } from "@/components/ui/kbd";

export function AppSearchFooter() {
  return (
    <div className="flex items-center justify-between border-t border-border/70 bg-[hsl(var(--secondary-100)/0.28)] px-4 py-2 text-[11px] text-muted-foreground">
      <span>Search is scoped to pages and actions you can access.</span>
      <div className="hidden items-center gap-3 sm:flex">
        <span className="flex items-center gap-1">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd>
          Navigate
        </span>
        <span className="flex items-center gap-1">
          <Kbd>Enter</Kbd>
          Open
        </span>
        <span className="flex items-center gap-1">
          <Kbd>Esc</Kbd>
          Close
        </span>
      </div>
    </div>
  );
}
