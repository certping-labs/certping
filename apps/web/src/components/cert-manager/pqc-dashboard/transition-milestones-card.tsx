// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { Card } from "@/components/ui/card";

const NIST_MILESTONES = [
  {
    year: "2030",
    title: "Deprecate vulnerable public-key algorithms",
  },
  {
    year: "2035",
    title: "Disallow legacy algorithm use",
  },
] as const;

export function TransitionMilestonesCard() {
  return (
    <Card className="p-4 sm:p-5 xl:p-4">
      <h2 className="text-sm font-semibold">NIST transition milestones</h2>
      <div className="relative mt-4 space-y-4 before:absolute before:top-2 before:bottom-2 before:left-[5px] before:w-px before:bg-primary/25">
        {NIST_MILESTONES.map((milestone) => (
          <Milestone key={milestone.year} {...milestone} />
        ))}
      </div>
    </Card>
  );
}

function Milestone({ title, year }: { title: string; year: string }) {
  return (
    <div className="relative grid grid-cols-[12px_1fr] gap-3">
      <span className="relative z-10 mt-1 size-[11px] rounded-full border-2 border-card bg-primary ring-1 ring-primary/20" />
      <div>
        <p className="text-sm font-semibold tabular-nums">{year}</p>
        <p className="mt-0.5 text-xs leading-4 text-muted-foreground">
          {title}
        </p>
      </div>
    </div>
  );
}
