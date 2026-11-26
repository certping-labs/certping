// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { PageHeader } from "@/components/ui/page-header";
import { SupportGuide } from "@/components/support/support-guide";

/** Support: the static guide on how to get help, for every installation. */
export default function SupportPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="Support"
        subtitle="How to get help with CertPing, whatever way you run it."
      />
      <SupportGuide />
    </div>
  );
}
