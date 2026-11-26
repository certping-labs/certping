// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import React, { Suspense } from "react";

import { OrganizationAccessPage } from "@/components/settings/organization-access/organization-access-page";
import { Skeleton } from "@/components/ui/skeleton";

export const metadata: Metadata = {
  title: "Organization & Access",
};

export default function SettingsOrganizationAccessPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-6 p-6">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-96 w-full rounded-2xl" />
        </div>
      }
    >
      <OrganizationAccessPage />
    </Suspense>
  );
}
