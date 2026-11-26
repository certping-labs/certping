// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { Skeleton } from "@/components/ui/skeleton";

export default function Loading() {
  return (
    <main className="flex min-h-[90svh] w-full items-center justify-center">
      <Skeleton className="h-64 max-w-md" />
    </main>
  );
}
