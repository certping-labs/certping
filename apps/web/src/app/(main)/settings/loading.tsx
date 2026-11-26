// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { Skeleton } from "@/components/ui/skeleton";

export default function Loading() {
  return (
    <main className="flex min-h-[90svh] w-full items-center justify-center">
      <div className="space-y-6">
        <div className="flex items-center space-x-4">
          <Skeleton className="h-20 w-20 rounded-full" />
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-4 w-[200px]" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-4 w-[200px]" />
          <Skeleton className="h-10 w-full" />
        </div>
        <Skeleton className="h-10 w-[150px]" />
      </div>
    </main>
  );
}
