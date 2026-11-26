// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { useIntegrationsTabs } from "@/components/integrations/use-integrations-tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { INTEGRATIONS_APPS_HREF } from "@/lib/integrations/routes";

/**
 * `/integrations` has no surface of its own - it lands on the first tab this
 * user can actually see.
 *
 * Which tabs exist depends on permissions and on feature flags that arrive
 * asynchronously, so the redirect waits for `isReady`. Redirecting earlier
 * would bounce a credentials-only user to Apps before their flags loaded.
 * With no visible tab at all we still send them to Apps, where the route
 * guard renders the unauthorised state rather than a blank page.
 */
export default function IntegrationsIndexPage() {
  const router = useRouter();
  const { tabs, isReady } = useIntegrationsTabs();
  const destination = tabs[0]?.href ?? INTEGRATIONS_APPS_HREF;

  useEffect(() => {
    if (!isReady) {
      return;
    }
    router.replace(destination);
  }, [destination, isReady, router]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <Skeleton className="h-16 rounded-(--certping-radius-md)" />
      <Skeleton className="h-64 rounded-(--certping-radius-md)" />
    </div>
  );
}
