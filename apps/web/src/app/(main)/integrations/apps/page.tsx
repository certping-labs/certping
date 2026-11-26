// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { IntegrationsManager } from "@/components/integrations/add-integration-form";
import { IntegrationsTabHeader } from "@/components/integrations/integrations-tab-header";

export default function IntegrationsAppsPage() {
  return (
    <div className="space-y-4">
      <IntegrationsTabHeader
        title="Apps"
        description="Send alerts and tickets to the tools your team already works in."
      />

      <IntegrationsManager />
    </div>
  );
}
