// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";

import { IntegrationsSectionShell } from "@/components/integrations/integrations-section-shell";
import { integrationsSeoMetadata } from "@/lib/seo-metadata";

export const metadata: Metadata = integrationsSeoMetadata;

export default function IntegrationsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <IntegrationsSectionShell>{children}</IntegrationsSectionShell>;
}
