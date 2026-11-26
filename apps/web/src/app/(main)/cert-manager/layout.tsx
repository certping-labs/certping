// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import { certManagerSeoMetadata } from "@/lib/seo-metadata";

export const metadata: Metadata = certManagerSeoMetadata;

export default function CertManagerLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
