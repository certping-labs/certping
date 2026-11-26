// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from "next/navigation";

import { legacySettingsRedirect } from "@/lib/legacy-settings-redirect";

/** The old Organizations page: now the Organization tab of Organization & Access. */
export default async function OrganizationsPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  redirect(legacySettingsRedirect("organization", await searchParams));
}
