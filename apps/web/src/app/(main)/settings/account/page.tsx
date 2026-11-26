// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from "next/navigation";

import { legacySettingsRedirect } from "@/lib/legacy-settings-redirect";

/** The old Account page: now the Your account tab of Organization & Access. */
export default async function AccountPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  redirect(legacySettingsRedirect("account", await searchParams));
}
