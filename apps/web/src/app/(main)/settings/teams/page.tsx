// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from "next/navigation";

import { legacySettingsRedirect } from "@/lib/legacy-settings-redirect";

/** The old Members page: now the Members & roles tab of Organization & Access. */
export default async function TeamsPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  redirect(legacySettingsRedirect("members", await searchParams));
}
