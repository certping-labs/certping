// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from "next/navigation";

import { legacySettingsRedirect } from "@/lib/legacy-settings-redirect";

/** The old notification settings page: now the Notifications tab of Organization & Access. */
export default async function NotificationSettingsPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  redirect(legacySettingsRedirect("notifications", await searchParams));
}
