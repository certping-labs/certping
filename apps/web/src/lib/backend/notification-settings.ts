// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { z } from "zod";

import { apiClient, apiRoutes } from "@/lib/api";

const settingsSchema = z.object({
  categories: z.array(
    z.object({ key: z.string().min(1), enabled: z.boolean() }),
  ),
});

/** One category an organization can turn off, and whether it is sent. */
export interface NotificationCategorySetting {
  readonly key: string;
  readonly enabled: boolean;
}

/** The organization's notification categories, in the order the server serves them. */
export async function getNotificationSettings(
  organizationId: string | number,
): Promise<NotificationCategorySetting[]> {
  const response = await apiClient.get<unknown>(
    apiRoutes.query.organization.notificationSettings(organizationId),
  );
  return settingsSchema.parse(response.data).categories;
}

/** Turns off exactly `muted`; every other category is sent. Answers the saved state. */
export async function saveNotificationSettings(
  organizationId: string | number,
  muted: readonly string[],
): Promise<NotificationCategorySetting[]> {
  const response = await apiClient.put<unknown>(
    apiRoutes.mutation.organization.notificationSettings(organizationId),
    { muted },
  );
  return settingsSchema.parse(response.data).categories;
}
