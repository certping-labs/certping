// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import { toast } from "sonner";

import {
  getNotificationSettings,
  saveNotificationSettings,
} from "@/lib/backend/notification-settings";
import { notificationSettingsSaveError } from "@/lib/notification-settings";

const isClientError = (error: unknown): boolean => {
  const status = axios.isAxiosError(error) ? error.response?.status : undefined;
  return status !== undefined && status >= 400 && status < 500;
};

const notificationSettingsKey = (organizationId: string | number) =>
  ["notification-settings", String(organizationId)] as const;

export const useNotificationSettings = (organizationId: string | number) =>
  useQuery({
    queryKey: notificationSettingsKey(organizationId),
    queryFn: () => getNotificationSettings(organizationId),
    // A refusal (4xx, the 423 of settings that are off included) won't change by asking again.
    retry: (failureCount, error) => !isClientError(error) && failureCount < 3,
  });

export const useSaveNotificationSettings = (
  organizationId: string | number,
) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (muted: readonly string[]) =>
      saveNotificationSettings(organizationId, muted),
    onSuccess: (saved) => {
      queryClient.setQueryData(notificationSettingsKey(organizationId), saved);
      toast.success("Notification settings saved.");
    },
    onError: (error) => {
      toast.error(notificationSettingsSaveError(error));
    },
  });
};
