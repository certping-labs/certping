// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useMemo, useState } from "react";
import { CheckIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { DetailSection } from "@/components/ui/detail-list";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useAuth } from "@/hooks/use-auth";
import { useFeatureFlags } from "@/hooks/use-feature-flags";
import {
  useNotificationSettings,
  useSaveNotificationSettings,
} from "@/hooks/notification-settings";
import {
  canChangeNotificationSettings,
  canViewNotificationSettings,
} from "@/lib/authz";
import type { NotificationCategorySetting } from "@/lib/backend/notification-settings";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  NOTIFICATION_SETTINGS_UNAVAILABLE,
  alwaysSentNotifications,
  isNotificationSettingsUnavailable,
  notificationCategories,
  notificationChannels,
  type FeatureCheck,
} from "@/lib/notification-settings";

export const NOTIFICATION_PREFERENCES_ID = "notification-preferences";

/**
 * The organization's notification preferences on the Account page. Shown only
 * while CertPing has notification preferences on for the organization, and to
 * whoever may see them; only the organization's own admins change them.
 */
export function NotificationPreferences() {
  const { user, isSuperAdmin } = useAuth();
  const { isEnabled } = useFeatureFlags();
  const organizationId = user?.organizationId;

  if (
    !organizationId ||
    !isEnabled(FEATURE_FLAGS.NOTIFICATION_PREFERENCES) ||
    !canViewNotificationSettings(user, isSuperAdmin)
  ) {
    return null;
  }

  return (
    <Preferences
      organizationId={organizationId}
      canChange={canChangeNotificationSettings(user, isSuperAdmin)}
      isEnabled={isEnabled}
    />
  );
}

function Preferences({
  organizationId,
  canChange,
  isEnabled,
}: {
  organizationId: string | number;
  canChange: boolean;
  isEnabled: FeatureCheck;
}) {
  const query = useNotificationSettings(organizationId);
  const save = useSaveNotificationSettings(organizationId);

  return (
    <section
      id={NOTIFICATION_PREFERENCES_ID}
      className="scroll-mt-6 rounded-xl border border-border bg-card"
    >
      <DetailSection
        title="Notification preferences"
        className="p-5"
        description={`Choose which informational notifications are sent. ${notificationChannels(isEnabled)}`}
      >
        {query.isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-12 w-full rounded-lg" />
            ))}
          </div>
        )}

        {query.isError && (
          <p role="alert" className="text-sm text-muted-foreground">
            {isNotificationSettingsUnavailable(query.error)
              ? NOTIFICATION_SETTINGS_UNAVAILABLE
              : "Notification settings couldn't be loaded. Please try again."}
          </p>
        )}

        {query.data && (
          <CategoryChoices
            // A fresh form for every saved state, so the switches start from what is stored.
            key={JSON.stringify(query.data)}
            stored={query.data}
            canChange={canChange}
            isEnabled={isEnabled}
            saving={save.isPending}
            onSave={(muted) => save.mutate(muted)}
          />
        )}
      </DetailSection>

      {query.data && (
        <DetailSection
          title="Always sent"
          className="p-5"
          description="These can't be turned off."
        >
          <ul className="space-y-1">
            {alwaysSentNotifications(isEnabled).map((group) => (
              <li
                key={group.label}
                className="flex items-start gap-3 border-b py-2 last:border-0"
              >
                <CheckIcon
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                />
                <div className="min-w-0">
                  <span className="text-sm font-medium">{group.label}</span>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {group.description}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        </DetailSection>
      )}
    </section>
  );
}

function CategoryChoices({
  stored,
  canChange,
  isEnabled,
  saving,
  onSave,
}: {
  stored: readonly NotificationCategorySetting[];
  canChange: boolean;
  isEnabled: FeatureCheck;
  saving: boolean;
  onSave: (muted: string[]) => void;
}) {
  const initial = useMemo(
    () =>
      new Set(
        stored
          .filter((setting) => !setting.enabled)
          .map((setting) => setting.key),
      ),
    [stored],
  );
  const [muted, setMuted] = useState<ReadonlySet<string>>(initial);
  const changed =
    muted.size !== initial.size || [...muted].some((key) => !initial.has(key));
  const served = new Set(stored.map((setting) => setting.key));
  const categories = notificationCategories(isEnabled).filter((category) =>
    served.has(category.key),
  );

  const toggle = (key: string, sent: boolean) => {
    setMuted((current) => {
      const next = new Set(current);
      if (sent) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  return (
    <div>
      <p className="text-sm text-muted-foreground">
        {canChange
          ? "Turn off what you don't need. Everything is sent unless you turn it off."
          : "Only organization admins can change these settings."}
      </p>
      <div className="mt-2 space-y-1">
        {categories.map((category) => {
          const sent = !muted.has(category.key);
          const state = sent ? "Sent" : "Off";
          const descriptionId = `notification-category-${category.key}`;
          return (
            <div
              key={category.key}
              className="flex items-start justify-between gap-4 border-b py-2 last:border-0"
            >
              <div className="min-w-0">
                <span className="text-sm font-medium">{category.label}</span>
                <p
                  id={descriptionId}
                  className="mt-0.5 text-xs text-muted-foreground"
                >
                  {category.description}
                </p>
              </div>
              {canChange ? (
                <Switch
                  checked={sent}
                  aria-label={category.label}
                  aria-describedby={descriptionId}
                  disabled={saving}
                  onCheckedChange={(checked) => toggle(category.key, checked)}
                />
              ) : (
                <span
                  role="group"
                  aria-label={`${category.label}: ${state}`}
                  className="shrink-0 text-sm font-medium"
                >
                  {state}
                </span>
              )}
            </div>
          );
        })}
      </div>
      {canChange && (
        <div className="flex justify-end pt-3">
          <Button
            disabled={!changed || saving}
            onClick={() =>
              onSave(
                stored
                  .map((setting) => setting.key)
                  .filter((key) => muted.has(key)),
              )
            }
          >
            {saving ? "Saving…" : "Save changes"}
          </Button>
        </div>
      )}
    </div>
  );
}
