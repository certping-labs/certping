// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

/**
 * Why an access save (member roles, role permissions, re-enabling a member)
 * is unavailable right now. While the feature-flag answer is still loading,
 * the backend cannot yet be trusted to have hidden the roles and permissions
 * of features that are off, so a save could send a set built on stale lists.
 */
export const ACCESS_SAVE_WAITING_REASON =
  "Checking which features are on. You can save in a moment.";

/** The reason a footer's save button is disabled, linked by `id`. */
export function AccessSaveBlockedNote({
  id,
  reason,
}: {
  id: string;
  reason: string | null;
}) {
  if (!reason) return null;
  return (
    <p
      id={id}
      role="status"
      className="text-xs leading-5 text-muted-foreground sm:mr-auto sm:self-center"
    >
      {reason}
    </p>
  );
}
