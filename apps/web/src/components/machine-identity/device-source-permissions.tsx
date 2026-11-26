// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { CheckCircleIcon, XCircleIcon } from "@phosphor-icons/react/dist/ssr";

import { Badge } from "@/components/ui/badge";
import { intunePermissionLabel } from "@/lib/machine-identity/backend-display";
import type { DeviceSourcePermission } from "@/types/machine-identity-backend";

interface DeviceSourcePermissionsProps {
  permissions: DeviceSourcePermission[];
}

/** The Graph application roles reported by the agent's latest health check. */
export function DeviceSourcePermissions({
  permissions,
}: DeviceSourcePermissionsProps) {
  if (permissions.length === 0) {
    return (
      <p className="px-4 py-5 text-sm text-muted-foreground">
        No permission report has arrived. Run or wait for the agent&apos;s next
        health check.
      </p>
    );
  }

  return (
    <ul className="divide-y divide-border">
      {permissions.map((permission) => {
        const Icon = permission.granted ? CheckCircleIcon : XCircleIcon;
        return (
          <li
            key={permission.name}
            className="flex items-start gap-3 px-4 py-3"
          >
            <Icon
              className={
                permission.granted
                  ? "mt-0.5 size-4 shrink-0 status-success-text"
                  : "mt-0.5 size-4 shrink-0 status-danger-text"
              }
              aria-hidden="true"
            />
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium">
                {intunePermissionLabel(permission.name)}
              </span>
              <span className="block font-mono text-xs break-all text-muted-foreground">
                {permission.name}
              </span>
            </span>
            <Badge variant={permission.granted ? "success" : "destructive"}>
              {permission.granted ? "Granted" : "Missing"}
            </Badge>
          </li>
        );
      })}
    </ul>
  );
}
