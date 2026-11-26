// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { AuditTrail } from "@/components/audit-trail/audit-trail";
import { useAuth } from "@/hooks/use-auth";
import { hasOrganizationContext, isRootOrSuperAdmin } from "@/lib/authz";
import { certManagerAuditSource } from "@/lib/cert-manager-audit-source";

/**
 * The organization's audit log, with its Access view. A super admin outside
 * any organization reads every organization's through the platform route.
 */
export default function AuditLogsPage() {
  const { user, isSuperAdmin } = useAuth();
  const platform =
    isRootOrSuperAdmin(user, isSuperAdmin) && !hasOrganizationContext(user);
  return <AuditTrail source={certManagerAuditSource} platform={platform} />;
}
