// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";
import {
  ArrowRightIcon,
  LockIcon,
  RocketLaunchIcon,
} from "@phosphor-icons/react/dist/ssr";

export interface QuickActionPermissions {
  canIssueCertificates: boolean;
  canViewDeployments: boolean;
}

interface QuickAction {
  id: string;
  title: string;
  detail: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

export function quickActionsFor(
  permissions: QuickActionPermissions,
): QuickAction[] {
  const actions: QuickAction[] = [];
  if (permissions.canIssueCertificates) {
    actions.push({
      id: "certificate",
      title: "Issue a TLS certificate",
      detail: "Secure a domain over HTTPS",
      href: "/cert-manager/add",
      icon: LockIcon,
    });
  }
  if (permissions.canViewDeployments) {
    actions.push({
      id: "deployments",
      title: "Review deployments",
      detail: "See where each certificate is installed",
      href: "/cert-manager/deployments",
      icon: RocketLaunchIcon,
    });
  }
  return actions;
}

export function QuickActions(permissions: QuickActionPermissions) {
  const actions = quickActionsFor(permissions);
  if (actions.length === 0) return null;
  return (
    <section aria-labelledby="quick-actions-title" className="space-y-3">
      <h2
        id="quick-actions-title"
        className="text-[15px] font-semibold tracking-[-0.015em] text-foreground"
      >
        Quick actions
      </h2>
      <ul className="space-y-2">
        {actions.map((action) => (
          <li key={action.id}>
            <Link
              href={action.href}
              className="group flex items-center gap-3 rounded-xl border border-border bg-card p-3 transition-[border-color,background-color] duration-150 hover:border-primary/40 hover:bg-primary-soft focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
            >
              <span className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-primary-soft text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground">
                <action.icon className="size-5" aria-hidden />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium text-foreground">
                  {action.title}
                </span>
                <span className="block truncate text-xs text-muted-foreground">
                  {action.detail}
                </span>
              </span>
              <ArrowRightIcon
                className="size-4 shrink-0 text-muted-foreground transition-transform duration-150 group-hover:translate-x-0.5 group-hover:text-primary"
                aria-hidden
              />
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
