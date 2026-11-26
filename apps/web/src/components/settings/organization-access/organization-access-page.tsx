// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useMemo } from "react";
import {
  ArrowRightIcon,
  BellIcon,
  PuzzlePieceIcon,
  ScrollIcon,
  SirenIcon,
} from "@phosphor-icons/react";

import { AccountPanel } from "@/components/settings/organization-access/account-panel";
import { MembersPanel } from "@/components/settings/organization-access/members-panel";
import { OrganizationPanel } from "@/components/settings/organization-access/organization-panel";
import { AuditRetentionCard } from "@/components/settings/audit/audit-retention-card";
import { NotificationPreferences } from "@/components/settings/notification-preferences";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/hooks/use-auth";
import { useIsRouteAvailable } from "@/hooks/use-feature-flags";
import {
  canManageTeam,
  canViewAudit,
  canViewIntegrations,
  canViewAlerts,
  canViewNotifications,
  canViewOrganizations,
} from "@/lib/authz";

export const ORGANIZATION_ACCESS_HREF = "/settings/organization-access";

export const ORGANIZATION_ACCESS_TABS = [
  "organization",
  "members",
  "account",
  "notifications",
  "audit",
] as const;

export type OrganizationAccessTab = (typeof ORGANIZATION_ACCESS_TABS)[number];

const TAB_LABELS: Record<OrganizationAccessTab, string> = {
  organization: "Organization",
  members: "Members & roles",
  account: "Your account",
  notifications: "Notifications",
  audit: "Audit",
};

export function isOrganizationAccessTab(
  value: string | null | undefined,
): value is OrganizationAccessTab {
  return ORGANIZATION_ACCESS_TABS.includes(value as OrganizationAccessTab);
}

/** The href of one tab, for links from elsewhere in the app. */
export function organizationAccessTabHref(tab: OrganizationAccessTab): string {
  return `${ORGANIZATION_ACCESS_HREF}?tab=${tab}`;
}

/**
 * One page for the organization, its members, the signed-in account,
 * notification preferences and the audit log. Each tab keeps the permission
 * check its own page had; a tab the user may not see is not offered, and a
 * bookmarked `?tab=` for it falls back to the first visible tab.
 */
export function OrganizationAccessPage() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, isSuperAdmin, isLoading } = useAuth();
  const isRouteAvailable = useIsRouteAvailable();

  const visibleTabs = useMemo<OrganizationAccessTab[]>(() => {
    const tabs: OrganizationAccessTab[] = [];
    if (canViewOrganizations(user, isSuperAdmin)) tabs.push("organization");
    if (canManageTeam(user, isSuperAdmin)) tabs.push("members");
    tabs.push("account", "notifications");
    if (
      canViewAudit(user, isSuperAdmin) &&
      isRouteAvailable("/settings/audit-logs")
    ) {
      tabs.push("audit");
    }
    return tabs;
  }, [isRouteAvailable, isSuperAdmin, user]);

  const requestedTab = searchParams.get("tab");
  const activeTab: OrganizationAccessTab =
    isOrganizationAccessTab(requestedTab) && visibleTabs.includes(requestedTab)
      ? requestedTab
      : visibleTabs[0];

  const selectTab = useCallback(
    (value: string) => {
      if (!isOrganizationAccessTab(value)) return;
      const next = new URLSearchParams(searchParams.toString());
      next.set("tab", value);
      // Query parameters belong to the tab that read them.
      if (value !== "account") next.delete("changePassword");
      router.replace(`${pathname}?${next.toString()}`, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-10 w-96" />
        <Skeleton className="h-96 w-full rounded-2xl" />
      </div>
    );
  }

  return (
    <div className="w-full space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Organization & Access"
        subtitle="Your organization, who belongs to it and what they may do, your own account, and what CertPing sends you."
      />

      <Tabs value={activeTab} onValueChange={selectTab} className="space-y-6">
        <TabsList aria-label="Organization and access sections">
          {visibleTabs.map((tab) => (
            <TabsTrigger key={tab} value={tab}>
              {TAB_LABELS[tab]}
            </TabsTrigger>
          ))}
        </TabsList>

        {visibleTabs.includes("organization") ? (
          <TabsContent value="organization">
            <OrganizationPanel />
          </TabsContent>
        ) : null}

        {visibleTabs.includes("members") ? (
          <TabsContent value="members">
            <MembersPanel />
          </TabsContent>
        ) : null}

        <TabsContent value="account">
          <AccountPanel />
        </TabsContent>

        <TabsContent value="notifications">
          <NotificationsTab
            showAlerts={canViewAlerts(user) && isRouteAvailable("/incidents")}
            showSystemNotifications={canViewNotifications(user)}
            showChannels={
              canViewIntegrations(user) &&
              isRouteAvailable("/integrations/apps")
            }
          />
        </TabsContent>

        {visibleTabs.includes("audit") ? (
          <TabsContent value="audit">
            <AuditTab />
          </TabsContent>
        ) : null}
      </Tabs>
    </div>
  );
}

function NotificationsTab({
  showAlerts,
  showSystemNotifications,
  showChannels,
}: {
  showAlerts: boolean;
  showSystemNotifications: boolean;
  showChannels: boolean;
}) {
  return (
    <div className="space-y-5">
      <PageHeader
        level="section"
        title="Notifications"
        subtitle="What CertPing sends your organization, and where alerts and alert channels are managed."
      />
      <NotificationPreferences />
      {showAlerts || showSystemNotifications || showChannels ? (
        <ul className="grid gap-3 sm:grid-cols-2">
          {showAlerts ? (
            <li>
              <LinkCard
                href="/incidents"
                icon={SirenIcon}
                title="Alerts"
                detail="Expiry, failure and deployment alerts, and who acknowledged them."
              />
            </li>
          ) : null}
          {showSystemNotifications ? (
            <li>
              <LinkCard
                href="/incidents/system-notifications"
                icon={BellIcon}
                title="System notifications"
                detail="Messages CertPing itself sent to this organization."
              />
            </li>
          ) : null}
          {showChannels ? (
            <li>
              <LinkCard
                href="/integrations/apps"
                icon={PuzzlePieceIcon}
                title="Alert channels"
                detail="Email, Slack, Teams and webhook integrations that receive alerts."
              />
            </li>
          ) : null}
        </ul>
      ) : null}
    </div>
  );
}

function AuditTab() {
  return (
    <div className="space-y-5">
      <PageHeader
        level="section"
        title="Audit"
        subtitle="Every change to certificates, members, credentials and settings is recorded with who made it and when."
        actions={
          <Button asChild>
            <Link href="/settings/audit-logs">
              <ScrollIcon aria-hidden />
              Open audit logs
            </Link>
          </Button>
        }
      />
      <p className="max-w-2xl text-sm text-muted-foreground">
        The audit log is read-only. Filter it by member, resource or action, and
        export it for an auditor. A Platform Super Admin outside any
        organization reads the platform-wide log.
      </p>
      <AuditRetentionCard />
    </div>
  );
}

function LinkCard({
  href,
  icon: Icon,
  title,
  detail,
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  detail: string;
}) {
  return (
    <Link
      href={href}
      className="group flex items-center gap-3 rounded-xl border border-border bg-card p-4 transition-colors hover:border-primary/40 hover:bg-primary-soft focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
    >
      <span className="grid size-10 shrink-0 place-items-center rounded-[10px] bg-primary-soft text-primary">
        <Icon className="size-5" aria-hidden />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium text-foreground">
          {title}
        </span>
        <span className="block text-xs text-muted-foreground">{detail}</span>
      </span>
      <ArrowRightIcon
        className="size-4 shrink-0 text-muted-foreground"
        aria-hidden
      />
    </Link>
  );
}
