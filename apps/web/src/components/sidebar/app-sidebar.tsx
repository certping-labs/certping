// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import {
  ArrowsClockwiseIcon,
  AtomIcon,
  BinocularsIcon,
  BuildingsIcon,
  CertificateIcon,
  CloudArrowUpIcon,
  DevicesIcon,
  IdentificationBadgeIcon,
  LifebuoyIcon,
  PlugsConnectedIcon,
  RobotIcon,
  ScrollIcon,
  SlidersHorizontalIcon,
  SquaresFourIcon,
} from "@phosphor-icons/react";
import { NavMain } from "@/components/sidebar/nav-main";
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { ToolTipCard } from "@/components/common/tooltip-card";
import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import microDarkLogo from "@/assets/brand/certping-symbol-micro-color-dark.svg";
import microLightLogo from "@/assets/brand/certping-symbol-micro-color-light.svg";
import { CertPingBrand } from "@/components/common/certping-brand";
import { NavSecondary } from "./nav-secondary";
import { useAuth } from "@/hooks/use-auth";
import {
  useFeatureFlags,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  canManageAgents,
  canViewAudit,
  canViewCredentials,
  canViewIntegrations,
  canViewCertificates,
  canViewDeployments,
  hasOrganizationContext,
} from "@/lib/authz";
import { getDefaultAuthorizedRoute } from "@/lib/app-routes";
import { resolveActiveNavUrl } from "@/lib/sidebar-navigation";

type SidebarIcon = React.ComponentType<React.ComponentProps<"svg">>;

interface SidebarSubItem {
  title: string;
  url?: string;
  icon?: SidebarIcon;
}

interface SidebarItem {
  title: string;
  url?: string;
  icon: SidebarIcon;
  exact?: boolean;
  matchPrefix?: string;
  highlight?: boolean;
  subMenu?: SidebarSubItem[];
}

/**
 * Drops entries whose route would not render (feature off, or it needs an
 * organization this session lacks), by the rule `FeatureRouteGate` enforces,
 * so the sidebar never leads to a not-available page.
 */
function keepAvailableRoutes(
  items: SidebarItem[],
  isRouteAvailable: (href: string) => boolean,
): SidebarItem[] {
  return items.flatMap((item) => {
    if (item.url && !isRouteAvailable(item.url)) return [];
    if (!item.subMenu) return [item];
    const subMenu = item.subMenu.filter(
      (sub) => !sub.url || isRouteAvailable(sub.url),
    );
    return subMenu.length > 0 || item.url ? [{ ...item, subMenu }] : [];
  });
}

/** Lives on the sidebar it controls; phones open the sidebar from the navbar instead. */
function SidebarCollapseControl() {
  const { state } = useSidebar();
  const label = state === "collapsed" ? "Expand sidebar" : "Collapse sidebar";
  return (
    <ToolTipCard value={`${label} (Ctrl+B / ⌘B)`}>
      <SidebarTrigger
        aria-label={label}
        className="hidden shrink-0 text-muted-foreground hover:text-foreground md:inline-flex"
      />
    </ToolTipCard>
  );
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { user, isSuperAdmin } = useAuth();
  const { isEnabled } = useFeatureFlags();
  const isRouteAvailable = useIsRouteAvailable();
  const pathname = usePathname();

  const canViewCertManager = canViewCertificates(user);
  const canViewDeploymentManager = canViewDeployments(user);
  const canAccessAudit = canViewAudit(user, isSuperAdmin);
  const hasOrganization = hasOrganizationContext(user);
  const appHomeHref = getDefaultAuthorizedRoute(user, isSuperAdmin);

  // The product surface: discovery, inventory, PQC readiness, rotation,
  // deployments, machine identity, audit, access and support. Alerts,
  // notification channels and the other integrations are reached from the
  // pages that use them (Organization & Access, Rotation, Deployments).
  const { topItems, certItems, machineIdentityItems } = React.useMemo(() => {
    const topItems: SidebarItem[] = [];
    const certItems: SidebarItem[] = [];
    const machineIdentityItems: SidebarItem[] = [];

    if (hasOrganization) {
      topItems.push({
        title: "Overview",
        url: "/dashboard",
        icon: SquaresFourIcon,
      });
    }

    if (canViewCertManager && isEnabled(FEATURE_FLAGS.DISCOVERY)) {
      certItems.push({
        title: "Certificate Discovery",
        url: "/cert-manager/discovery",
        icon: BinocularsIcon,
      });
    }
    if (canViewCertManager) {
      certItems.push({
        title: "Certificates",
        url: "/cert-manager",
        icon: CertificateIcon,
      });
    }
    if (canViewCertManager && isEnabled(FEATURE_FLAGS.PQC_READINESS)) {
      certItems.push({
        title: "PQC Readiness",
        url: "/cert-manager/cryptography",
        icon: AtomIcon,
      });
    }
    if (canViewCertManager && isEnabled(FEATURE_FLAGS.CERTIFICATE_RENEWAL)) {
      certItems.push({
        title: "Rotation",
        url: "/cert-manager/rotation",
        icon: ArrowsClockwiseIcon,
      });
    }
    if (
      canViewDeploymentManager &&
      isEnabled(FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT)
    ) {
      certItems.push({
        title: "Deployments",
        url: "/cert-manager/deployments",
        icon: CloudArrowUpIcon,
      });
    }

    if (hasOrganization) {
      if (isEnabled(FEATURE_FLAGS.IOT_DEVICE_MANAGEMENT)) {
        machineIdentityItems.push(
          {
            title: "Devices",
            url: "/machine-identity/devices",
            icon: DevicesIcon,
          },
          {
            title: "Device certificates",
            url: "/machine-identity/device-certificates",
            icon: IdentificationBadgeIcon,
          },
        );
      }
      if (isEnabled(FEATURE_FLAGS.IOT_CERTIFICATE_PROFILE_MANAGEMENT)) {
        machineIdentityItems.push({
          title: "Profiles",
          url: "/machine-identity/profiles",
          icon: SlidersHorizontalIcon,
        });
      }
    }

    return {
      topItems: keepAvailableRoutes(topItems, isRouteAvailable),
      certItems: keepAvailableRoutes(certItems, isRouteAvailable),
      machineIdentityItems: keepAvailableRoutes(
        machineIdentityItems,
        isRouteAvailable,
      ),
    };
  }, [
    hasOrganization,
    isRouteAvailable,
    canViewCertManager,
    canViewDeploymentManager,
    isEnabled,
  ]);

  const operationsItems = React.useMemo(() => {
    const items: SidebarItem[] = [];
    if (canAccessAudit && isEnabled(FEATURE_FLAGS.AUDIT_LOGS)) {
      items.push({
        title: "Audit Logs",
        url: "/settings/audit-logs",
        icon: ScrollIcon,
      });
    }
    return keepAvailableRoutes(items, isRouteAvailable);
  }, [canAccessAudit, isEnabled, isRouteAvailable]);

  const administrationItems = React.useMemo(() => {
    const items: SidebarItem[] = [];
    // Cloud accounts, certificate authorities, DNS providers and deployment targets: the
    // connections discovery, rotation and deployment run with.
    if (
      hasOrganization &&
      (canViewCredentials(user) || canViewIntegrations(user))
    ) {
      items.push({
        title: "Integrations",
        url: "/integrations",
        icon: PlugsConnectedIcon,
      });
    }
    // Agents: the same permission that manages agent tokens on the organization page.
    if (canManageAgents(user, isSuperAdmin)) {
      items.push({
        title: "Agents",
        url: "/agents",
        icon: RobotIcon,
      });
    }
    items.push({
      title: "Organization & Access",
      url: "/settings/organization-access",
      icon: BuildingsIcon,
    });
    // Support is a static page every signed-in user may read.
    items.push({
      title: "Support",
      url: "/support",
      icon: LifebuoyIcon,
    });
    return keepAvailableRoutes(items, isRouteAvailable);
  }, [hasOrganization, isRouteAvailable, isSuperAdmin, user]);

  const activeUrl = React.useMemo(
    () =>
      resolveActiveNavUrl(pathname, [
        ...topItems,
        ...certItems,
        ...machineIdentityItems,
        ...operationsItems,
        ...administrationItems,
      ]),
    [
      pathname,
      topItems,
      certItems,
      machineIdentityItems,
      operationsItems,
      administrationItems,
    ],
  );

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader className="mb-2">
        <SidebarMenu>
          <SidebarMenuItem className="flex items-center gap-1 group-data-[collapsible=icon]:flex-col group-data-[collapsible=icon]:gap-2">
            <SidebarMenuButton
              asChild
              className="h-14 flex-1 border-none px-1.5 py-2 group-data-[collapsible=icon]:size-10! group-data-[collapsible=icon]:p-2! hover:bg-transparent"
            >
              <Link aria-label="CertPing workspace" href={appHomeHref} prefetch>
                <CertPingBrand
                  className="group-data-[collapsible=icon]:hidden"
                  priority
                  surface="auto"
                  symbolClassName="size-7"
                  wordmarkClassName="text-lg"
                />
                <Image
                  alt=""
                  aria-hidden="true"
                  className="hidden size-6 group-data-[collapsible=icon]:block dark:group-data-[collapsible=icon]:hidden"
                  src={microLightLogo}
                />
                <Image
                  alt=""
                  aria-hidden="true"
                  className="hidden size-6 dark:group-data-[collapsible=icon]:block"
                  src={microDarkLogo}
                />
              </Link>
            </SidebarMenuButton>
            <SidebarCollapseControl />
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {topItems.length > 0 ? (
          <NavSecondary
            items={topItems}
            groupLabel=""
            activeUrl={activeUrl}
            emphasis="recede"
          />
        ) : null}

        {certItems.length > 0 ? (
          <NavSecondary
            items={certItems}
            groupLabel="Certificate lifecycle"
            activeUrl={activeUrl}
            emphasis="recede"
          />
        ) : null}

        {machineIdentityItems.length > 0 ? (
          <NavSecondary
            items={machineIdentityItems}
            groupLabel="Machine identity"
            activeUrl={activeUrl}
            emphasis="recede"
          />
        ) : null}

        {operationsItems.length > 0 ? (
          <NavMain
            items={operationsItems}
            groupLabel="Operations"
            activeUrl={activeUrl}
            emphasis="recede"
          />
        ) : null}
        {administrationItems.length > 0 ? (
          <NavMain
            items={administrationItems}
            groupLabel="Administration"
            activeUrl={activeUrl}
            emphasis="recede"
          />
        ) : null}
      </SidebarContent>
      <SidebarRail />
    </Sidebar>
  );
}
