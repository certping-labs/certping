// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { FullScreenLoader } from "@/components/ui/loading-templates";
import { useAuth } from "@/hooks/use-auth";
import {
  useFeatureFlags,
  useFeatureFlagsSync,
} from "@/hooks/use-feature-flags";
import {
  REQUIRED_PASSWORD_CHANGE_ROUTE,
  shouldRequirePasswordChange,
} from "@/lib/post-auth";
import {
  canCreateCertificates,
  canViewAudit,
  canViewCertificates,
  canViewCredentials,
  canViewDeployments,
  canViewIntegrations,
  canViewOrganizations,
  canViewIncidents,
  hasOrganizationContext,
} from "@/lib/authz";
import { getDefaultAuthorizedRoute } from "@/lib/app-routes";
import { SsoUser } from "@/types/auth";
import { usePathname, useRouter } from "next/navigation";
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import { getPendingSignedOutReason } from "@/lib/session-end";
import { getLoginPath } from "@/lib/signed-out-reason";
import { usePageRestore } from "@/hooks/use-page-restore";

interface AuthProviderProps {
  children: React.ReactNode;
}

const PRIVATE_ROUTES = [
  "/dashboard",
  "/incidents",
  "/settings",
  "/integrations",
  "/cert-manager",
  "/machine-identity",
  "/support",
];

interface RouteAccessRule {
  pathPrefix: string;
  hasAccess: (user: SsoUser | null, isSuperAdmin: boolean) => boolean;
}

/**
 * Who may open each private route. The most specific (longest) prefix wins,
 * so rules are ordered specific-first. Pages whose permission is checked by
 * the page itself (Organization & Access, the Rotation page) need no rule
 * here beyond being signed in.
 */
const ROUTE_ACCESS_RULES: RouteAccessRule[] = [
  {
    pathPrefix: "/dashboard",
    hasAccess: (user) => hasOrganizationContext(user),
  },
  {
    pathPrefix: "/incidents",
    hasAccess: (user) => canViewIncidents(user),
  },
  {
    pathPrefix: "/cert-manager/add",
    hasAccess: (user) => canCreateCertificates(user),
  },
  {
    pathPrefix: "/cert-manager/manage",
    hasAccess: (user) => canViewCertificates(user),
  },
  {
    pathPrefix: "/cert-manager/deployments",
    hasAccess: (user) => canViewDeployments(user),
  },
  {
    pathPrefix: "/cert-manager",
    hasAccess: (user) => canViewCertificates(user),
  },
  // Machine Identity ships only in enterprise deployments. Its feature flags are
  // checked by `FeatureRouteGate` (see feature-routes), so the deployment mode
  // plus an organization context is the whole rule here.
  {
    pathPrefix: "/machine-identity",
    hasAccess: (user) => isEnterpriseAppMode() && hasOrganizationContext(user),
  },
  {
    pathPrefix: "/settings/audit-logs",
    hasAccess: (user, isSuperAdmin) => canViewAudit(user, isSuperAdmin),
  },
  {
    pathPrefix: "/settings/organizations",
    hasAccess: (user, isSuperAdmin) => canViewOrganizations(user, isSuperAdmin),
  },
  // Integrations is one section split into category tabs, each keeping the
  // exact gate it carried as a standalone page. Category rules first so they
  // win the longest-prefix match; the catch-all below only has to answer "may
  // this user reach the section at all", which the index page then resolves
  // into whichever category they can actually see.
  {
    pathPrefix: "/integrations/apps",
    hasAccess: (user) => canViewIntegrations(user),
  },
  {
    pathPrefix: "/integrations/dns",
    hasAccess: (user) => canViewCredentials(user),
  },
  {
    pathPrefix: "/integrations/deployment-targets",
    hasAccess: (user) => canViewCredentials(user),
  },
  {
    pathPrefix: "/integrations/connections",
    hasAccess: (user) => canViewCredentials(user),
  },
  // CA accounts for credential viewers, device CA connectors for enterprise.
  // Connector detail pages are also behind IOT_DEVICE_MANAGEMENT (see
  // feature-routes), which credential-only users do not reach.
  {
    pathPrefix: "/integrations/certificate-authorities",
    hasAccess: (user) =>
      canViewCredentials(user) ||
      (isEnterpriseAppMode() && hasOrganizationContext(user)),
  },
  {
    pathPrefix: "/integrations/device-sources",
    hasAccess: (user) => isEnterpriseAppMode() && hasOrganizationContext(user),
  },
  {
    pathPrefix: "/integrations",
    hasAccess: (user) =>
      canViewIntegrations(user) ||
      canViewCredentials(user) ||
      (isEnterpriseAppMode() && hasOrganizationContext(user)),
  },
  // Support is open to every signed-in user: the page explains how to get help.
];

const pathMatches = (pathname: string, prefix: string): boolean =>
  pathname === prefix || pathname.startsWith(`${prefix}/`);

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const router = useRouter();
  const {
    accessToken,
    expiresAt,
    isAuthenticated,
    isLoading,
    user,
    isSuperAdmin,
  } = useAuth();
  const [isHistoryRestoring, setIsHistoryRestoring] = useState(false);
  const historyRestoreTimeoutRef = useRef<number | null>(null);
  useFeatureFlagsSync();
  const { isEnabled: flagIsEnabled, isReady: areFlagsSettled } =
    useFeatureFlags();
  const pathName = usePathname();
  const hasUsableLocalSession = Boolean(
    accessToken && user && expiresAt && Date.now() < expiresAt,
  );
  const isRequiredPasswordChangeRoute =
    pathName === "/settings/organization-access";
  const isSignInEntryRoute =
    pathName === "/" || pathName === "/login" || pathName === "/setup";

  const isPrivateRoute = useMemo(
    () => PRIVATE_ROUTES.some((route) => pathName.startsWith(route)),
    [pathName],
  );
  const deniedRoute = useMemo(() => {
    // Most-specific (longest-prefix) rule wins. Rules are ordered specific-first,
    // so the FIRST matching rule is authoritative and we evaluate ITS access.
    // (Selecting the first *denying* match instead would let a broad deny-rule
    // override a more specific allow-rule on nested paths.)
    const matched = ROUTE_ACCESS_RULES.find((rule) =>
      pathMatches(pathName, rule.pathPrefix),
    );
    return matched && !matched.hasAccess(user, Boolean(isSuperAdmin))
      ? matched
      : undefined;
  }, [isSuperAdmin, pathName, user]);

  const defaultRoute = useMemo(
    () =>
      shouldRequirePasswordChange(user, Boolean(isSuperAdmin))
        ? REQUIRED_PASSWORD_CHANGE_ROUTE
        : getDefaultAuthorizedRoute(user, Boolean(isSuperAdmin), flagIsEnabled),
    [flagIsEnabled, isSuperAdmin, user],
  );

  usePageRestore(
    useCallback(() => {
      if (historyRestoreTimeoutRef.current) {
        window.clearTimeout(historyRestoreTimeoutRef.current);
      }

      setIsHistoryRestoring(true);
      historyRestoreTimeoutRef.current = window.setTimeout(() => {
        setIsHistoryRestoring(false);
        historyRestoreTimeoutRef.current = null;
      }, 1500);
    }, []),
  );

  useEffect(
    () => () => {
      if (historyRestoreTimeoutRef.current) {
        window.clearTimeout(historyRestoreTimeoutRef.current);
      }
    },
    [],
  );

  useEffect(() => {
    if (isLoading) return;

    if (!isAuthenticated && isPrivateRoute) {
      router.replace(getLoginPath(getPendingSignedOutReason()));
      return;
    }

    if (
      isAuthenticated &&
      shouldRequirePasswordChange(user, Boolean(isSuperAdmin)) &&
      !isRequiredPasswordChangeRoute
    ) {
      router.replace(REQUIRED_PASSWORD_CHANGE_ROUTE);
      return;
    }

    // The default route depends on which features are on; deciding it
    // before the flags answer would land a user on the wrong page.
    if (isAuthenticated && !areFlagsSettled) return;

    if (isAuthenticated && isSignInEntryRoute) {
      router.replace(defaultRoute);
      return;
    }

    if (isAuthenticated && deniedRoute && pathName !== defaultRoute) {
      router.replace(defaultRoute);
      return;
    }
  }, [
    areFlagsSettled,
    defaultRoute,
    deniedRoute,
    isAuthenticated,
    isLoading,
    isPrivateRoute,
    isRequiredPasswordChangeRoute,
    isSignInEntryRoute,
    isSuperAdmin,
    pathName,
    router,
    user,
  ]);

  const shouldShowHistoryRestoredPage =
    isHistoryRestoring && (isAuthenticated || hasUsableLocalSession);

  if (isLoading && !hasUsableLocalSession && !shouldShowHistoryRestoredPage) {
    return <FullScreenLoader>{children}</FullScreenLoader>;
  }

  if (!isAuthenticated && isPrivateRoute && !shouldShowHistoryRestoredPage) {
    return <FullScreenLoader>{children}</FullScreenLoader>;
  }

  if (isAuthenticated && deniedRoute && !shouldShowHistoryRestoredPage) {
    return <FullScreenLoader>{children}</FullScreenLoader>;
  }

  return <>{children}</>;
};

export default AuthProvider;
