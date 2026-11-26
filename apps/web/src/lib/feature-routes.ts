// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  type EffectiveFlagMap,
  FEATURE_FLAGS,
  type FeatureFlagKey,
} from "@/lib/feature-flags";
import {
  type FeatureAvailability,
  type FeatureFlagStatus,
  type FeatureMatch,
  resolveFeatureSetAvailability,
} from "@/lib/feature-availability";

/**
 * Which feature flags a route needs. `FeatureRouteGate` enforces this map
 * for the whole authenticated (main) area, so pages do not repeat the check.
 *
 * Matching: the rule with the most path segments wins, so a nested rule
 * overrides its parent (`/incidents/system-notifications` is ungated even
 * though `/incidents` is not). An asterisk segment matches exactly one dynamic
 * segment. A rule covers its own path and everything beneath it.
 *
 * `features: []` marks a deliberately ungated route under a gated parent.
 *
 * Intentionally ungated (no rule, or `[]`): `/dashboard`, `/cert-manager`
 * (the list), `/cert-manager/manage/*`, `/support` and
 * `/settings/organization-access`: core surfaces that must always be
 * reachable; the options inside them are hidden per flag instead.
 */
export interface FeatureRouteRule {
  // Path pattern; an asterisk segment matches one dynamic segment.
  pattern: string;
  features: readonly FeatureFlagKey[];
  /** Defaults to `all`. */
  match?: FeatureMatch;
  /**
   * Super admins pass regardless of flags: platform consoles they must reach
   * whatever their own organization has on. Everyone else is gated normally.
   */
  superAdminExempt?: boolean;
  /**
   * The page's endpoints resolve the organization from the session and
   * refuse a session without one (`OrgResolver.fromJwt()` in the backend).
   * A super admin signed in without an organization gets an explanation
   * instead of the page, and the route is left out of navigation.
   */
  requiresOrganization?: boolean;
}

const F = FEATURE_FLAGS;

/**
 * `requiresOrganization` follows the backend: each such page's endpoints call
 * `OrgResolver.fromJwt()` or `resolve(null)` and refuse a session without an
 * organization. Audit logs take an explicit organization filter or none, so
 * they serve platform-wide data to a super admin without one.
 */
const IN_ORG = { requiresOrganization: true } as const;

export const FEATURE_ROUTE_RULES: readonly FeatureRouteRule[] = [
  // Certificate lifecycle
  {
    pattern: "/cert-manager/add",
    features: [F.CERTIFICATE_ISSUANCE],
    ...IN_ORG,
  },
  {
    pattern: "/cert-manager/deployments",
    features: [F.CERTIFICATE_DEPLOYMENT],
    ...IN_ORG,
  },
  { pattern: "/cert-manager/discovery", features: [F.DISCOVERY], ...IN_ORG },
  // The renewal views inside the inventory follow CERTIFICATE_RENEWAL, so the
  // page that gathers them does too.
  {
    pattern: "/cert-manager/rotation",
    features: [F.CERTIFICATE_RENEWAL],
    ...IN_ORG,
  },
  {
    pattern: "/cert-manager/cryptography",
    features: [F.PQC_READINESS],
    ...IN_ORG,
  },

  // Machine identity
  {
    pattern: "/machine-identity/devices",
    features: [F.IOT_DEVICE_MANAGEMENT],
    ...IN_ORG,
  },
  {
    pattern: "/machine-identity/device-certificates",
    features: [F.IOT_DEVICE_MANAGEMENT],
    ...IN_ORG,
  },
  {
    pattern: "/machine-identity/profiles",
    features: [F.IOT_CERTIFICATE_PROFILE_MANAGEMENT],
    ...IN_ORG,
  },

  // Integrations
  {
    pattern: "/integrations/dns",
    features: [F.CREDENTIALS_MANAGEMENT],
    ...IN_ORG,
  },
  {
    pattern: "/integrations/deployment-targets",
    features: [F.CREDENTIALS_MANAGEMENT, F.CERTIFICATE_DEPLOYMENT],
    ...IN_ORG,
  },
  {
    pattern: "/integrations/connections",
    features: [F.CREDENTIALS_MANAGEMENT],
    ...IN_ORG,
  },
  { pattern: "/integrations/apps", features: [F.INTEGRATIONS] },
  // The Certificate authorities tab root also lists CA accounts for
  // credential viewers, so the page gates its own lists. Only the device CA
  // connector detail pages need device management.
  {
    pattern: "/integrations/certificate-authorities/*",
    features: [F.IOT_DEVICE_MANAGEMENT],
    ...IN_ORG,
  },
  {
    pattern: "/integrations/device-sources",
    features: [F.IOT_DEVICE_MANAGEMENT],
    ...IN_ORG,
  },

  // Operations. `/alerts` answers a session without an organization with
  // that user's own alerts only, never platform alerts, so it counts as
  // needing one. Audit logs take an organization filter (none = all).
  { pattern: "/incidents", features: [F.ALERTS], ...IN_ORG },
  { pattern: "/incidents/system-notifications", features: [] },
  // Recording never stops, so a super admin reads the platform audit log
  // whatever AUDIT_LOGS says; everyone else sees "isn't available".
  {
    pattern: "/settings/audit-logs",
    features: [F.AUDIT_LOGS],
    superAdminExempt: true,
  },
];

function toSegments(path: string): string[] {
  return path.split(/[?#]/, 1)[0].split("/").filter(Boolean);
}

const COMPILED_RULES = FEATURE_ROUTE_RULES.map((rule) => ({
  rule,
  segments: toSegments(rule.pattern),
})).sort((a, b) => b.segments.length - a.segments.length);

function matchesSegments(pathSegments: string[], patternSegments: string[]) {
  if (pathSegments.length < patternSegments.length) return false;
  return patternSegments.every(
    (segment, index) => segment === "*" || segment === pathSegments[index],
  );
}

/**
 * The most specific rule for a path (query and hash are ignored), or
 * `undefined` when no flag guards it.
 */
export function findFeatureRouteRule(
  path: string,
): FeatureRouteRule | undefined {
  const pathSegments = toSegments(path);
  return COMPILED_RULES.find(({ segments }) =>
    matchesSegments(pathSegments, segments),
  )?.rule;
}

/** A route's answer: a feature state, or "only inside an organization". */
export type RouteAvailability = FeatureAvailability | "needs-organization";

export interface RouteAvailabilityResult {
  availability: RouteAvailability;
  /** The key to name on the not-available or needs-organization page. */
  blockingKey?: string;
}

/** What route availability depends on, read from the flag store and session. */
export interface RouteFlagContext {
  status: FeatureFlagStatus;
  effectiveMap: EffectiveFlagMap;
  isSuperAdmin: boolean;
}

const UNGATED: RouteAvailabilityResult = { availability: "on" };

/**
 * The one answer to "may this route render?", shared by `FeatureRouteGate`,
 * navigation, search and post-login routing so they can never disagree.
 * Exempt super admins pass; a session without an organization passes unless
 * the route needs one; otherwise the route's flags decide.
 */
export function resolveRouteAvailability(
  path: string,
  { status, effectiveMap, isSuperAdmin }: RouteFlagContext,
): RouteAvailabilityResult {
  const rule = findFeatureRouteRule(path);
  if (!rule || rule.features.length === 0) return UNGATED;
  if (rule.superAdminExempt && isSuperAdmin) return UNGATED;
  if (status === "not-applicable" && rule.requiresOrganization) {
    return {
      availability: "needs-organization",
      blockingKey: rule.features[0],
    };
  }
  return resolveFeatureSetAvailability(
    status,
    effectiveMap,
    rule.features,
    rule.match,
  );
}

/**
 * Whether a link to `href` may be shown: false unless the route would
 * render. Navigation and search filter through this so no entry point leads
 * to a not-available or needs-organization page.
 */
export function isRouteFeatureOn(
  href: string,
  context: RouteFlagContext,
): boolean {
  return resolveRouteAvailability(href, context).availability === "on";
}
