// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { isRouteFeatureOn } from "@/lib/feature-routes";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

import { getAppSearchItems } from "@/lib/app-search";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { PERMISSIONS } from "@/lib/authz";
import type { SsoUser } from "@/types/auth";

const APP_ROOT = "src/app/(main)";

/**
 * Turns a `page.tsx` path into the URL it serves, or null if it has no single
 * address to search for.
 */
function toRoute(pageFile: string): string | null {
  const segments = pageFile
    .slice(APP_ROOT.length)
    .replace(/\/page\.tsx$/, "")
    .split("/")
    .filter(Boolean);

  // Dynamic segments need an id nobody can type into a palette.
  if (segments.some((segment) => segment.startsWith("["))) return null;

  // Route groups like "(main)" organize files without appearing in the URL.
  const path = segments
    .filter((segment) => !segment.startsWith("("))
    .map((segment) => `/${segment}`)
    .join("");

  return path || "/";
}

/**
 * Every static route the repository ships, as a URL path.
 *
 * <p>Enumerated rather than hand-listed, because a hand-kept list is exactly
 * what drifts: the Machine Identity module shipped five routes and none of
 * them were reachable from the command palette until someone noticed by hand.
 *
 * <p>Read from git rather than from the working directory. Walking the
 * filesystem made this audit depend on whose machine it ran on - an
 * uncommitted local page counted as a route here and did not exist in CI, so
 * an exclusion for it looked honest locally and stale on the runner. What the
 * repository contains is the thing worth asserting about. A tracked page
 * deleted in the working tree (a removal not yet committed) no longer counts.
 */
function findStaticRoutes(): string[] {
  const output = execFileSync(
    "git",
    ["ls-files", "--", `${APP_ROOT}/**/page.tsx`, `${APP_ROOT}/page.tsx`],
    { encoding: "utf8" },
  );

  return output
    .split("\n")
    .filter((line) => line.endsWith("page.tsx"))
    .filter((line) => existsSync(line))
    .map(toRoute)
    .filter((route): route is string => route !== null);
}

/**
 * Routes that deliberately have no command-palette entry, each with the reason
 * it would be wrong to offer one. Anything not listed here must be searchable.
 */
const INTENTIONALLY_UNSEARCHABLE: Record<string, string> = {
  "/settings":
    "Redirects to Organization & Access; searching it twice is noise.",
  "/integrations":
    "Redirects to the first Integrations category this user can see; each category has its own entry.",
  // The pre-consolidation settings pages keep bookmarks working by redirecting
  // to their tab of Organization & Access, which has the entry.
  "/settings/account": "Redirects to the Your account tab.",
  "/settings/teams": "Redirects to the Members & roles tab.",
  "/settings/organizations": "Redirects to the Organization tab.",
  "/settings/notifications": "Redirects to the Notifications tab.",
};

/** A user holding every permission, so gating cannot hide a missing entry. */
function omniscientUser(): SsoUser {
  return {
    id: "user-1",
    email: "user@example.com",
    organizationId: "organization-1",
    organizationName: "Acme",
    roles: ["ORGANIZATION_ADMIN"],
    permissions: Object.values(PERMISSIONS),
    authMethod: "LOCAL",
  } as SsoUser;
}

function searchItemsForMode(appMode: string, isSuperAdmin = false) {
  const previous = process.env.NEXT_PUBLIC_APP_MODE;
  process.env.NEXT_PUBLIC_APP_MODE = appMode;
  try {
    return getAppSearchItems({
      isFeatureEnabled: () => true,
      isRouteAvailable: (href) =>
        isRouteFeatureOn(href, {
          status: "ready",
          effectiveMap: Object.fromEntries(
            Object.values(FEATURE_FLAGS).map((featureKey) => [
              featureKey,
              true,
            ]),
          ),
          isSuperAdmin,
        }),
      isFeatureFlagsReady: true,
      isSuperAdmin,
      user: omniscientUser(),
    });
  } finally {
    process.env.NEXT_PUBLIC_APP_MODE = previous;
  }
}

/**
 * Every destination some legitimate persona can reach.
 *
 * <p>Two dimensions, because both hide things. The app mode decides the
 * auth surfaces - Machine Identity is enterprise-only. And super-admin is not
 * a superset of org admin. A route is covered if any of those four
 * combinations offers it.
 */
function allSearchableHrefs(): Set<string> {
  const items = [
    ...searchItemsForMode("enterprise"),
    ...searchItemsForMode("enterprise", true),
    ...searchItemsForMode(""),
    ...searchItemsForMode("", true),
  ];
  // Query strings and anchors open the same page; the route is what matters.
  return new Set(items.map((item) => item.href.split(/[?#]/)[0]));
}

describe("command palette route coverage", () => {
  it("offers a destination for every static application route", () => {
    const searchable = allSearchableHrefs();
    const missing = findStaticRoutes()
      .filter((route) => !searchable.has(route))
      .filter((route) => !(route in INTENTIONALLY_UNSEARCHABLE));

    expect(missing).toEqual([]);
  });

  it("does not offer a destination that no longer exists", () => {
    // A renamed route leaves a search result that 404s.
    const routes = new Set(findStaticRoutes());
    const dangling = [...allSearchableHrefs()].filter(
      (href) => !routes.has(href),
    );

    expect(dangling).toEqual([]);
  });

  it("keeps the exclusion list honest", () => {
    // An entry that no longer names a real route is a stale excuse.
    const routes = new Set(findStaticRoutes());
    const stale = Object.keys(INTENTIONALLY_UNSEARCHABLE).filter(
      (route) => !routes.has(route),
    );

    expect(stale).toEqual([]);
  });

  it("gives every entry a title, description, group and href", () => {
    const items = searchItemsForMode("enterprise");

    for (const item of items) {
      expect(item.title.trim()).not.toBe("");
      expect(item.description.trim()).not.toBe("");
      expect(item.href.startsWith("/")).toBe(true);
      expect(item.keywords.length).toBeGreaterThan(0);
    }
  });

  it("does not list the same title twice", () => {
    const titles = searchItemsForMode("enterprise").map((item) => item.title);

    expect(titles).toHaveLength(new Set(titles).size);
  });
});
