// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { type ReactNode, useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { useIntegrationsTabCounts } from "@/components/integrations/use-integrations-tabs";
import { PageHeader } from "@/components/ui/page-header";
import { tabsListClassName, tabsTriggerClassName } from "@/components/ui/tabs";
import { useActiveChildThumb } from "@/hooks/use-sliding-thumb";
import { INTEGRATIONS_TAB_HREFS } from "@/lib/integrations/routes";

/**
 * Section shell for Integrations: one page title, one category tab bar, and
 * whichever category is open.
 *
 * The counts on the tabs are load-bearing - they are what makes the landing
 * view read as a catalogue of everything CertPing connects to rather than as
 * five unrelated pages behind one heading.
 *
 * Only the five tab roots get the shell. Detail and form routes nested under
 * the section - adding a connection, opening a device source - keep the
 * full-page chrome they already had, so they don't end up with the section
 * `<h1>` stacked on top of their own.
 */
export function IntegrationsSectionShell({
  children,
}: {
  children: ReactNode;
}) {
  const pathname = usePathname();

  if (!INTEGRATIONS_TAB_HREFS.includes(pathname)) {
    return <>{children}</>;
  }

  return (
    <div className="space-y-5 p-4 md:p-6">
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Integrations"
          subtitle="Everything CertPing connects to: the apps your alerts reach, the DNS providers your certificates are validated through, the targets they are delivered to, and what your agents advertise."
        />
        <IntegrationsTabs pathname={pathname} />
      </div>

      <div>{children}</div>
    </div>
  );
}

function IntegrationsTabs({ pathname }: { pathname: string }) {
  const tabs = useIntegrationsTabCounts();
  const navRef = useRef<HTMLElement | null>(null);
  const indicator = useActiveChildThumb(navRef);

  // The bar scrolls sideways on narrow screens; keep the open category in view.
  useEffect(() => {
    const nav = navRef.current;
    const active = nav?.querySelector<HTMLElement>('[data-state="active"]');
    if (!nav || !active) return;
    const start = active.offsetLeft;
    const end = start + active.offsetWidth;
    if (start < nav.scrollLeft || end > nav.scrollLeft + nav.clientWidth) {
      nav.scrollLeft = start;
    }
  }, [pathname]);

  return (
    <nav
      ref={navRef}
      className={tabsListClassName.underline}
      aria-label="Integration categories"
    >
      <span
        aria-hidden
        className="mg-tab-indicator"
        style={indicator.thumbStyle}
      />
      {tabs.map((tab) => {
        const isActive = pathname === tab.href;
        return (
          <Link
            key={tab.id}
            href={tab.href}
            aria-current={isActive ? "page" : undefined}
            data-state={isActive ? "active" : "inactive"}
            className={tabsTriggerClassName.underline}
          >
            {tab.label}
            {tab.count === undefined ? null : (
              <span className="rounded-full bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground tabular-nums">
                {tab.count}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}
