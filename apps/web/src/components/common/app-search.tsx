// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { MagnifyingGlassIcon } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";

import { Button } from "@/components/ui/button";
import {
  CommandDialog,
  CommandGroup,
  CommandInput,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { useAuth } from "@/hooks/use-auth";
import {
  useFeatureFlags,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import { getAppSearchItems } from "@/lib/app-search";
import { rankAppSearchItems } from "@/lib/app-search-ranking";
import { groupAppSearchItems } from "./app-search-groups";
import { AppSearchFooter } from "./app-search-footer";
import { AppSearchResultItem } from "./app-search-result-item";
import { AppSearchShortcut } from "./app-search-shortcut";

export function AppSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [, startTransition] = useTransition();
  const prefetchedHrefs = useRef<Set<string> | null>(null);
  const router = useRouter();
  const { isEnabled, isReady } = useFeatureFlags();
  const isRouteAvailable = useIsRouteAvailable();
  const { isSuperAdmin, user } = useAuth();

  const searchItems = useMemo(
    () =>
      getAppSearchItems({
        isFeatureEnabled: isEnabled,
        isRouteAvailable,
        isFeatureFlagsReady: isReady,
        isSuperAdmin,
        user,
      }),
    [isEnabled, isReady, isRouteAvailable, isSuperAdmin, user],
  );
  const rankedItems = useMemo(
    () => rankAppSearchItems(searchItems, query),
    [query, searchItems],
  );
  const groupedItems = useMemo(
    () =>
      query.trim()
        ? [{ group: "Best matches", items: rankedItems }]
        : groupAppSearchItems(searchItems),
    [query, rankedItems, searchItems],
  );

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        event.key.toLowerCase() !== "k" ||
        (!event.metaKey && !event.ctrlKey)
      ) {
        return;
      }

      event.preventDefault();
      setQuery("");
      setOpen((currentOpen) => !currentOpen);
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  const prefetchItem = useCallback(
    (href: string) => {
      const hrefs = prefetchedHrefs.current ?? new Set<string>();
      prefetchedHrefs.current = hrefs;
      if (hrefs.has(href)) {
        return;
      }

      hrefs.add(href);
      router.prefetch(href);
    },
    [router],
  );

  const navigateToItem = useCallback(
    (href: string) => {
      setOpen(false);
      setQuery("");
      startTransition(() => {
        router.push(href);
      });
    },
    [router, startTransition],
  );

  return (
    <>
      {/*
        Two triggers for two breakpoints, both named the same way. The visible
        "Search" text plus the shortcut hint used to compose an accessible name
        of "Search ⌘ + K shortcut"; the shortcut belongs in
        `aria-keyshortcuts`, which assistive technology reads as a shortcut
        rather than as part of the control's name. Both modifiers are listed
        because the handler accepts either.
      */}
      <Button
        type="button"
        variant="icon"
        size="sm"
        className="hidden h-8 min-w-56 justify-between px-2.5 text-xs text-muted-foreground md:inline-flex"
        aria-label="Open application search"
        aria-keyshortcuts="Control+K Meta+K"
        onClick={() => setOpen(true)}
      >
        <span className="flex items-center gap-2">
          <MagnifyingGlassIcon className="h-4 w-4" />
          Search
        </span>
        <AppSearchShortcut />
      </Button>
      <Button
        type="button"
        variant="icon"
        size="iconSm"
        className="md:hidden"
        aria-label="Open application search"
        aria-keyshortcuts="Control+K Meta+K"
        onClick={() => setOpen(true)}
      >
        <MagnifyingGlassIcon className="h-4 w-4" />
      </Button>

      <CommandDialog
        open={open}
        onOpenChange={(nextOpen) => {
          setOpen(nextOpen);
          if (!nextOpen) setQuery("");
        }}
        title="Application search"
        shouldFilter={false}
        contentClassName="top-[18%] max-w-[680px] translate-y-0 gap-0 data-[state=closed]:slide-out-to-top-2 data-[state=open]:slide-in-from-top-2"
        commandClassName="rounded-2xl bg-transparent"
      >
        <CommandInput
          value={query}
          onValueChange={setQuery}
          placeholder="Search pages, settings, and actions..."
          wrapperClassName="border-divider px-4"
          className="h-14 text-[15px]"
          iconClassName="mr-3 text-muted-foreground opacity-80"
        />
        <CommandList className="max-h-[min(520px,calc(100dvh-220px))] px-2 py-2">
          <div>
            {groupedItems[0]?.items.length ? null : (
              <div className="px-6 py-12 text-center duration-150 animate-in fade-in-0 motion-reduce:animate-none">
                <div className="text-sm font-medium text-foreground">
                  No matching pages or actions
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  Try a product area like certificates, deployments, alerts, or
                  settings.
                </div>
              </div>
            )}
            {groupedItems.map(({ group, items }, groupIndex) => (
              <div key={group}>
                {groupIndex > 0 ? (
                  <CommandSeparator className="mx-2 my-1" />
                ) : null}
                <CommandGroup
                  heading={group}
                  className="**:[[cmdk-group-heading]]:px-2 **:[[cmdk-group-heading]]:pt-2 **:[[cmdk-group-heading]]:pb-1 **:[[cmdk-group-heading]]:text-xs **:[[cmdk-group-heading]]:font-medium"
                >
                  {items.map((item) => (
                    <AppSearchResultItem
                      key={`${item.group}:${item.title}:${item.href}`}
                      item={item}
                      onPreview={prefetchItem}
                      onSelect={navigateToItem}
                    />
                  ))}
                </CommandGroup>
              </div>
            ))}
          </div>
        </CommandList>
        <AppSearchFooter />
      </CommandDialog>
    </>
  );
}
