// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { MagnifyingGlassIcon } from "@phosphor-icons/react";
import React from "react";

import { CommandItem } from "@/components/ui/command";
import type { AppSearchItem } from "@/lib/app-search";
import { appSearchIconByTitle } from "./app-search-icons";

interface AppSearchResultItemProps {
  item: AppSearchItem;
  onPreview: (href: string) => void;
  onSelect: (href: string) => void;
}

export function AppSearchResultItem({
  item,
  onPreview,
  onSelect,
}: AppSearchResultItemProps) {
  const Icon = appSearchIconByTitle[item.title] ?? MagnifyingGlassIcon;

  return (
    <CommandItem
      className="group h-auto cursor-pointer rounded-[10px] px-3 py-2.5 data-[selected=true]:bg-primary-soft"
      value={`${item.title} ${item.description}`}
      keywords={[...item.keywords]}
      onFocus={() => onPreview(item.href)}
      onPointerEnter={() => onPreview(item.href)}
      onSelect={() => onSelect(item.href)}
    >
      <span className="flex size-8 shrink-0 items-center justify-center rounded-[10px] bg-secondary text-muted-foreground transition-colors group-data-[selected=true]:bg-card group-data-[selected=true]:text-primary">
        <Icon className="h-4 w-4" />
      </span>
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-foreground">
          {item.title}
        </div>
        <div className="truncate text-xs text-muted-foreground">
          {item.description}
        </div>
      </div>
      <span className="ml-auto hidden max-w-40 truncate pl-4 text-[11px] text-muted-foreground/80 sm:block">
        {item.href}
      </span>
    </CommandItem>
  );
}
