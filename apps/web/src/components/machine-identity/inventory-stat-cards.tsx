// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import {
  MetricCard,
  MetricStrip,
  type MetricCardProps,
} from "@/components/common/metric-card";
import { cn } from "@/lib/utils";

export interface InventoryStatCard {
  key: string;
  title: string;
  value: number;
  /** Qualifier under the number, e.g. "Within 30 days". */
  description?: string;
  icon?: PhosphorIcon;
  tone?: MetricCardProps["tone"];
  /** Applies this tile's filter to the inventory below. */
  onClick?: () => void;
  /** True while the tile's filter is the one applied, so it reads selected. */
  isActive?: boolean;
  /**
   * The query behind this tile failed. Renders "—" instead of a fabricated
   * `0`, so a real backend error can never be misread as "there is nothing
   * here".
   */
  hasError?: boolean;
}

interface InventoryStatCardsProps {
  cards: InventoryStatCard[];
  isLoading: boolean;
  className?: string;
}

/**
 * KPI strip above a Machine Identity inventory table.
 *
 * <p>Follows the Venafi/Keyfactor dashboard contract: every tile is the same
 * query as a filtered view of the list below it, and clicking the tile applies
 * that filter. Clicking the active tile again clears it.
 */
export function InventoryStatCards({
  cards,
  isLoading,
  className,
}: InventoryStatCardsProps) {
  return (
    <MetricStrip className={className}>
      {cards.map((card) => (
        <MetricCard
          key={card.key}
          title={card.title}
          value={card.hasError ? "—" : card.value.toLocaleString()}
          description={card.hasError ? "Unable to load" : card.description}
          icon={card.icon}
          tone={card.hasError ? "neutral" : (card.tone ?? "neutral")}
          density="compact"
          isLoading={isLoading}
          pressed={card.onClick ? Boolean(card.isActive) : undefined}
          onClick={card.hasError ? undefined : card.onClick}
          className={cn(
            !card.hasError &&
              card.isActive &&
              "bg-primary-soft text-primary hover:bg-primary-soft [&_span]:text-primary",
          )}
        />
      ))}
    </MetricStrip>
  );
}
