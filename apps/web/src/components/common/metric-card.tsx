// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { CaretRightIcon } from "@phosphor-icons/react/dist/ssr";
import type { Icon as PhosphorIcon } from "@phosphor-icons/react";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export interface MetricCardProps {
  title: string;
  value: string | number;
  unit?: string;
  description?: string;
  action?: React.ReactNode;
  icon?: PhosphorIcon | React.ComponentType<React.ComponentProps<"svg">>;
  trend?: "up" | "down" | "neutral";
  trendValue?: string;
  tone?: "primary" | "success" | "warning" | "danger" | "info" | "neutral";
  statusColor?: string;
  onClick?: () => void;
  showChevron?: boolean;
  className?: string;
  isLoading?: boolean;
  iconClasses?: string;
  density?: "standard" | "compact";
  pressed?: boolean;
}

const MetricStripContext = React.createContext(false);

export function MetricStrip({
  children,
  className,
  "aria-label": ariaLabel = "Summary",
}: {
  children: React.ReactNode;
  className?: string;
  "aria-label"?: string;
}) {
  const items = React.Children.toArray(children).filter(Boolean);
  return (
    <MetricStripContext.Provider value>
      <div
        role="group"
        aria-label={ariaLabel}
        className={cn(
          "flex flex-wrap items-center gap-x-1 gap-y-1.5 text-sm",
          className,
        )}
      >
        {items.map((item, index) => (
          <React.Fragment
            key={
              React.isValidElement(item) && item.key != null ? item.key : index
            }
          >
            {index > 0 ? (
              <span aria-hidden className="text-muted-foreground/50">
                ·
              </span>
            ) : null}
            {item}
          </React.Fragment>
        ))}
      </div>
    </MetricStripContext.Provider>
  );
}

const toneText = {
  primary: "text-primary",
  success: "text-success-foreground",
  warning: "text-warning-foreground",
  danger: "text-danger-foreground",
  info: "text-info-foreground",
  neutral: "text-muted-foreground",
} as const;

function isZero(value: string | number): boolean {
  return value === 0 || value === "0";
}

export function MetricCard({
  title,
  value,
  unit,
  description,
  action,
  icon: Icon,
  trend,
  trendValue,
  tone = "primary",
  statusColor,
  onClick,
  showChevron = false,
  className,
  isLoading = false,
  iconClasses,
  density = "standard",
  pressed,
}: MetricCardProps) {
  const inStrip = React.useContext(MetricStripContext);
  const quiet = (tone === "warning" || tone === "danger") && isZero(value);
  const frame = "rounded-xl border border-border bg-card";

  if (inStrip) {
    const alarming = (tone === "warning" || tone === "danger") && !quiet;
    const content = (
      <>
        {alarming && Icon ? (
          <Icon
            aria-hidden
            className={cn("size-3.5 shrink-0 self-center", toneText[tone])}
          />
        ) : null}
        {isLoading ? (
          <Skeleton className="h-3.5 w-6 self-center rounded-full" />
        ) : (
          <span
            className={cn(
              "font-semibold tabular-nums",
              alarming ? toneText[tone] : "text-foreground",
            )}
          >
            {value}
            {unit ? ` ${unit}` : ""}
          </span>
        )}
        <span className={alarming ? toneText[tone] : "text-muted-foreground"}>
          {title}
        </span>
        {description ? <span className="sr-only">, {description}</span> : null}
      </>
    );
    const segmentClass =
      "inline-flex items-baseline gap-1.5 rounded-full px-2 py-0.5";
    return onClick ? (
      <button
        type="button"
        onClick={onClick}
        aria-pressed={pressed}
        className={cn(
          segmentClass,
          "transition-colors first:pl-2 hover:bg-secondary focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden",
          className,
        )}
      >
        {content}
      </button>
    ) : (
      <span className={cn(segmentClass, className)}>{content}</span>
    );
  }

  if (isLoading) {
    return (
      <div className={cn("flex flex-col gap-2 p-4", frame, className)}>
        <Skeleton className="h-3.5 w-24 rounded-full" />
        <Skeleton className="h-7 w-14" />
        <Skeleton className="h-3 w-28 rounded-full" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        "group flex h-full min-w-0 flex-col gap-1.5 p-4 transition-colors",
        frame,
        onClick &&
          "cursor-pointer hover:surface-muted focus-visible:ring-2 focus-visible:ring-brand focus-visible:outline-hidden focus-visible:ring-inset",
        className,
      )}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <div className="flex items-center gap-1.5 text-[13px] font-medium text-muted-foreground">
        {Icon ? (
          <Icon
            aria-hidden
            className={cn(
              "size-3.5 shrink-0",
              quiet ? "text-muted-foreground" : toneText[tone],
              statusColor,
              iconClasses,
            )}
          />
        ) : null}
        <p className="min-w-0 wrap-break-word">{title}</p>
        {showChevron ? (
          <CaretRightIcon
            aria-hidden
            className="ml-auto size-4 text-muted-foreground transition-transform duration-150 group-hover:translate-x-0.5"
          />
        ) : null}
      </div>
      <div className="flex items-baseline gap-1.5">
        <p
          className={cn(
            "leading-none font-semibold tracking-[-0.03em] text-foreground tabular-nums",
            density === "compact" ? "text-xl" : "text-2xl",
          )}
        >
          {value}
        </p>
        {unit ? (
          <span className="text-xs font-medium text-muted-foreground">
            {unit}
          </span>
        ) : null}
        {trend && trend !== "neutral" && trendValue ? (
          <span
            className={cn(
              "text-xs font-medium",
              trend === "up" ? "status-success-text" : "status-danger-text",
            )}
          >
            {trend === "up" ? "↑" : "↓"} {trendValue}
          </span>
        ) : null}
      </div>
      {description ? (
        <p className="text-xs leading-5 text-muted-foreground">{description}</p>
      ) : null}
      {action ? <div className="flex items-center gap-2">{action}</div> : null}
    </div>
  );
}
