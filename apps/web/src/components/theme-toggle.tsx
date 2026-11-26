// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import { MoonIcon, SunIcon } from "@phosphor-icons/react";
import { useTheme } from "next-themes";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const subscribeToHydration = () => () => undefined;

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const mounted = React.useSyncExternalStore(
    subscribeToHydration,
    () => true,
    () => false,
  );
  const [optimisticTheme, setOptimisticTheme] = React.useState<
    "light" | "dark" | null
  >(null);

  if (!mounted) {
    return (
      <Button
        variant="icon"
        size="iconSm"
        className="h-8 w-8"
        aria-label="Theme loading"
        disabled
      >
        <SunIcon className="h-4 w-4" />
      </Button>
    );
  }

  const isDark = (optimisticTheme ?? resolvedTheme) === "dark";
  const toggleTheme = () => {
    const nextTheme = isDark ? "light" : "dark";
    setOptimisticTheme(nextTheme);
    setTheme(nextTheme);
  };

  return (
    <Button
      variant="icon"
      size="iconSm"
      className="h-8 w-8"
      onClick={toggleTheme}
      aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
    >
      <span className="relative block h-4 w-4" aria-hidden>
        <SunIcon
          className={cn(
            "absolute inset-0 h-4 w-4 transition-[transform,opacity] duration-500 ease-spring motion-reduce:transition-none",
            isDark
              ? "scale-100 rotate-0 opacity-100"
              : "scale-50 -rotate-90 opacity-0",
          )}
        />
        <MoonIcon
          className={cn(
            "absolute inset-0 h-4 w-4 transition-[transform,opacity] duration-500 ease-spring motion-reduce:transition-none",
            isDark
              ? "scale-50 rotate-90 opacity-0"
              : "scale-100 rotate-0 opacity-100",
          )}
        />
      </span>
    </Button>
  );
}
