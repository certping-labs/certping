// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";

import { Kbd, KbdGroup } from "@/components/ui/kbd";

const subscribeToPlatform = () => () => undefined;

function getIsApplePlatform(): boolean {
  return (
    typeof navigator !== "undefined" &&
    /Mac|iPhone|iPad|iPod/i.test(navigator.platform)
  );
}

export function AppSearchShortcut() {
  const isApplePlatform = React.useSyncExternalStore(
    subscribeToPlatform,
    getIsApplePlatform,
    () => false,
  );
  const shortcutKeys = isApplePlatform ? ["⌘", "K"] : ["Ctrl", "K"];

  return (
    // Decorative. This hint lives inside the search trigger, so labelling it
    // appended "⌘ + K shortcut" to that button's accessible name - a screen
    // reader announced "Search ⌘ + K shortcut" as the control's name. The
    // shortcut is conveyed properly by `aria-keyshortcuts` on the button
    // itself, which is the attribute assistive technology looks for.
    <KbdGroup aria-hidden="true">
      {shortcutKeys.map((key) => (
        <Kbd
          key={key}
          className="h-4 min-w-4 rounded-md border border-border/70 bg-background px-1 text-[10px]"
        >
          {key}
        </Kbd>
      ))}
    </KbdGroup>
  );
}
