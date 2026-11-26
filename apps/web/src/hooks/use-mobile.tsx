// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";

const MOBILE_BREAKPOINT = 768;
const TABLET_BREAKPOINT = 1024;

function useMaxWidthMatch(breakpoint: number): boolean {
  const [matches, setMatches] = React.useState(false);

  React.useEffect(() => {
    const mediaQuery = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const syncMatch = (event?: MediaQueryListEvent) => {
      setMatches(event ? event.matches : mediaQuery.matches);
    };

    syncMatch();
    mediaQuery.addEventListener("change", syncMatch);

    return () => {
      mediaQuery.removeEventListener("change", syncMatch);
    };
  }, [breakpoint]);

  return matches;
}

export function useIsMobile() {
  return useMaxWidthMatch(MOBILE_BREAKPOINT);
}

export function useIsTabletScreen() {
  return useMaxWidthMatch(TABLET_BREAKPOINT);
}
