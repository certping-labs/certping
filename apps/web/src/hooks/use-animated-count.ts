// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useRef, useState } from "react";

const COUNT_ANIMATION_DURATION_MS = 320;

const prefersReducedMotion = (): boolean =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Animates count changes while preserving an immediate reduced-motion path. */
export function useAnimatedCount(target: number): number {
  const [displayedCount, setDisplayedCount] = useState(0);
  const displayedCountRef = useRef(0);

  useEffect(() => {
    if (prefersReducedMotion()) {
      displayedCountRef.current = target;
      setDisplayedCount(target);
      return;
    }

    const initialCount = displayedCountRef.current;
    const countDifference = target - initialCount;
    const startedAt = performance.now();
    let animationFrameId = 0;

    const updateCount = (timestamp: number) => {
      const progress = Math.min(
        (timestamp - startedAt) / COUNT_ANIMATION_DURATION_MS,
        1,
      );
      const nextCount = Math.round(initialCount + countDifference * progress);
      displayedCountRef.current = nextCount;
      setDisplayedCount(nextCount);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(updateCount);
      }
    };

    animationFrameId = requestAnimationFrame(updateCount);
    return () => cancelAnimationFrame(animationFrameId);
  }, [target]);

  return displayedCount;
}
