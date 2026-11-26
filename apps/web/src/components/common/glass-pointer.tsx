// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect } from "react";

export function GlassPointer() {
  useEffect(() => {
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!finePointer.matches || reducedMotion.matches) return;

    let frame = 0;
    let target: HTMLElement | null = null;
    let x = 0;
    let y = 0;

    const paint = () => {
      frame = 0;
      if (!target) return;
      const rect = target.getBoundingClientRect();
      target.style.setProperty("--lg-x", `${x - rect.left}px`);
      target.style.setProperty("--lg-y", `${y - rect.top}px`);
    };

    const onMove = (event: PointerEvent) => {
      target =
        event.target instanceof Element
          ? event.target.closest<HTMLElement>(
              ".lg-interactive, .mg-btn, .mg-spot",
            )
          : null;
      if (!target) return;
      x = event.clientX;
      y = event.clientY;
      if (!frame) frame = window.requestAnimationFrame(paint);
    };

    document.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      document.removeEventListener("pointermove", onMove);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, []);

  return null;
}
