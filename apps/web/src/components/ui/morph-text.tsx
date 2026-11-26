// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";
import type { MorphController, TextMorphOptions } from "torph";

/* The default spatial spring (damping ratio 0.8, stiffness 380). */
const MORPH_OPTIONS: Omit<TextMorphOptions, "element"> = {
  ease: { stiffness: 380, damping: 31 },
};

// Most labels never change, so torph stays out of the page bundle and loads once, after mount.
let torphModule: Promise<typeof import("torph")> | null = null;
const loadTorph = () => (torphModule ??= import("torph"));

interface MorphTextProps {
  children: string;
  className?: string;
}

/**
 * Text that morphs into its next value. Nothing is attached or measured until
 * the value first changes, so a label that never changes costs a plain span.
 */
export function MorphText({ children, className }: MorphTextProps) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const controllerRef = React.useRef<MorphController | null>(null);
  const loadingRef = React.useRef(false);
  const mountedRef = React.useRef(false);
  const shownRef = React.useRef(children);
  // React renders the first value once; torph owns the span's content after that.
  const [initial] = React.useState(children);

  React.useEffect(() => {
    const element = ref.current;
    mountedRef.current = true;
    void loadTorph().catch(() => undefined);
    return () => {
      mountedRef.current = false;
      const controller = controllerRef.current;
      if (!controller) return;
      controller.destroy();
      controllerRef.current = null;
      // destroy() drops torph's screen-reader copy; put the plain label back.
      if (element) element.textContent = shownRef.current;
    };
  }, []);

  React.useEffect(() => {
    const element = ref.current;
    if (!element || children === shownRef.current) return;
    const previous = shownRef.current;
    shownRef.current = children;
    if (controllerRef.current) {
      controllerRef.current.update(children);
      return;
    }
    if (typeof element.animate !== "function") {
      element.textContent = children;
      return;
    }
    if (loadingRef.current) return;
    loadingRef.current = true;
    loadTorph()
      .then(({ MorphController }) => {
        if (!mountedRef.current) return;
        const controller = new MorphController();
        controller.attach(element, MORPH_OPTIONS);
        controller.update(previous);
        controller.update(shownRef.current);
        controllerRef.current = controller;
      })
      .catch(() => {
        if (mountedRef.current) element.textContent = shownRef.current;
      })
      .finally(() => {
        loadingRef.current = false;
      });
  }, [children]);

  return (
    <span ref={ref} className={className}>
      {initial}
    </span>
  );
}
