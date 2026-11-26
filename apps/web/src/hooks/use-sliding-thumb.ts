// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import {
  type CSSProperties,
  type RefObject,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

const useIsomorphicLayoutEffect =
  typeof window === "undefined" ? useEffect : useLayoutEffect;

const TRAVEL_MS = 420;
const TRAIL_DELAY_MS = 70;

interface ThumbBox {
  left: number;
  right: number;
  direction: 1 | -1 | 0;
}

function nextBox(
  previous: ThumbBox | null,
  item: HTMLElement,
  track: HTMLElement,
  animate: boolean,
): ThumbBox {
  const left = item.offsetLeft;
  const right = track.clientWidth - left - item.offsetWidth;
  if (previous?.left === left && previous.right === right) return previous;
  const direction =
    !animate || !previous || previous.left === left
      ? 0
      : left > previous.left
        ? 1
        : -1;
  return { direction, left, right };
}

/*
 * Elastic glass thumb: the leading edge springs toward the new item first and
 * the trailing edge follows (Material elastic indicator), while the thumb lifts
 * into glass for the length of the trip (Liquid Glass lens).
 */
function useThumbPresentation(box: ThumbBox | null) {
  const [moving, setMoving] = useState(false);

  useEffect(() => {
    if (!box || box.direction === 0) return;
    setMoving(true);
    const timer = window.setTimeout(() => setMoving(false), TRAVEL_MS);
    return () => window.clearTimeout(timer);
  }, [box]);

  const thumbStyle: CSSProperties = box
    ? {
        left: box.left,
        right: box.right,
        transitionDelay:
          box.direction === 1
            ? `${TRAIL_DELAY_MS}ms, 0ms, 0ms, 0ms, 0ms`
            : box.direction === -1
              ? `0ms, ${TRAIL_DELAY_MS}ms, 0ms, 0ms, 0ms`
              : "0ms",
      }
    : { opacity: 0 };

  return { moving, thumbStyle };
}

export function useSlidingThumb(activeIndex: number) {
  const items = useRef<(HTMLElement | null)[]>([]);
  const [box, setBox] = useState<ThumbBox | null>(null);

  useIsomorphicLayoutEffect(() => {
    const measure = (animate: boolean) => {
      const item = items.current[activeIndex];
      const track = item?.offsetParent as HTMLElement | null;
      if (!item || !track) return;
      setBox((previous) => nextBox(previous, item, track, animate));
    };
    measure(true);
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => measure(false));
    for (const item of items.current) if (item) observer.observe(item);
    return () => observer.disconnect();
  }, [activeIndex]);

  const itemRef = useCallback(
    (index: number) => (node: HTMLElement | null) => {
      items.current[index] = node;
    },
    [],
  );

  return { itemRef, ...useThumbPresentation(box) };
}

export function useActiveChildThumb<T extends HTMLElement>(
  containerRef: RefObject<T | null>,
  selector = '[data-state="active"]',
) {
  const [box, setBox] = useState<ThumbBox | null>(null);

  useIsomorphicLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const measure = (animate: boolean) => {
      const active = container.querySelector<HTMLElement>(selector);
      if (!active) {
        setBox(null);
        return;
      }
      setBox((previous) => nextBox(previous, active, container, animate));
    };
    measure(false);
    const resizes =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(() => measure(false));
    // Items resize on their own (a count arriving) and come and go (flags).
    const observeSizes = () => {
      if (!resizes) return;
      resizes.disconnect();
      resizes.observe(container);
      for (const item of Array.from(container.children)) {
        // The thumb resizes every frame of its own slide.
        if (item.getAttribute("aria-hidden") !== "true") resizes.observe(item);
      }
    };
    observeSizes();
    const mutations = new MutationObserver((records) => {
      if (records.some((record) => record.type === "childList")) {
        observeSizes();
      }
      // Only a selection change slides the thumb; content loading just settles it.
      measure(records.some((record) => record.type === "attributes"));
    });
    mutations.observe(container, {
      attributeFilter: ["data-state", "aria-pressed"],
      attributes: true,
      childList: true,
      subtree: true,
    });
    return () => {
      mutations.disconnect();
      resizes?.disconnect();
    };
  }, [containerRef, selector]);

  return useThumbPresentation(box);
}
