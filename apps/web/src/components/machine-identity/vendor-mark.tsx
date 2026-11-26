// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Image from "next/image";
import React from "react";

import {
  VENDOR_MARK_HEIGHT,
  vendorMarkSize,
  type VendorLogo,
} from "@/lib/machine-identity/backend-display";
import { cn } from "@/lib/utils";

interface VendorMarkProps {
  logo: VendorLogo | undefined;
  /** Brand name. Used as the visible label, or as the mark's accessible name. */
  label: string;
  /** Optical height of the mark in px. Width follows the asset's own aspect. */
  height?: number;
  /** Render the mark only, never the text label (for dense cells and rows). */
  markOnly?: boolean;
  className?: string;
}

/**
 * A vendor's mark next to its name - the single renderer behind every
 * platform and CA identity in the module, so the same brand is never a legible
 * logo in one table and a smudge in the next.
 *
 * <p>Two rules keep it honest. The mark is laid out from its asset's real
 * aspect ratio, so wide wordmarks get the width they need
 * instead of being crushed into a square slot. And when the asset already
 * spells the brand, the mark carries the accessible name and the text label is
 * dropped rather than printing the word twice.
 */
export function VendorMark({
  logo,
  label,
  height = VENDOR_MARK_HEIGHT,
  markOnly = false,
  className,
}: VendorMarkProps) {
  if (!logo) {
    // No art for this vendor: the name alone is still a complete label, and
    // beats a broken image or an invented placeholder glyph.
    return markOnly ? null : (
      <span className={cn("truncate text-sm", className)}>{label}</span>
    );
  }

  const { width, height: markHeight } = vendorMarkSize(logo, height);
  const showLabel = !markOnly && !logo.wordmark;
  // A wordmark is the label, so it needs a real accessible name. A symbol
  // sitting beside its own text label is decorative.
  const isLabelBearing = Boolean(logo.wordmark) && !markOnly;
  const imageProps = {
    // Always decorative. The accessible name, when there is one, lives on the
    // wrapper below rather than on either image.
    alt: "",
    "aria-hidden": true,
    width,
    height: markHeight,
    style: { width, height: markHeight },
  } as const;

  return (
    // `text-sm` is the module default and is merged away by any size a caller
    // passes, so the label follows the row it sits in.
    <span
      // The name sits here, not on the `<img>`, because a mark with a dark
      // variant renders both files and lets CSS pick one. Naming each image
      // would make the announced name depend on which copy CSS happened to
      // hide - two names in a context that computes no styles, none if the
      // rule ever stopped matching. One wrapper, one name, in every theme.
      role={isLabelBearing ? "img" : undefined}
      aria-label={isLabelBearing ? label : undefined}
      className={cn(
        "inline-flex min-w-0 items-center gap-1.5 text-sm",
        className,
      )}
    >
      {/*
        Swapped by CSS rather than by reading the theme in JS: these marks
        render inside server and client components alike, and a theme read on
        the client would flash the wrong logo on first paint.
      */}
      <Image
        {...imageProps}
        alt=""
        src={logo.src}
        className={cn("shrink-0 object-contain", logo.darkSrc && "dark:hidden")}
      />
      {logo.darkSrc ? (
        <Image
          {...imageProps}
          alt=""
          src={logo.darkSrc}
          className="hidden shrink-0 object-contain dark:block"
        />
      ) : null}
      {showLabel ? <span className="truncate">{label}</span> : null}
    </span>
  );
}
