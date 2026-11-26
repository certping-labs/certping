// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { MetadataRoute } from "next";

/**
 * A self-hosted CertPing is a private console, not a public site: every
 * crawler is asked to stay out, and there is no sitemap.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", disallow: "/" }],
  };
}
