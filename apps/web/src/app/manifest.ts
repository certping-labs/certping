// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { MetadataRoute } from "next";

import { publicDescription, SITE_NAME } from "@/lib/seo-metadata";

export default function manifest(): MetadataRoute.Manifest {
  return {
    background_color: "#FAF8FF",
    description: publicDescription,
    display: "standalone",
    icons: [
      { sizes: "192x192", src: "/icon-192.png", type: "image/png" },
      { sizes: "512x512", src: "/icon-512.png", type: "image/png" },
      { sizes: "any", src: "/icon.svg", type: "image/svg+xml" },
    ],
    name: SITE_NAME,
    short_name: SITE_NAME,
    start_url: "/",
    theme_color: "#004AC6",
  };
}
