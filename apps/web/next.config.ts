// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Next.js also reads NEXT_DEPLOYMENT_ID itself and accepts only letters, digits, hyphens and
  // underscores. The Dockerfile turns a release version (0.1.0-rc.1) into a valid id.
  deploymentId: process.env.NEXT_DEPLOYMENT_ID,

  experimental: {
    // turbopackMemoryLimit was removed in Next.js 16.4; builds use webpack (next build --webpack).
    optimizePackageImports: [
      "@phosphor-icons/react",
      "@phosphor-icons/react/dist/ssr",
    ],
  },

  async redirects() {
    return [
      {
        source: "/settings",
        destination: `/settings/account`,
        permanent: false,
      },
      {
        source: "/cert-manager/cbom-pqc-dashboard",
        destination: "/cert-manager/cryptography",
        permanent: true,
      },

      // Credentials, Connectors and third-party Integrations are one categorised
      // section at /integrations now. Bookmarks and emailed deep links still
      // point at the old paths, so keep them resolving.
      // Order matters - Next matches top to bottom, so the specific CA rule has
      // to beat the device-source catch-all, and the nested credential rules
      // have to beat their bare parent.
      {
        source: "/cert-manager/credentials/add",
        destination: "/integrations/connections/add",
        permanent: true,
      },
      {
        source: "/cert-manager/credentials/:credential/edit",
        destination: "/integrations/connections/:credential/edit",
        permanent: true,
      },
      // The old list had no category of its own, so a bare bookmark lands on
      // DNS providers. A `?credential=` deep link that turns out to name a
      // deployment target hops itself across to that tab once the list loads.
      {
        source: "/cert-manager/credentials",
        destination: "/integrations/dns",
        permanent: true,
      },
      {
        source: "/cert-manager/integrations",
        destination: "/integrations/dns",
        permanent: true,
      },
      {
        source: "/machine-identity/connectors/ca/:connectorId",
        destination: "/integrations/certificate-authorities/:connectorId",
        permanent: true,
      },
      {
        source: "/machine-identity/connectors/:sourceXref",
        destination: "/integrations/device-sources/:sourceXref",
        permanent: true,
      },
      {
        source: "/machine-identity/connectors",
        destination: "/integrations/certificate-authorities",
        permanent: true,
      },
      {
        source: "/settings/integrations",
        destination: "/integrations/apps",
        permanent: true,
      },
    ];
  },

  /* Security Headers */

  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff", // Prevents content type sniffing
          },
          // HTTPS only, for this host alone. No includeSubDomains or preload: those would pin
          // a customer's other subdomains to HTTPS. Caddy sends the same value when it fronts
          // the app and replaces this one; Helm/Ingress installs without Caddy still get it.
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000",
          },
          // Content-Security-Policy is set per request by src/proxy.ts (it carries a nonce).
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
    ];
  },

  async rewrites() {
    // Development proxy: routes browser requests for /api-proxy/* to the API
    // through the Next.js server to avoid CORS. It exists only when
    // CERTPING_API_TARGET names the API origin; there is no default target.
    // Pair it with NEXT_PUBLIC_API_URL=/api-proxy. Rewrites are fixed when
    // `next build` runs, so setting CERTPING_API_TARGET on a released image's
    // container has no effect: released images use NEXT_PUBLIC_API_URL=same-origin
    // and the kit's proxy (Caddy or the Ingress) routes /api/* to the server.
    const apiTarget = process.env.CERTPING_API_TARGET?.trim();
    if (!apiTarget) {
      return [];
    }
    return [
      {
        source: "/api-proxy/:path*",
        destination: `${apiTarget.replace(/\/+$/, "")}/:path*`,
      },
    ];
  },

  /* config options here */

  output: "standalone",
  images: {
    // WebP only. AVIF encoding through sharp/libvips roughly doubled the
    // server's resident memory (native, not JS heap) and cost ~2.7x the CPU
    // per image under load; one quality keeps one cached variant per width.
    formats: ["image/webp"],
    qualities: [75],
    remotePatterns: [
      {
        protocol: "https",
        hostname: "i.pravatar.cc",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "logo.clearbit.com",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "images.unsplash.com",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "upload.wikimedia.org",
        pathname: "/**",
      },
    ],
  },
};

export default nextConfig;
