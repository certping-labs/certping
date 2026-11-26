// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";

export const SITE_NAME = "CertPing";
export const SITE_TITLE_TEMPLATE = `%s | ${SITE_NAME}`;

const primaryDescription =
  "CertPing helps PKI, security, and platform teams discover, issue, deploy, renew, revoke, and govern certificates across cloud, Kubernetes, edge, and private infrastructure.";

export const publicTitle = "CertPing | Certificate Lifecycle Management";

export const publicDescription =
  "Open source certificate lifecycle management. Discover, issue, deploy, renew and revoke certificates across cloud, Kubernetes and your own servers.";

export const privateRobots: Metadata["robots"] = {
  index: false,
  follow: false,
  nocache: true,
  googleBot: {
    index: false,
    follow: false,
    noimageindex: true,
  },
};

export const pkiSeoKeywords = [
  "enterprise PKI",
  "PKI platform",
  "certificate lifecycle management",
  "CLM platform",
  "TLS certificate management",
  "SSL certificate management",
  "certificate discovery",
  "certificate inventory",
  "certificate renewal automation",
  "certificate auto-rotation",
  "certificate deployment automation",
  "ACME automation",
  "private CA management",
  "digital trust platform",
  "cryptographic posture management",
  "crypto-agility",
  "post-quantum cryptography readiness",
  "PQC readiness",
  "Kubernetes certificate management",
  "cloud certificate management",
] as const;

export const coreSeoMetadata: Metadata = {
  title: {
    default: publicTitle,
    template: SITE_TITLE_TEMPLATE,
  },
  description: primaryDescription,
  keywords: [...pkiSeoKeywords],
  authors: [{ name: "CertPing contributors" }],
  creator: SITE_NAME,
  applicationName: SITE_NAME,
  icons: {
    icon: [
      {
        url: "/icon.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: light)",
      },
      {
        url: "/favicon-dark.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: dark)",
      },
    ],
    shortcut: "/icon.svg",
  },
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  category: "Technology",
};

export const certManagerSeoMetadata: Metadata = {
  title: "Certificates",
  description:
    "Discover certificates, issue and renew SSL/TLS, rotate keys and deploy to cloud and Kubernetes targets.",
};

export const integrationsSeoMetadata: Metadata = {
  title: "Integrations, Credentials & Connectors",
  description:
    "Connect Slack, Microsoft Teams, PagerDuty and ServiceNow, manage the DNS and deployment credentials your certificates are issued and delivered with, and review the connectors your CertPing agents advertise.",
};
