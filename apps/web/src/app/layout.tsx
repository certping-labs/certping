// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import { headers } from "next/headers";

import "./material-glass.css";
import "./globals.css";
import { GlassPointer } from "@/components/common/glass-pointer";
import { Toaster } from "sonner";
import NextTopLoader from "nextjs-toploader";
import { ThemeProvider } from "@/components/theme-provider";
import { TopLoaderRestore } from "@/components/common/top-loader-restore";
import { coreSeoMetadata } from "@/lib/seo-metadata";
import { certpingMono, certpingSans, landingSans } from "./fonts";

export const metadata: Metadata = coreSeoMetadata;

// Reading the request headers renders every page per request, which the CSP nonce needs:
// src/proxy.ts sets a fresh one each time and Next stamps it on its scripts.
export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${certpingSans.variable} ${certpingMono.variable} ${landingSans.variable}`}
    >
      <body suppressHydrationWarning className="w-full font-sans antialiased">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-100 focus:rounded-md focus:bg-background focus:px-4 focus:py-2 focus:text-foreground focus:ring-2 focus:ring-brand"
        >
          Skip to content
        </a>
        <ThemeProvider nonce={nonce}>
          <NextTopLoader showSpinner={false} />
          <GlassPointer />
          <TopLoaderRestore />

          <Toaster
            position="top-center"
            closeButton
            toastOptions={{
              classNames: {
                toast:
                  "rounded-(--radius-surface) border border-border bg-popover text-popover-foreground shadow-overlay font-sans",
                title: "font-semibold",
                description: "text-muted-foreground",
                success: "**:data-icon:text-success",
                error: "**:data-icon:text-destructive",
                warning: "**:data-icon:text-warning",
                info: "**:data-icon:text-brand",
                loading: "**:data-icon:text-muted-foreground",
                actionButton:
                  "rounded-full! bg-primary! text-primary-foreground! hover:bg-primary-hover!",
                cancelButton:
                  "rounded-full! bg-secondary! text-secondary-foreground!",
                closeButton:
                  "border-border! bg-popover! text-muted-foreground hover:text-foreground",
              },
            }}
          />
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
