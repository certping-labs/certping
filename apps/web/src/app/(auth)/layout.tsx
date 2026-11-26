// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import "../globals.css";
import { ReactQueryProvider } from "@/providers/react-query";
import AuthProvider from "@/providers/auth-provider";
import { privateRobots } from "@/lib/seo-metadata";

export const metadata: Metadata = {
  robots: privateRobots,
};

// Authentication pages must never reuse prerendered HTML across deployments.
// A cached document can reference chunks from the previous image, leaving the
// page permanently on its pre-hydration loading state after a rolling update.
export const dynamic = "force-dynamic";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ReactQueryProvider>
      <AuthProvider>
        <div className="min-h-screen w-full">{children}</div>
      </AuthProvider>
    </ReactQueryProvider>
  );
}
