// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import "../globals.css";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/sidebar/app-sidebar";
import { Navbar } from "@/components/common/navbar";
import { ReactQueryProvider } from "@/providers/react-query";
import { Suspense } from "react";
import AuthProvider from "@/providers/auth-provider";
import { NetworkStatusProvider } from "@/providers/network-status-provider";
import { privateRobots } from "@/lib/seo-metadata";
import { FeatureRouteGate } from "@/components/common/feature-route-gate";
import { StatusBanner } from "@/components/common/status-banner";

export const metadata: Metadata = {
  robots: privateRobots,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ReactQueryProvider>
      <Suspense fallback={null}>
        <NetworkStatusProvider>
          <AuthProvider>
            <SidebarProvider className="certping-app-environment">
              <AppSidebar className="certping-app-sidebar" variant="sidebar" />
              <SidebarInset
                id="main-content"
                className="overflow-hidden certping-app-workspace"
              >
                <Navbar />
                <StatusBanner />
                <div className="min-h-0 flex-1 overflow-auto bg-background">
                  <FeatureRouteGate>{children}</FeatureRouteGate>
                </div>
              </SidebarInset>
            </SidebarProvider>
          </AuthProvider>
        </NetworkStatusProvider>
      </Suspense>
    </ReactQueryProvider>
  );
}
