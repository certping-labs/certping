// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { JSX, useEffect, useRef } from "react";

import { useAuthStore } from "@/stores/auth-store";

export const queryClient = new QueryClient();
const isDevelopment = process.env.NODE_ENV === "development";

export function ReactQueryProvider(props: { children: JSX.Element }) {
  const organizationScope = useAuthStore(
    (state) => state.user?.organizationId?.trim() || null,
  );
  const previousOrganizationScope = useRef(organizationScope);

  useEffect(() => {
    if (previousOrganizationScope.current !== organizationScope) {
      queryClient.clear();
      previousOrganizationScope.current = organizationScope;
    }
  }, [organizationScope]);

  return (
    <QueryClientProvider client={queryClient}>
      {isDevelopment ? <ReactQueryDevtools initialIsOpen={false} /> : null}
      {props.children}
    </QueryClientProvider>
  );
}
