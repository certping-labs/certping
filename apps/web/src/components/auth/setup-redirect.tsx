// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { getSetupStatus } from "@/lib/backend/auth";

/**
 * On the sign-in page of a fresh installation there is nobody to sign in as:
 * while the server says setup is required, send the visitor to /setup.
 */
export function SetupRedirect() {
  const router = useRouter();
  const status = useQuery({
    queryKey: ["auth", "setup-status"],
    queryFn: getSetupStatus,
    retry: 1,
    staleTime: 60_000,
  });
  useEffect(() => {
    if (status.data?.setupRequired) {
      router.replace("/setup");
    }
  }, [router, status.data?.setupRequired]);
  return null;
}
