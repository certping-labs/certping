// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import type { Metadata } from "next";
import EntLoginForm from "./ent-login-form";
import { SetupRedirect } from "@/components/auth/setup-redirect";
import { privateRobots } from "@/lib/seo-metadata";
import {
  SIGNED_OUT_REASON_PARAM,
  parseSignedOutReason,
} from "@/lib/signed-out-reason";

export const metadata: Metadata = {
  title: "Sign in",
  robots: privateRobots,
};

/** Local sign-in with a username or email and a password. Members are invited by an admin. */
export default async function LoginPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const signedOutReason = parseSignedOutReason(
    params?.[SIGNED_OUT_REASON_PARAM],
  );
  return (
    <>
      <SetupRedirect />
      <EntLoginForm signedOutReason={signedOutReason} />
    </>
  );
}
