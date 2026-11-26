// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { redirect } from "next/navigation";

/*
 * The app's root goes to sign in. On a fresh installation the sign-in page
 * sends the visitor on to first-run setup (see `SetupRedirect`).
 */
export default function AppRoot() {
  redirect("/login");
}
