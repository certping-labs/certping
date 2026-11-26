// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * App mode controls which auth surfaces should be reachable.
 *
 * NEXT_PUBLIC_APP_MODE:
 * - "enterprise" => enterprise login + org SSO entrypoint are enabled
 * - other/empty  => self-serve auth surface is enabled
 */
export function isEnterpriseAppMode(): boolean {
  return process.env.NEXT_PUBLIC_APP_MODE === "enterprise";
}
