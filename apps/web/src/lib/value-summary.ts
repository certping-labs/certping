// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";

/** What CertPing did for the organization and the manual work that saved (server: ValueSummaryDto). */
export interface ValueSummary {
  days: number;
  since: string;
  issuances: number;
  renewals: number;
  scheduledRenewals: number;
  automatedDeployments: number;
  /**
   * Renewals completed before the old certificate's notAfter. Optional: an
   * older or newer server may not send it, and then the card is hidden rather
   * than showing a number that is not a real check.
   */
  renewedBeforeExpiry?: number | null;
  minutesSaved: number;
  unmanagedDiscovered: number;
  /** Unmanaged certificates expiring in the next 30 days; already expired ones are not counted. */
  unmanagedExpiringSoon?: number | null;
  assumptions: {
    minutesPerRenewal: number;
    minutesPerDeployment: number;
    minutesPerIssuance: number;
  };
}

export async function getValueSummary(days = 365): Promise<ValueSummary> {
  const response = await apiClient.get<ValueSummary>(
    apiRoutes.query.certs.valueSummary,
    { params: { days } },
  );
  return response.data;
}

/** "12.5" hours from minutes, one decimal below 10 hours, whole hours above. */
export function formatHours(minutes: number): string {
  const hours = minutes / 60;
  if (hours === 0) return "0";
  return hours < 10
    ? hours.toFixed(1).replace(/\.0$/, "")
    : String(Math.round(hours));
}
