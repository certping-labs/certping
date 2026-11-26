// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export interface ExpectedComponent {
  id: string;
  name: string;
  /**
   * A component the source leaves out when this installation does not run
   * it (email notifications without a mail server). Left out, it is not
   * shown; an expected component that is not optional shows as unknown.
   */
  optional?: boolean;
}

export interface StatusSource {
  id: string;
  path: string;
  components: readonly ExpectedComponent[];
}

/**
 * Where the status page reads each service's state, as a Statuspage v2
 * summary. Moving to a hosted Statuspage means replacing this list with its
 * summary.json.
 */
export const STATUS_SOURCES: readonly StatusSource[] = [
  {
    id: "platform",
    path: "/api/v1/public/status",
    components: [
      { id: "api", name: "API and sign-in" },
      { id: "notifications", name: "Email notifications", optional: true },
      { id: "certificates", name: "Certificate issuance and renewal" },
    ],
  },
];

/** Components whose work waits in a queue while they are down. */
export const QUEUED_COMPONENTS: readonly string[] = [
  "notifications",
  "certificates",
];
