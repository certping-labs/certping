// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/** Response from `GET /api/v1/deployment-info`. Public, no auth required. */
export interface DeploymentInfo {
  /**
   * How agents connect. `GATEWAY`: outbound HTTPS long polling with an agent token.
   */
  agentTransport?: AgentTransport;
  /** True until the first Platform Super Admin exists; visitors are sent to first-run setup. */
  setupRequired?: boolean;
  /**
   * The installation's OpenID Connect provider (`CERTPING_OIDC_*`), when configured: the login page
   * shows a button with `label` that opens `startPath` on the API origin. Null or absent when sign-in
   * is local only.
   */
  ssoLogin?: SsoLogin | null;
  /** False on a self-hosted install without outgoing email; absent means it can send. */
  emailEnabled?: boolean;
}

export interface SsoLogin {
  label: string;
  /** Path on the API origin, e.g. `/oauth2/authorization/sso`. */
  startPath: string;
}

export type AgentTransport = "GATEWAY";
