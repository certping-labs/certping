// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Route constants for the unified Integrations section.
 *
 * Third-party apps, saved provider connections and the things agents advertise
 * used to be three separate nav entries under Operations, Certificate Lifecycle
 * and Machine Identity. They are one page now, split by category rather than by
 * which module happened to own them:
 *
 *   /integrations/apps                   <- was /settings/integrations
 *   /integrations/dns                    <- /cert-manager/credentials, type DNS
 *   /integrations/deployment-targets     <- /cert-manager/credentials, type DEPLOYMENT
 *   /integrations/certificate-authorities <- /machine-identity/connectors, CA half
 *   /integrations/device-sources         <- /machine-identity/connectors, source half
 *
 * A saved DNS or deployment record is a *connection*, so its add and edit forms
 * live under /integrations/connections rather than under either category - one
 * form serves both, branching on `?type=`.
 *
 * The old paths still resolve - see the redirects in `next.config.ts`.
 */

export const INTEGRATIONS_HREF = "/integrations";
export const INTEGRATIONS_APPS_HREF = "/integrations/apps";
export const INTEGRATIONS_DNS_HREF = "/integrations/dns";
export const INTEGRATIONS_DEPLOYMENT_TARGETS_HREF =
  "/integrations/deployment-targets";
export const INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF =
  "/integrations/certificate-authorities";
export const INTEGRATIONS_DEVICE_SOURCES_HREF = "/integrations/device-sources";

/** Add and edit forms for a saved DNS or deployment connection. */
export const CONNECTIONS_HREF = "/integrations/connections";

/**
 * The category tab a connection of this type belongs to.
 *
 * `/integrations/connections` is only ever a form segment, so "back to the
 * list" from an add or edit form resolves through here. An unknown or missing
 * type falls back to DNS - the first category either way.
 */
export const connectionsListHref = (type?: string | null) =>
  type === "DEPLOYMENT"
    ? INTEGRATIONS_DEPLOYMENT_TARGETS_HREF
    : INTEGRATIONS_DNS_HREF;
export const addConnectionHref = (type?: "DNS" | "DEPLOYMENT") =>
  type ? `${CONNECTIONS_HREF}/add?type=${type}` : `${CONNECTIONS_HREF}/add`;
export const editConnectionHref = (credentialRef: string) =>
  `${CONNECTIONS_HREF}/${encodeURIComponent(credentialRef)}/edit`;

/**
 * Deep link that opens one deployment connection's details.
 *
 * Discovery is the only caller and only ever references deployment targets
 * (AWS ACM, Azure Key Vault, Kubernetes Secrets), so it lands on that tab.
 */
export const deploymentTargetDetailsHref = (credentialXref: string) =>
  `${INTEGRATIONS_DEPLOYMENT_TARGETS_HREF}?credential=${encodeURIComponent(credentialXref)}`;

/** Stable identifiers for the section's category tabs. */
export type IntegrationsTabId =
  | "apps"
  | "dns"
  | "deployment-targets"
  | "certificate-authorities"
  | "device-sources";

/**
 * The five tab roots, independent of who may see them.
 *
 * The section shell uses this to tell a tab root (which gets the section header
 * and tab bar) from a detail or form route nested under the section (which
 * keeps its own full-page chrome).
 */
export const INTEGRATIONS_TAB_HREFS: readonly string[] = [
  INTEGRATIONS_APPS_HREF,
  INTEGRATIONS_DNS_HREF,
  INTEGRATIONS_DEPLOYMENT_TARGETS_HREF,
  INTEGRATIONS_CERTIFICATE_AUTHORITIES_HREF,
  INTEGRATIONS_DEVICE_SOURCES_HREF,
];
