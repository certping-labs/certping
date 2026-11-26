// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canCreateCertificates,
  canCreateDeployments,
  canViewCertificates,
  canViewDeployments,
} from "@/lib/authz";
import {
  type AppSearchContext,
  type AppSearchItem,
  createAppSearchItem,
} from "@/lib/app-search-types";
import {
  DEPLOYMENT_CREDENTIAL_ALIASES,
  SSL_CERTIFICATE_ALIASES,
} from "@/lib/app-search-aliases";

export function getCertificateSearchItems({
  isFeatureEnabled,
  isFeatureFlagsReady,
  user,
}: AppSearchContext): AppSearchItem[] {
  const items: AppSearchItem[] = [];

  if (canViewCertificates(user)) {
    items.push(
      createAppSearchItem(
        "Certificates",
        "View and manage certificate inventory.",
        "/cert-manager",
        "Certificate Lifecycle",
        ["clm", "inventory", ...SSL_CERTIFICATE_ALIASES],
      ),
    );
  }

  if (canViewCertificates(user) && isFeatureEnabled("DISCOVERY")) {
    items.push(
      createAppSearchItem(
        "Certificate Discovery",
        "Scan for certificates across your infrastructure.",
        "/cert-manager/discovery",
        "Certificate Lifecycle",
        [
          "scan",
          "inventory",
          "discover ssl",
          "discover tls",
          "discovery",
          ...SSL_CERTIFICATE_ALIASES,
        ],
      ),
    );
  }

  if (canViewCertificates(user)) {
    items.push(
      createAppSearchItem(
        "Rotation",
        "Renewal schedule, automatic renewal and renewal results.",
        "/cert-manager/rotation",
        "Certificate Lifecycle",
        [
          "rotation",
          "renewal",
          "renew",
          "auto-renew",
          "automatic renewal",
          "expiring",
          "renewal schedule",
        ],
      ),
    );
  }

  if (
    canViewCertificates(user) &&
    isFeatureFlagsReady &&
    isFeatureEnabled("PQC_READINESS")
  ) {
    items.push(
      createAppSearchItem(
        "PQC Readiness",
        "Inspect cryptographic posture, algorithms and post-quantum readiness.",
        "/cert-manager/cryptography",
        "Certificate Lifecycle",
        [
          "crypto",
          "cryptography",
          "pqc",
          "post-quantum",
          "algorithm",
          "cipher",
          "key strength",
          "tls posture",
        ],
      ),
    );
  }

  if (canCreateCertificates(user) && isFeatureEnabled("CERTIFICATE_ISSUANCE")) {
    items.push(
      createAppSearchItem(
        "Issue Certificate",
        "Request a new certificate.",
        "/cert-manager/add",
        "Certificate Lifecycle",
        [
          "create",
          "new",
          "add certificate",
          "new certificate",
          "issue ssl",
          "issue tls",
          ...SSL_CERTIFICATE_ALIASES,
        ],
      ),
    );
  }

  if (canViewDeployments(user) && isFeatureEnabled("CERTIFICATE_DEPLOYMENT")) {
    items.push(
      createAppSearchItem(
        "Deployments",
        "Track certificate deployment activity.",
        "/cert-manager/deployments",
        "Certificate Lifecycle",
        [
          "deployment",
          "requests",
          "targets",
          "deploy certificate",
          ...DEPLOYMENT_CREDENTIAL_ALIASES,
        ],
      ),
    );

    if (canCreateDeployments(user)) {
      items.push(
        createAppSearchItem(
          "Deploy certificate",
          "Open deployment manager to choose a certificate and target.",
          "/cert-manager/deployments",
          "Certificate Lifecycle",
          [
            "deploy certificate",
            "new deployment",
            ...DEPLOYMENT_CREDENTIAL_ALIASES,
          ],
        ),
      );
    }
  }

  // Saved DNS providers and deployment targets used to be searched from here,
  // as "Credentials", alongside a "Certificate Integrations" entry pointing at
  // the legacy /cert-manager/integrations alias for that same list. Integrations
  // is one real section now, so all of those palette entries live with the rest
  // of it in `app-search-operations`.

  return items;
}
