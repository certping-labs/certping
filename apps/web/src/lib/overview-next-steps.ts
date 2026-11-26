// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export type NextStepTone = "critical" | "warning" | "opportunity";

export type NextStepAction = { kind: "link"; label: string; href: string };

export interface NextStep {
  id: string;
  tone: NextStepTone;
  title: string;
  detail: string;
  action: NextStepAction | null;
  note?: string;
}

export interface NextStepInputs {
  /** Total certificates in the inventory; null while it is unknown. */
  totalCertificates?: number | null;
  canIssueCertificates?: boolean;
  certificatesExpiring: number;
  certificatesFailed?: number;
  deploymentsFailed: number;
  priorityAlerts: number;
  /**
   * CERTIFICATE_RENEWAL is on. When off, expiring certificates still surface
   * (the expiry is a fact) but link to the inventory, not a renewal view.
   */
  canReviewRenewals?: boolean;
  /**
   * Whether a link may be offered (its route's feature is on). Steps whose
   * link fails are dropped, so no next step leads to a not-available page.
   */
  isRouteAvailable?: (href: string) => boolean;
}

export function describeFailedSources(sources: readonly string[]): string {
  if (sources.length <= 1) return sources[0] ?? "";
  return `${sources.slice(0, -1).join(", ")} and ${sources[sources.length - 1]}`;
}

const MAX_STEPS = 6;

const plural = (count: number, one: string, many = `${one}s`) =>
  `${count} ${count === 1 ? one : many}`;

export function buildNextSteps(inputs: NextStepInputs): NextStep[] {
  const steps: NextStep[] = [];

  if (inputs.priorityAlerts > 0) {
    steps.push({
      id: "alerts",
      tone: "critical",
      title: `${plural(inputs.priorityAlerts, "priority alert")} unread`,
      detail: "Warning and critical alerts that nobody has reviewed yet.",
      action: { kind: "link", label: "Review alerts", href: "/incidents" },
    });
  }
  if ((inputs.certificatesFailed ?? 0) > 0) {
    steps.push({
      id: "certificates-failed",
      tone: "warning",
      title: `${plural(inputs.certificatesFailed ?? 0, "certificate")} failed to issue`,
      detail: "See why each request failed, fix it and request it again.",
      action: {
        kind: "link",
        label: "Review failures",
        href: "/cert-manager?status=FAILED",
      },
    });
  }
  if (inputs.deploymentsFailed > 0) {
    steps.push({
      id: "deployments",
      tone: "warning",
      title: `${plural(inputs.deploymentsFailed, "certificate deployment")} failed`,
      detail: "A target did not receive its certificate.",
      action: {
        kind: "link",
        label: "Review",
        href: "/cert-manager/deployments",
      },
    });
  }
  if (inputs.certificatesExpiring > 0) {
    steps.push({
      id: "certificates-expiring",
      tone: "warning",
      title: `${plural(inputs.certificatesExpiring, "certificate")} ${inputs.certificatesExpiring === 1 ? "expires" : "expire"} within 30 days`,
      detail:
        inputs.canReviewRenewals === false
          ? "Replace them before browsers start warning visitors."
          : "Renew them before browsers start warning visitors.",
      action:
        inputs.canReviewRenewals === false
          ? {
              kind: "link",
              label: "Review certificates",
              href: "/cert-manager?status=ACTIVE",
            }
          : {
              kind: "link",
              label: "Review renewals",
              href: "/cert-manager?status=ACTIVE&renewal=expiring_30_days",
            },
    });
  }
  // A new organization: the first-run path, in the order it is best done.
  // Discover what exists, check its PQC readiness, connect the CA and DNS
  // accounts rotation needs, add where certificates get deployed, then
  // invite the team. Each link is dropped when its feature is off.
  if (inputs.totalCertificates === 0) {
    steps.push({
      id: "onboarding:discover",
      tone: "opportunity",
      title: "Configure certificate discovery",
      detail:
        "Read the certificates already stored in AWS Certificate Manager, Azure Key Vault and Kubernetes so the inventory starts from what you already run.",
      action: {
        kind: "link",
        label: "Set up discovery",
        href: "/cert-manager/discovery",
      },
    });
    steps.push({
      id: "onboarding:pqc",
      tone: "opportunity",
      title: "Review PQC readiness",
      detail:
        "See which keys and signatures are quantum-vulnerable once discovery has found them.",
      action: {
        kind: "link",
        label: "Open PQC readiness",
        href: "/cert-manager/cryptography",
      },
    });
    if (inputs.canIssueCertificates) {
      steps.push({
        id: "onboarding:rotation",
        tone: "opportunity",
        title: "Configure certificate rotation",
        detail:
          "Connect a certificate authority and a DNS provider, then issue or import the first certificate.",
        action: {
          kind: "link",
          label: "Set up rotation",
          href: "/cert-manager/rotation",
        },
      });
      steps.push({
        id: "onboarding:deployments",
        tone: "opportunity",
        title: "Configure deployment integrations",
        detail:
          "Add the clusters, load balancers and cloud services certificates are deployed to.",
        action: {
          kind: "link",
          label: "Add deployment targets",
          href: "/integrations/deployment-targets",
        },
      });
      steps.push({
        id: "onboarding:members",
        tone: "opportunity",
        title: "Invite organization members",
        detail:
          "Give analysts and viewers their own access instead of sharing yours.",
        action: {
          kind: "link",
          label: "Invite members",
          href: "/settings/organization-access?tab=members",
        },
      });
    }
  }

  return steps
    .filter(
      (step) =>
        !step.action || (inputs.isRouteAvailable?.(step.action.href) ?? true),
    )
    .slice(0, MAX_STEPS);
}
