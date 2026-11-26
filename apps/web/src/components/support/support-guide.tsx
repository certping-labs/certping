// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import Link from "next/link";
import React from "react";

import {
  DOCS_URL,
  EXTERNAL_LINK_PROPS,
  GITHUB_ISSUES_URL,
  PAID_OPTIONS_URL,
  SECURITY_EMAIL,
  SECURITY_POLICY_URL,
} from "@/lib/support-links";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const SUPPORT_STATEMENT =
  "CertPing OSS is free to self-host. For help deploying CertPing in the cloud, on-premises, or in an enterprise environment, read the docs or open an issue on GitHub.";

/** What a useful support request carries. Nothing on this list is a secret. */
export const SUPPORT_REQUEST_CHECKLIST = [
  "The CertPing version (the release tag, or the image digest from the release notes).",
  "How CertPing is deployed: Docker Compose, Helm, the Azure single VM kit, or your own setup.",
  "What you expected and what happened, with the time it happened and your time zone.",
  "Server and agent logs around that time, with tokens, passwords and private keys removed.",
  "The certificate, deployment target or discovery job affected (names and identifiers, never the private key).",
  "Anything you already tried.",
] as const;

interface SupportSectionProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

function SupportSection({ title, description, children }: SupportSectionProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm text-muted-foreground">
        {children}
      </CardContent>
    </Card>
  );
}

/**
 * The support page of the open edition: how to get help, what to include,
 * and what applies to cloud, self-hosted and on-premises installations.
 * It never asks for a payment, a license key or an activation.
 */
export function SupportGuide() {
  const linkClass = "font-medium text-foreground underline";
  return (
    <div className="space-y-6">
      <p className="max-w-3xl text-sm text-muted-foreground">
        {SUPPORT_STATEMENT}
      </p>

      <div className="grid gap-4 lg:grid-cols-2">
        <SupportSection
          title="How to request help"
          description="GitHub is the support channel for the open edition."
        >
          <p>
            Start with the{" "}
            <a className={linkClass} href={DOCS_URL} {...EXTERNAL_LINK_PROPS}>
              documentation
            </a>
            . For a question, a bug or a feature request, open an issue in the{" "}
            <a
              className={linkClass}
              href={GITHUB_ISSUES_URL}
              {...EXTERNAL_LINK_PROPS}
            >
              CertPing GitHub issues
            </a>
            . Issues are public: do not put secrets or customer data in one.
          </p>
          <p>
            Security vulnerabilities never go in a public issue. Report them as{" "}
            <a
              className={linkClass}
              href={SECURITY_POLICY_URL}
              {...EXTERNAL_LINK_PROPS}
            >
              SECURITY.md
            </a>{" "}
            describes, to{" "}
            <a className={linkClass} href={`mailto:${SECURITY_EMAIL}`}>
              {SECURITY_EMAIL}
            </a>
            , which is for security reports only.
          </p>
        </SupportSection>

        <SupportSection
          title="What to include"
          description="A complete first message saves a round trip."
        >
          <ul className="list-disc space-y-1 pl-5">
            {SUPPORT_REQUEST_CHECKLIST.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </SupportSection>

        <SupportSection
          title="Cloud deployment support"
          description="CertPing running on a cloud provider, managed by you."
        >
          <p>
            The Azure single VM kit under <code>deploy/azure</code> and the Helm
            charts under <code>deploy/charts</code> are the supported cloud
            layouts. Say which one you use, the provider, and whether the agent
            runs next to the server or inside the network it manages.
          </p>
        </SupportSection>

        <SupportSection
          title="Self-hosted deployment support"
          description="Docker Compose on a server you run."
        >
          <p>
            The Compose kit under <code>deploy/compose</code> is the reference
            single-server install. Include the output of{" "}
            <code>docker compose ps</code> and the health endpoints&apos;
            answers. Keep your <code>.env</code> file to yourself: it holds the
            database password and the secret store key.
          </p>
        </SupportSection>

        <SupportSection
          title="On-premises deployment support"
          description="Air-gapped or restricted networks."
        >
          <p>
            CertPing works without outbound access from the agent except to the
            CertPing server, your CA and the systems it deploys to. Tell us
            which of those the agent can reach, and whether images are pulled
            through a private registry, so the answer fits your network.
          </p>
        </SupportSection>

        <SupportSection
          title="Commercial support"
          description="For organizations that need more than best-effort help."
        >
          <p>
            Seaionl Inc., the company behind CertPing, offers paid support,
            enterprise plans and managed cloud deployments. See{" "}
            <a
              className={linkClass}
              href={PAID_OPTIONS_URL}
              {...EXTERNAL_LINK_PROPS}
            >
              CertPing Enterprise
            </a>
            .
          </p>
          <p>
            Nothing in this installation requires a license key or a payment.
          </p>
        </SupportSection>
      </div>

      <p className="text-xs text-muted-foreground">
        Looking for how to install or upgrade? Start with{" "}
        <code>docs/self-hosting.md</code> in the repository. Need to check who
        can do what?{" "}
        <Link
          className="underline"
          href="/settings/organization-access?tab=members"
        >
          Organization &amp; Access
        </Link>{" "}
        lists the roles.
      </p>
    </div>
  );
}
