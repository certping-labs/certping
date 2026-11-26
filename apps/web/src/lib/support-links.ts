// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where people of a self-hosted installation get help: the project's public
 * GitHub issues and documentation. Security reports follow SECURITY.md and go
 * to the security address, never to a public issue.
 */
export const PROJECT_REPOSITORY_URL =
  "https://github.com/certping-labs/certping" as const;

export const GITHUB_ISSUES_URL = `${PROJECT_REPOSITORY_URL}/issues` as const;

export const DOCS_URL = `${PROJECT_REPOSITORY_URL}/tree/main/docs` as const;

export const SECURITY_POLICY_URL =
  `${PROJECT_REPOSITORY_URL}/blob/main/SECURITY.md` as const;

/** For security vulnerability reports only, as SECURITY.md describes. */
export const SECURITY_EMAIL = "security@certping.com" as const;

/** Paid support, enterprise plans and managed cloud from Seaionl Inc. */
export const PAID_OPTIONS_URL = "https://www.certping.com/enterprise/" as const;

/** A new GitHub issue with the title and body filled in. */
export function newGithubIssueHref(title: string, body?: string): string {
  const params = new URLSearchParams({ title });
  if (body) {
    params.set("body", body);
  }
  return `${GITHUB_ISSUES_URL}/new?${params.toString()}`;
}

/** Anchor attributes for opening an off-site destination safely. */
export const EXTERNAL_LINK_PROPS = {
  rel: "noreferrer",
  target: "_blank",
} as const;

export const isExternalHref = (href: string): boolean =>
  href.startsWith("http://") || href.startsWith("https://");
