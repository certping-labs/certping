// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Authentication is one plain task, not a marketing page: a quiet form
 * column on the page plane and, on wide screens, a short panel beside it that
 * says what this open source installation is and the terms it comes under.
 * The page follows the app theme; in dark mode the graphite field carries a
 * fine grain so it reads as a surface rather than a void.
 */
import React from "react";
import Link from "next/link";

import { CertPingBrand } from "@/components/common/certping-brand";

/** What every installation should know at the door: licence, data, warranty. */
export const OSS_TERMS = [
  {
    title: "Free and open source",
    body: "CertPing is licensed under the Apache License 2.0. You may use, change and share it, including for commercial use.",
  },
  {
    title: "Your data stays with you",
    body: "This installation runs on your own servers. Certificates, private keys and credentials are stored here and nowhere else.",
  },
  {
    title: "Nothing is sent without your say",
    body: "No usage data leaves this installation unless an administrator turns on the opt-in usage report.",
  },
  {
    title: "Provided as is",
    body: "The software comes without warranty of any kind, as the Apache License 2.0 sets out. The people who run this installation are responsible for it.",
  },
] as const;

interface AuthCardShellProps {
  title: string;
  description: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  eyebrow?: string;
}

export function AuthCardShell({
  title,
  description,
  children,
  footer,
  eyebrow,
}: AuthCardShellProps) {
  return (
    <div className="certping-noise min-h-dvh bg-background text-foreground certping-auth-page lg:grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <main
        id="main-content"
        className="relative flex min-h-dvh flex-col overflow-hidden px-5 py-6 sm:px-10 sm:py-8"
      >
        <div aria-hidden className="certping-auth-wash" />
        <div className="relative z-1 my-auto w-full max-w-[400px] self-center py-8">
          <section
            aria-labelledby="auth-title"
            className="certping-auth-surface"
          >
            <header>
              <Link
                aria-label="CertPing home"
                className="inline-flex rounded-md focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background focus-visible:outline-hidden"
                href="/"
              >
                <CertPingBrand
                  priority
                  surface="auto"
                  symbolClassName="size-8"
                  wordmarkClassName="text-xl"
                />
              </Link>
              {eyebrow ? (
                <p className="mt-10 text-sm font-medium text-primary">
                  {eyebrow}
                </p>
              ) : null}
              <h1
                className={`${eyebrow ? "mt-1.5" : "mt-10"} text-[1.75rem] leading-[1.15] font-semibold tracking-[-0.03em] text-balance`}
                id="auth-title"
              >
                {title}
              </h1>
              <p className="mt-2 max-w-[52ch] text-sm leading-6 text-muted-foreground">
                {description}
              </p>
            </header>

            <div className="mt-8 certping-auth-controls">{children}</div>

            {footer ? (
              <footer className="mt-6 border-t border-divider pt-5 text-sm leading-6 text-muted-foreground">
                {footer}
              </footer>
            ) : null}
          </section>
        </div>
        <p className="relative z-1 text-center text-xs text-muted-foreground">
          &copy; {new Date().getFullYear()} Seaionl Inc. CertPing is open source
          software under the Apache License 2.0.
        </p>
      </main>

      <aside
        aria-labelledby="oss-terms-title"
        className="relative hidden p-3 lg:block"
      >
        <div className="sticky top-3 flex h-[calc(100dvh-1.5rem)] flex-col justify-center rounded-[28px] border border-border bg-card px-12 py-10">
          <div className="max-w-[440px]">
            <p className="text-sm font-medium text-primary">Open source</p>
            <h2
              id="oss-terms-title"
              className="mt-1.5 text-2xl font-semibold tracking-[-0.02em] text-balance text-foreground"
            >
              Certificate lifecycle management you run yourself
            </h2>
            <dl className="mt-8 space-y-6">
              {OSS_TERMS.map(({ title, body }) => (
                <div key={title}>
                  <dt className="text-sm font-semibold text-foreground">
                    {title}
                  </dt>
                  <dd className="mt-1 text-sm leading-6 text-muted-foreground">
                    {body}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </aside>
    </div>
  );
}
