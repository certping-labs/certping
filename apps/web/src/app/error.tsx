// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useRef } from "react";
import React from "react";
import Image from "next/image";
import Link from "next/link";
import { WarningIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { logger } from "@/lib/logger/logger.service";

const CHUNK_RELOAD_STORAGE_PREFIX = "certping:chunk-reload";
const CHUNK_ERROR_PATTERN =
  /ChunkLoadError|Loading chunk \d+ failed|_next\/static\/chunks/i;

// Stale/mismatched chunks after a deploy don't always surface as a
// "ChunkLoadError". When webpack's runtime (`__webpack_require__`) fails to
// resolve a module, it throws a generic TypeError while doing `factory.call(...)`
// -e.g. "Cannot read properties of undefined (reading 'call')" (Chrome),
// "undefined is not an object (evaluating 'e.call')" (Safari), or
// "can't access property \"call\"" (Firefox). The message never mentions
// chunks; only the stack points at the `webpack-*.js` runtime. Treat these as
// chunk errors too so they auto-recover instead of showing the crash screen.
const WEBPACK_FACTORY_ERROR_PATTERN =
  /reading '(?:call|default)'|evaluating '[^']*\.call'|access property "(?:call|default)"/i;
const WEBPACK_RUNTIME_STACK_PATTERN = /webpack-|_next\/static\/chunks/i;

interface GlobalErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

const isChunkLoadError = (error: Error): boolean => {
  if (
    error.name === "ChunkLoadError" ||
    CHUNK_ERROR_PATTERN.test(error.message)
  ) {
    return true;
  }

  // Webpack module-resolution failure: the factory-call signature in the
  // message plus a stack originating in the webpack runtime / static chunks.
  return (
    WEBPACK_FACTORY_ERROR_PATTERN.test(error.message) &&
    WEBPACK_RUNTIME_STACK_PATTERN.test(error.stack ?? "")
  );
};

const buildChunkReloadKey = (error: Error): string => {
  const deploymentId =
    process.env.NEXT_PUBLIC_DEPLOYMENT_ID ?? process.env.NEXT_DEPLOYMENT_ID;
  const errorSignature = `${error.name}:${error.message}`;

  return [CHUNK_RELOAD_STORAGE_PREFIX, deploymentId, errorSignature]
    .filter(Boolean)
    .join(":");
};

const reloadOnceForChunkError = (error: Error): void => {
  if (typeof window === "undefined" || !isChunkLoadError(error)) {
    return;
  }

  try {
    const reloadKey = buildChunkReloadKey(error);
    if (window.sessionStorage.getItem(reloadKey)) {
      return;
    }

    window.sessionStorage.setItem(reloadKey, "1");
    window.location.reload();
  } catch {
    window.location.reload();
  }
};

export default function GlobalError({ error, reset }: GlobalErrorProps) {
  const lastLoggedSignatureRef = useRef<string | null>(null);

  useEffect(() => {
    reloadOnceForChunkError(error);

    const signature = `${error.name}:${error.message}:${error.digest ?? "no-digest"}`;
    if (lastLoggedSignatureRef.current === signature) {
      return;
    }
    lastLoggedSignatureRef.current = signature;

    void logger.error("Global error boundary captured an app crash", {
      eventName: "exception",
      error,
      digest: error.digest,
      pathname:
        typeof window !== "undefined" ? window.location.pathname : undefined,
      href: typeof window !== "undefined" ? window.location.href : undefined,
      userAgent:
        typeof window !== "undefined" ? window.navigator.userAgent : undefined,
    });
  }, [error]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4 py-10">
      <section className="flex w-full max-w-3xl flex-col items-center text-center">
        <div className="mb-8 flex h-48 w-full max-w-sm items-center justify-center md:h-56">
          <Image
            src="/assets/certping-service-unavailable.svg"
            alt="Files temporarily unavailable illustration"
            width={320}
            height={260}
            priority
            className="h-full w-auto object-contain"
          />
        </div>

        <div className="mb-4 inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1 text-xs font-medium text-muted-foreground">
          <WarningIcon className="h-3.5 w-3.5" aria-hidden="true" />
          Application error
        </div>
        <h1 className="max-w-xl text-3xl font-semibold tracking-[-0.035em] text-foreground md:text-4xl">
          Something interrupted the CertPing console.
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-7 text-muted-foreground">
          An unexpected error occurred while loading this page. Retry the
          current view, or return to the dashboard to continue from a stable
          page.
        </p>
        {error.digest ? (
          <p className="mt-5 rounded-md border bg-muted px-3 py-2 text-xs text-muted-foreground">
            Error ID: {error.digest}
          </p>
        ) : null}
        <div className="mt-8 flex flex-col gap-3 sm:flex-row">
          <Button onClick={reset} className="gap-2">
            <ArrowCounterClockwiseIcon className="h-4 w-4" aria-hidden="true" />
            Try again
          </Button>
          <Button variant="outline" asChild>
            <Link href="/dashboard">Dashboard</Link>
          </Button>
        </div>
      </section>
    </div>
  );
}
