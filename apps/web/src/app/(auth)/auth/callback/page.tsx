// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  CheckCircleIcon,
  CircleNotchIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import { toast } from "sonner";

import { AuthCardShell } from "@/components/auth/auth-card-shell";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/use-auth";
import { exchangeSsoCode } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";
import { getPostAuthRoute } from "@/lib/post-auth";

/** What the server's failure redirect says, in words a person can act on. */
const FAILURE_COPY: Record<string, { title: string; detail: string }> = {
  SSO_MISCONFIGURED: {
    title: "Single sign-on is not set up correctly",
    detail:
      "The identity provider answered, but CertPing's configuration for it is incomplete or points at an organization that does not exist. Ask your administrator to check the CERTPING_OIDC settings.",
  },
  SSO_MEMBER_NOT_PROVISIONED: {
    title: "No member account for this sign-in",
    detail:
      "Your identity provider knows you, but this installation only lets invited members sign in with it. Ask an organization admin to add you.",
  },
  SSO_REJECTED: {
    title: "The identity provider rejected the sign-in",
    detail:
      "Try again. If it keeps happening, ask your administrator to check the provider's logs.",
  },
  ACCOUNT_DISABLED: {
    title: "Your account is disabled",
    detail: "An organization admin can re-enable it.",
  },
  ORGANIZATION_SUSPENDED: {
    title: "Your organization is suspended",
    detail: "Contact the people who run this CertPing installation.",
  },
};

/** Query keys that must not stay in the address bar or history once read. */
const CREDENTIAL_PARAMS = ["code", "token", "refreshToken", "expiresIn"];

/** Drops the one-time code (and any stale token params) from the URL without a navigation. */
function scrubCredentialsFromUrl() {
  const url = new URL(window.location.href);
  if (!CREDENTIAL_PARAMS.some((key) => url.searchParams.has(key))) return;
  CREDENTIAL_PARAMS.forEach((key) => url.searchParams.delete(key));
  window.history.replaceState(
    window.history.state,
    "",
    `${url.pathname}${url.search}${url.hash}`,
  );
}

/**
 * Where the server sends the browser after single sign-on: with a one-time `code` on success,
 * or `error`, `message`, `reason` and `ref` on failure. The code is read once, wiped from the
 * address bar and history before anything else runs, and traded for a session exactly like a
 * password login. It is never logged or shown.
 */
function CallbackContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { establishSession } = useAuth();
  const handled = useRef(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  // Captured on first render: stripping the URL below changes searchParams afterwards.
  const [code] = useState(() => searchParams.get("code"));

  const error = searchParams.get("error");
  const message = searchParams.get("message");
  const reason = searchParams.get("reason");
  const reference = searchParams.get("ref");
  const failure = reason ? FAILURE_COPY[reason] : undefined;

  useEffect(() => {
    if (handled.current) return;
    handled.current = true;
    scrubCredentialsFromUrl();
    if (error || !code) return;
    exchangeSsoCode(code)
      .then(async (response) => {
        // The same finish as a password sign-in (ent-login-form's finishSignIn).
        const session = await establishSession(response);
        toast.success(response.message || "Signed in successfully.");
        router.replace(getPostAuthRoute(session));
      })
      .catch((cause: unknown) => {
        setSessionError(
          getApiErrorMessage(cause, "Could not open your session."),
        );
      });
  }, [code, error, establishSession, router]);

  if (error || sessionError) {
    return (
      <AuthCardShell
        title="Sign-in failed"
        description="Single sign-on did not complete."
      >
        <div className="space-y-4">
          <Alert variant="destructive">
            <XCircleIcon aria-hidden weight="fill" />
            <AlertTitle>{failure ? failure.title : "Error"}</AlertTitle>
            <AlertDescription>
              {failure
                ? failure.detail
                : sessionError ||
                  message ||
                  "An error occurred during sign-in."}
            </AlertDescription>
          </Alert>
          {reference ? (
            <p className="text-xs text-muted-foreground">
              Reference for your administrator:{" "}
              <code className="font-mono break-all">{reference}</code>
            </p>
          ) : null}
          <Button
            onClick={() => router.push("/login")}
            className="w-full"
            variant="outline"
          >
            Back to sign in
          </Button>
        </div>
      </AuthCardShell>
    );
  }

  if (!code) {
    return (
      <AuthCardShell
        title="Incomplete sign-in response"
        description="The identity provider's answer did not carry a session."
      >
        <div className="space-y-4">
          <Alert variant="destructive">
            <AlertTitle>Missing sign-in code</AlertTitle>
            <AlertDescription>
              Start the sign-in again from the login page.
            </AlertDescription>
          </Alert>
          <Button
            onClick={() => router.push("/login")}
            className="w-full"
            variant="outline"
          >
            Back to sign in
          </Button>
        </div>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      title="Signing you in"
      description="Your identity provider accepted the sign-in. Opening your workspace."
      footer={
        <Link href="/login" className="underline underline-offset-4">
          Back to sign in
        </Link>
      }
    >
      <div
        aria-live="polite"
        className="divide-y divide-border rounded-xl border border-border"
      >
        <div className="flex items-center gap-3 px-4 py-4">
          <CheckCircleIcon
            className="h-5 w-5 status-success-text"
            aria-hidden
          />
          <p className="text-sm font-semibold text-foreground">
            Identity verified
          </p>
        </div>
        <div className="flex items-center gap-3 px-4 py-4">
          <CircleNotchIcon
            className="h-5 w-5 animate-spin text-primary motion-reduce:animate-none"
            aria-hidden
          />
          <p className="text-sm font-semibold text-foreground">
            Opening workspace
          </p>
        </div>
      </div>
    </AuthCardShell>
  );
}

export default function CallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-dvh items-center justify-center certping-auth-field">
          <CircleNotchIcon className="h-8 w-8 animate-spin text-muted-foreground motion-reduce:animate-none" />
        </div>
      }
    >
      <CallbackContent />
    </Suspense>
  );
}
