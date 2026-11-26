// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import {
  CircleNotchIcon,
  LockIcon,
  ShieldCheckIcon,
  UserIcon,
} from "@phosphor-icons/react";
import { toast } from "sonner";

import { AuthCardShell } from "@/components/auth/auth-card-shell";
import { SignedOutNotice } from "@/components/auth/signed-out-notice";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { loginUser, loginWithMfa } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";
import { getPostAuthRoute } from "@/lib/post-auth";
import { useAuth } from "@/hooks/use-auth";
import { useEmailEnabled, useSsoLogin } from "@/hooks/use-deployment-mode";
import { apiBaseUrl } from "@/lib/api-base-url";
import type { SignedOutReason } from "@/lib/signed-out-reason";

const loginSchema = z.object({
  identifier: z.string().min(1, "Username or email is required."),
  password: z.string().min(1, "Password is required."),
});

type LoginValues = z.infer<typeof loginSchema>;

const mfaSchema = z.object({
  code: z
    .string()
    .trim()
    .min(6, "Enter the six-digit code or a recovery code."),
});

type MfaValues = z.infer<typeof mfaSchema>;

interface EntLoginFormProps {
  signedOutReason: SignedOutReason | null;
}

export default function LoginPage({ signedOutReason }: EntLoginFormProps) {
  const router = useRouter();
  const { establishSession, isLoading: isLoadingAuth } = useAuth();
  const ssoLogin = useSsoLogin();
  const emailEnabled = useEmailEnabled();

  /** Set once the password was accepted and the account wants a one-time code. */
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      identifier: "",
      password: "",
    },
  });

  const mfaForm = useForm<MfaValues>({
    resolver: zodResolver(mfaSchema),
    defaultValues: { code: "" },
  });

  const finishSignIn = async (
    response: Awaited<ReturnType<typeof loginUser>>,
  ) => {
    const session = await establishSession(response);
    toast.success(response.message || "Signed in successfully.");
    router.replace(getPostAuthRoute(session));
  };

  const loginMutation = useMutation({
    mutationFn: loginUser,
    onSuccess: async (response) => {
      if (response.mfaRequired && response.mfaToken) {
        setMfaToken(response.mfaToken);
        mfaForm.reset({ code: "" });
        return;
      }
      await finishSignIn(response);
    },
    onError: (error: unknown) => {
      toast.error(getApiErrorMessage(error, "Sign-in failed."));
    },
  });

  const mfaMutation = useMutation({
    mutationFn: loginWithMfa,
    onSuccess: finishSignIn,
    onError: (error: unknown) => {
      const message = getApiErrorMessage(error, "That code was not valid.");
      toast.error(message);
      if (/expired/i.test(message)) {
        // The challenge is good for five minutes; after that the password step starts over.
        setMfaToken(null);
      }
    },
  });

  const handleMfaSubmit = mfaForm.handleSubmit((values) => {
    if (!mfaToken) return;
    mfaMutation.mutate({ mfaToken, code: values.code });
  });

  const handleSubmit = form.handleSubmit((values) => {
    loginMutation.mutate({
      identifier: values.identifier.trim(),
      password: values.password,
    });
  });

  const isPageLoading = isLoadingAuth;

  if (isPageLoading) {
    return (
      <div className="flex min-h-dvh items-center justify-center certping-auth-field">
        <CircleNotchIcon className="h-8 w-8 animate-spin text-muted-foreground motion-reduce:animate-none" />
      </div>
    );
  }

  if (mfaToken) {
    return (
      // A key per step: the steps share a tree shape, and reused fields would keep the previous form.
      <AuthCardShell
        key="mfa-step"
        title="Enter your one-time code"
        description="Open your authenticator app and enter the six-digit code for CertPing, or use one of your recovery codes."
        footer={
          <>
            Lost your authenticator and recovery codes? An organization admin
            can reset two-factor authentication for your account.
          </>
        }
      >
        <Form {...mfaForm}>
          <form className="space-y-4" onSubmit={handleMfaSubmit}>
            <FormField
              control={mfaForm.control}
              name="code"
              render={({ field }) => (
                <FormItem>
                  <FormLabel htmlFor="login-mfa-code">One-time code</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <ShieldCheckIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                      <Input
                        id="login-mfa-code"
                        className="h-11 pl-9 font-mono tracking-widest"
                        autoComplete="one-time-code"
                        inputMode="numeric"
                        autoFocus
                        placeholder="123 456"
                        {...field}
                      />
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              className="h-11 w-full"
              disabled={mfaMutation.isPending}
              type="submit"
            >
              {mfaMutation.isPending ? (
                <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Verify and sign in
            </Button>
            <Button
              className="w-full"
              type="button"
              variant="ghost"
              onClick={() => setMfaToken(null)}
            >
              Back to sign in
            </Button>
          </form>
        </Form>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      key="password-step"
      title="Sign in to CertPing"
      description="Use your local admin credentials to access the CertPing console."
      footer={
        emailEnabled ? (
          <>
            Forgot your password?{" "}
            <Link
              className="underline underline-offset-4"
              href="/forgot-password"
            >
              Reset it by email
            </Link>
            .
          </>
        ) : (
          <>
            Forgot your password? Ask an administrator to reset it, or run{" "}
            <code>certping-admin</code> on the server.
          </>
        )
      }
    >
      {signedOutReason ? <SignedOutNotice reason={signedOutReason} /> : null}
      <Form {...form}>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <FormField
            control={form.control}
            name="identifier"
            render={({ field }) => (
              <FormItem>
                <FormLabel htmlFor="login-identifier">
                  Username or email
                </FormLabel>
                <FormControl>
                  <div className="relative">
                    <UserIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="login-identifier"
                      className="h-11 pl-9"
                      autoComplete="username"
                      placeholder="admin or you@example.com"
                      {...field}
                    />
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel htmlFor="login-password">Password</FormLabel>
                <FormControl>
                  <div className="relative">
                    <LockIcon className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="login-password"
                      className="h-11 pl-9"
                      placeholder="Enter your password"
                      type="password"
                      {...field}
                    />
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button
            className="h-11 w-full"
            disabled={loginMutation.isPending}
            type="submit"
          >
            {loginMutation.isPending ? (
              <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
            ) : null}
            Sign in
          </Button>
        </form>
      </Form>
      {ssoLogin ? (
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="h-px flex-1 bg-border" aria-hidden />
            or
            <span className="h-px flex-1 bg-border" aria-hidden />
          </div>
          <Button asChild variant="outline" className="h-11 w-full">
            {/* A plain navigation: the server starts the OpenID Connect flow and comes back to /auth/callback. */}
            <a href={`${apiBaseUrl()}${ssoLogin.startPath}`}>
              Continue with {ssoLogin.label}
            </a>
          </Button>
        </div>
      ) : null}
    </AuthCardShell>
  );
}
