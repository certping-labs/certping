// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useRouter } from "next/navigation";
import React, { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";

import { AuthCardShell } from "@/components/auth/auth-card-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { completeFirstRunSetup, getSetupStatus } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";

export const SETUP_STATUS_QUERY_KEY = ["auth", "setup-status"] as const;

const MIN_PASSWORD_LENGTH = 12;

/**
 * First-run setup: creates the first Platform Super Admin on a fresh
 * installation. The server only answers while no user exists, so this page
 * sends everyone else to sign in. No account or password is built in.
 */
export function SetupForm() {
  const router = useRouter();
  const status = useQuery({
    queryKey: SETUP_STATUS_QUERY_KEY,
    queryFn: getSetupStatus,
    retry: 1,
    staleTime: 0,
  });
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const [serverError, setServerError] = useState<string | null>(null);

  const setupRequired = status.data?.setupRequired;

  useEffect(() => {
    if (setupRequired === false) {
      router.replace("/login");
    }
  }, [router, setupRequired]);

  const mutation = useMutation({
    mutationFn: completeFirstRunSetup,
    onSuccess: (result) => {
      toast.success(
        result.message || "Platform Super Admin created. You can sign in now.",
      );
      router.replace("/login?setup=done");
    },
    onError: (error: unknown) => {
      setServerError(
        getApiErrorMessage(
          error,
          "Setup failed. Check the details and try again.",
        ),
      );
    },
  });

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    setLocalError(null);
    setServerError(null);
    if (password.length < MIN_PASSWORD_LENGTH) {
      setLocalError(
        `Use at least ${MIN_PASSWORD_LENGTH} characters for the password.`,
      );
      return;
    }
    if (password !== confirmPassword) {
      setLocalError("The two passwords do not match.");
      return;
    }
    mutation.mutate({
      displayName: displayName.trim() || undefined,
      username: username.trim(),
      email: email.trim(),
      password,
    });
  };

  if (status.isLoading || setupRequired === false) {
    return (
      <AuthCardShell
        eyebrow="First run"
        title="Checking this installation"
        description="One moment."
      >
        <p className="text-sm text-muted-foreground" role="status">
          Checking whether setup is still needed...
        </p>
      </AuthCardShell>
    );
  }

  if (status.isError) {
    return (
      <AuthCardShell
        eyebrow="First run"
        title="CertPing server not reachable"
        description="The web app could not ask the server whether setup is needed."
      >
        <p className="text-sm text-muted-foreground" role="alert">
          Check that the server is running and that the web app points at it,
          then reload this page.
        </p>
      </AuthCardShell>
    );
  }

  const error = localError ?? serverError;

  return (
    <AuthCardShell
      eyebrow="First run"
      title="Create the first Platform Super Admin"
      description="This account administers the whole installation: organizations, members and platform settings. It is created once; afterwards administrators invite everyone else."
    >
      <form
        onSubmit={handleSubmit}
        className="space-y-5"
        aria-label="First-run setup"
      >
        <div className="space-y-2">
          <Label htmlFor="displayName">Display name</Label>
          <Input
            id="displayName"
            autoComplete="name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Platform administrator"
            className="h-11"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            minLength={3}
            maxLength={50}
            className="h-11"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="h-11"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={MIN_PASSWORD_LENGTH}
            className="h-11"
          />
          <p className="text-xs text-muted-foreground">
            At least {MIN_PASSWORD_LENGTH} characters. Use a password manager;
            this password is not recoverable without a working mail setup.
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="confirmPassword">Confirm password</Label>
          <Input
            id="confirmPassword"
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            className="h-11"
          />
        </div>

        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}

        <Button
          type="submit"
          className="h-11 w-full font-semibold"
          disabled={mutation.isPending}
          isPending={mutation.isPending}
          loadingtext="Creating the account..."
        >
          Create Platform Super Admin
        </Button>
      </form>
    </AuthCardShell>
  );
}
