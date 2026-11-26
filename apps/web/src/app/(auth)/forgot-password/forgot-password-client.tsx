// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EnvelopeIcon } from "@phosphor-icons/react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { logger } from "@/lib/logger/logger.service";
import Link from "next/link";
import { requestPasswordReset } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";
import { AuthCardShell } from "@/components/auth/auth-card-shell";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");

  const mutation = useMutation({
    mutationKey: ["forgot-password"],
    mutationFn: async () =>
      requestPasswordReset({ email: email.toLowerCase() }),
    onSuccess: (data) => {
      toast.success("Success", {
        description: data.message || "Password reset link sent to your email",
        duration: Infinity,
        dismissible: true,
        closeButton: true,
      });
      logger.info("Forgot password request accepted", {
        eventName: "auth.password_reset.requested",
        email,
      });
    },
    onError: (err) => {
      const errorMessage = getApiErrorMessage(
        err,
        "Something went wrong! Try again.",
      );
      toast.error(errorMessage);
      logger.error("Forgot password failed", {
        eventName: "auth.password_reset.exception",
        message: errorMessage,
        email,
        error: err,
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };

  return (
    <AuthCardShell
      eyebrow="Account recovery"
      title="Reset your password"
      description="Enter the email attached to your workspace. We’ll send a time-limited reset link if the account is eligible."
      footer={
        <Link href="/login" className="certping-auth-link font-semibold">
          Return to sign in
        </Link>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="email" className="text-sm font-medium">
            Work email
          </Label>
          <div className="relative">
            <Input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              className="h-11 pl-10"
            />
            <EnvelopeIcon
              aria-hidden="true"
              className="absolute top-1/2 left-3 -translate-y-1/2 text-muted-foreground"
              size={16}
            />
          </div>
        </div>

        <Button
          type="submit"
          className="h-11 w-full font-semibold"
          disabled={mutation.isPending}
          isPending={mutation.isPending}
          loadingtext="Sending reset link..."
        >
          Send reset link
        </Button>
      </form>
    </AuthCardShell>
  );
}
