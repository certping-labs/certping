// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { EyeIcon, EyeClosedIcon, LockIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import { AuthCardShell } from "@/components/auth/auth-card-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { resetPasswordWithToken } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";
import { logger } from "@/lib/logger/logger.service";

interface PasswordFieldProps {
  id: string;
  label: string;
  value: string;
  isVisible: boolean;
  onChange: (value: string) => void;
  onVisibilityChange: () => void;
}

function PasswordField({
  id,
  label,
  value,
  isVisible,
  onChange,
  onVisibilityChange,
}: PasswordFieldProps) {
  const VisibilityIcon = isVisible ? EyeClosedIcon : EyeIcon;

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <LockIcon
          aria-hidden="true"
          className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          autoComplete="new-password"
          className="h-11 pr-11 pl-10"
          id={id}
          onChange={(event) => onChange(event.target.value)}
          required
          type={isVisible ? "text" : "password"}
          value={value}
        />
        <Button
          aria-label={isVisible ? `Hide ${label}` : `Show ${label}`}
          className="absolute top-1/2 right-1 -translate-y-1/2"
          size="icon"
          onClick={onVisibilityChange}
          type="button"
          variant="ghost"
        >
          <VisibilityIcon aria-hidden="true" className="size-4" />
        </Button>
      </div>
    </div>
  );
}

export default function ResetPassword() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isPasswordVisible, setIsPasswordVisible] = useState(false);
  const [isConfirmationVisible, setIsConfirmationVisible] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");

  const mutation = useMutation({
    mutationKey: ["reset-password"],
    mutationFn: async () => {
      if (!token) throw new Error("The reset link is missing its token.");
      if (password !== confirmPassword) {
        throw new Error("The passwords do not match.");
      }
      return resetPasswordWithToken(token, {
        newPassword: password,
        confirmPassword,
      });
    },
    onSuccess: (response) => {
      toast.success(response.message || "Password reset successful.");
      logger.info("Password reset successful", {
        eventName: "auth.password_reset.completed",
      });
      router.push("/login");
    },
    onError: (error) => {
      const message =
        error instanceof Error
          ? error.message
          : getApiErrorMessage(error, "The password could not be reset.");
      toast.error(message);
      logger.error("Password reset failed", {
        eventName: "auth.password_reset.exception",
        message,
        error,
      });
    },
  });

  if (!token) {
    return (
      <AuthCardShell
        eyebrow="Account recovery"
        title="This reset link is not valid"
        description="The link is incomplete or has expired. Request a new reset email to continue."
        footer={
          <Link className="certping-auth-link font-semibold" href="/login">
            Return to sign in
          </Link>
        }
      >
        <Button asChild className="h-11 w-full">
          <Link href="/forgot-password">Request a new reset link</Link>
        </Button>
      </AuthCardShell>
    );
  }

  return (
    <AuthCardShell
      eyebrow="Account recovery"
      title="Choose a new password"
      description="Use a unique password for your CertPing workspace and confirm it below."
      footer={
        <Link className="certping-auth-link font-semibold" href="/login">
          Return to sign in
        </Link>
      }
    >
      <form
        className="space-y-5"
        onSubmit={(event) => {
          event.preventDefault();
          mutation.mutate();
        }}
      >
        <PasswordField
          id="password"
          isVisible={isPasswordVisible}
          label="New password"
          onChange={setPassword}
          onVisibilityChange={() =>
            setIsPasswordVisible((isVisible) => !isVisible)
          }
          value={password}
        />
        <PasswordField
          id="confirm-password"
          isVisible={isConfirmationVisible}
          label="Confirm new password"
          onChange={setConfirmPassword}
          onVisibilityChange={() =>
            setIsConfirmationVisible((isVisible) => !isVisible)
          }
          value={confirmPassword}
        />
        <Button
          className="h-11 w-full font-semibold"
          disabled={mutation.isPending}
          isPending={mutation.isPending}
          loadingtext="Resetting password..."
          type="submit"
        >
          Reset password
        </Button>
      </form>
    </AuthCardShell>
  );
}
