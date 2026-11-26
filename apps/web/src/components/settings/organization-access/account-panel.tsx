// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  CheckCircleIcon,
  EyeIcon,
  EyeSlashIcon,
  LockIcon,
} from "@phosphor-icons/react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  DetailItem,
  DetailList,
  DetailSection,
} from "@/components/ui/detail-list";
import { PageHeader } from "@/components/ui/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, PasswordError, validatePasswordStrenght } from "@/lib/utils";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { changePassword, getCurrentUser } from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";
import { useAuth } from "@/hooks/use-auth";
import { useAuthStore } from "@/stores/auth-store";
import { shouldRequirePasswordChange } from "@/lib/post-auth";
import { MfaSection } from "./mfa-section";

const formatLabel = (value?: string | null) => {
  if (!value) return "Missing";
  return value
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
};

const SUPER_ADMIN_LABEL = "Super Admin";
const PASSWORD_UPDATE_SUCCESS_MESSAGE =
  "Password updated successfully. Use your new password the next time you sign in.";

/** The Your account tab: profile, sign-in method and password. */
export function AccountPanel() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const securitySettingsRef = useRef<HTMLElement | null>(null);
  const [passwordData, setPasswordData] = useState({
    currentPassword: "",
    newPassword: "",
    confirmNewPassword: "",
  });
  const {
    user,
    accessToken,
    isSuperAdmin,
    isLoading: isLoadingUser,
  } = useAuth();
  const queryClient = useQueryClient();
  const [error, setError] = useState<PasswordError | null>(null);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [passwordSuccessMessage, setPasswordSuccessMessage] = useState<
    string | null
  >(null);
  const canChangePassword =
    user?.authMethod === "LOCAL" || Boolean(isSuperAdmin);
  const currentUserQuery = useQuery({
    queryKey: ["auth-current-user", accessToken],
    enabled: Boolean(accessToken) && !isLoadingUser,
    queryFn: async () => getCurrentUser(accessToken ?? ""),
    staleTime: 60_000,
  });
  const hasPasswordChangeRequest =
    shouldRequirePasswordChange(user, Boolean(isSuperAdmin)) ||
    Boolean(currentUserQuery.data?.mustChangePassword) ||
    searchParams.get("changePassword") === "true";
  const mustChangePassword =
    hasPasswordChangeRequest &&
    (!isSuperAdmin || Boolean(user?.organizationId));
  const isAccountLoading =
    isLoadingUser ||
    (Boolean(accessToken) &&
      currentUserQuery.fetchStatus !== "idle" &&
      !currentUserQuery.data);

  const accountEmail = currentUserQuery.data?.email ?? user?.email ?? "Missing";
  const accountOrganizationName =
    currentUserQuery.data?.organizationName ?? user?.organizationName ?? null;
  const accountAuthMethod = user?.authMethod ?? null;
  const accountRoles = useMemo(() => {
    const roles = (currentUserQuery.data?.roles ?? user?.roles ?? []).map(
      (role) => formatLabel(role),
    );

    if (isSuperAdmin && !roles.includes(SUPER_ADMIN_LABEL)) {
      roles.push(SUPER_ADMIN_LABEL);
    }

    return Array.from(new Set(roles));
  }, [currentUserQuery.data?.roles, isSuperAdmin, user?.roles]);

  useEffect(() => {
    if (!canChangePassword || !mustChangePassword) {
      return;
    }

    setShowPasswordForm(true);
    requestAnimationFrame(() => {
      securitySettingsRef.current?.scrollIntoView({
        block: "start",
        behavior: "smooth",
      });
    });
  }, [canChangePassword, mustChangePassword]);

  const updatePassword = useMutation({
    mutationKey: ["change-password"],
    mutationFn: async () =>
      changePassword({
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword,
        confirmPassword: passwordData.confirmNewPassword,
      }),
    async onSuccess() {
      toast.success("Password updated successfully");
      setPasswordSuccessMessage(PASSWORD_UPDATE_SUCCESS_MESSAGE);
      if (user) {
        useAuthStore.getState().setUser({
          ...user,
          mustChangePassword: false,
        });
      }
      // Everything fetched while the change was owed was refused (403) and is
      // still cached: feature flags, two-factor status and the rest.
      await queryClient.invalidateQueries();
      router.replace("/settings/organization-access?tab=account");
      setPasswordData({
        currentPassword: "",
        newPassword: "",
        confirmNewPassword: "",
      });
      setError(null);
      setTimeout(() => {
        toast.dismiss("password-changed");
      }, 3500);
    },
    onError(err) {
      setPasswordSuccessMessage(null);
      toast.error(
        getApiErrorMessage(
          err,
          "We could not update your password. Please try again.",
        ),
      );
    },
  });
  const handlePasswordChange = () => {
    if (!canChangePassword) {
      setPasswordSuccessMessage(null);
      toast.error(
        "Your authentication method does not allow password changes",
        { duration: 8000 },
      );
      return;
    }
    if (passwordData.newPassword === passwordData.currentPassword) {
      setPasswordSuccessMessage(null);
      toast.error("New Password can not be same as current password");
      return;
    }
    if (passwordData.newPassword !== passwordData.confirmNewPassword) {
      setPasswordSuccessMessage(null);
      toast.error("Passwords do not match");
      return;
    }
    if (
      validatePasswordStrenght({ value: passwordData.newPassword, setError })
    ) {
      updatePassword.mutate();
    }
    return;
  };

  const resetPasswordForm = () => {
    setShowPasswordForm(false);
    setPasswordSuccessMessage(null);
    setPasswordData({
      currentPassword: "",
      newPassword: "",
      confirmNewPassword: "",
    });
    setError(null);
  };

  return (
    <div className="w-full space-y-5">
      <PageHeader
        level="section"
        title="Your account"
        subtitle="Who you are signed in as, your password and your second factor."
      />

      <section
        ref={securitySettingsRef}
        className="rounded-xl border border-border bg-card"
      >
        <DetailSection title="Profile" className="p-5">
          {isAccountLoading ? (
            <AccountSkeleton />
          ) : (
            <DetailList>
              <DetailItem label="Email">{accountEmail}</DetailItem>
              <DetailItem label="Sign-in">
                {accountAuthMethod === "LOCAL"
                  ? "Password"
                  : formatLabel(accountAuthMethod)}
              </DetailItem>
              <DetailItem label="Organization">
                {accountOrganizationName ||
                  (isSuperAdmin ? "Global platform access" : "Missing")}
              </DetailItem>
              <DetailItem label="Roles">
                {accountRoles.length > 0 ? (
                  <span className="flex flex-wrap gap-1.5">
                    {accountRoles.map((role) => (
                      <Badge key={role} variant="secondary" textOnly>
                        {role}
                      </Badge>
                    ))}
                  </span>
                ) : (
                  "Missing"
                )}
              </DetailItem>
            </DetailList>
          )}
        </DetailSection>

        <DetailSection
          title="Password"
          className="p-5"
          description={
            canChangePassword
              ? mustChangePassword
                ? "Please update your password before continuing."
                : "Use a long password you don't use anywhere else."
              : "Your sign-in method does not use a CertPing password."
          }
          action={
            canChangePassword && !showPasswordForm ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setPasswordSuccessMessage(null);
                  setShowPasswordForm(true);
                }}
              >
                <LockIcon aria-hidden />
                Change password
              </Button>
            ) : null
          }
        >
          {canChangePassword && passwordSuccessMessage ? (
            <Alert variant="success" className="max-w-xl" role="status">
              <CheckCircleIcon aria-hidden />
              <AlertTitle>Password changed</AlertTitle>
              <AlertDescription>{passwordSuccessMessage}</AlertDescription>
            </Alert>
          ) : null}

          {canChangePassword && showPasswordForm ? (
            <form
              className="grid max-w-md gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                handlePasswordChange();
              }}
            >
              <PasswordInput
                id="current-password"
                label="Current password"
                value={passwordData.currentPassword}
                onChange={(currentPassword) => {
                  setPasswordSuccessMessage(null);
                  setPasswordData((previous) => ({
                    ...previous,
                    currentPassword,
                  }));
                }}
              />
              <PasswordInput
                id="new-password"
                label="New password"
                value={passwordData.newPassword}
                invalid={Boolean(error?.message)}
                onChange={(newPassword) => {
                  setPasswordSuccessMessage(null);
                  setPasswordData((previous) => ({ ...previous, newPassword }));
                  validatePasswordStrenght({ value: newPassword, setError });
                }}
              />
              <PasswordInput
                id="confirm-password"
                label="Confirm new password"
                value={passwordData.confirmNewPassword}
                onChange={(confirmNewPassword) => {
                  setPasswordSuccessMessage(null);
                  setPasswordData((previous) => ({
                    ...previous,
                    confirmNewPassword,
                  }));
                }}
              />
              {error ? (
                <div className="space-y-1.5 text-xs">
                  <p className="text-destructive">{error.message}</p>
                  <ul className="space-y-1">
                    {PASSWORD_RULES.map((rule) => (
                      <li
                        key={rule.key}
                        className={cn(
                          "flex items-center gap-1.5",
                          error.checks[rule.key]
                            ? "status-success-text"
                            : "text-muted-foreground",
                        )}
                      >
                        <CheckCircleIcon className="size-3.5" aria-hidden />
                        {rule.label}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <div className="flex gap-2">
                <Button
                  type="submit"
                  disabled={updatePassword.isPending}
                  isPending={updatePassword.isPending}
                >
                  Update password
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={resetPasswordForm}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : null}
        </DetailSection>

        {canChangePassword ? <MfaSection /> : null}
      </section>
    </div>
  );
}

const PASSWORD_RULES: { key: keyof PasswordError["checks"]; label: string }[] =
  [
    { key: "length", label: "At least 12 characters" },
    { key: "uppercase", label: "One uppercase letter" },
    { key: "lowercase", label: "One lowercase letter" },
    { key: "number", label: "One number" },
    { key: "special", label: "One special character (@$!%*?&)" },
  ];

function PasswordInput({
  id,
  label,
  value,
  onChange,
  invalid,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  invalid?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Input
          id={id}
          type={visible ? "text" : "password"}
          autoComplete={
            id === "current-password" ? "current-password" : "new-password"
          }
          value={value}
          aria-invalid={invalid || undefined}
          onChange={(event) => onChange(event.target.value)}
          className="pr-11"
        />
        <Button
          type="button"
          variant="ghost"
          size="iconSm"
          className="absolute top-1/2 right-1 -translate-y-1/2 text-muted-foreground"
          aria-label={
            visible
              ? `Hide ${label.toLowerCase()}`
              : `Show ${label.toLowerCase()}`
          }
          aria-pressed={visible}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? <EyeSlashIcon aria-hidden /> : <EyeIcon aria-hidden />}
        </Button>
      </div>
    </div>
  );
}

function AccountSkeleton() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-4 w-[150px]" />
      <Skeleton className="h-6 w-[200px]" />
    </div>
  );
}
