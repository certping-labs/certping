// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheckIcon, ShieldWarningIcon } from "@phosphor-icons/react";
import { toast } from "sonner";
import { QRCodeSVG } from "qrcode.react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DetailSection } from "@/components/ui/detail-list";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  confirmMfaEnrollment,
  disableMfa,
  getMfaStatus,
  startMfaEnrollment,
  type MfaEnrollment,
} from "@/lib/backend/auth";
import { getApiErrorMessage } from "@/lib/backend/common";

export const MFA_STATUS_QUERY_KEY = ["auth-mfa-status"] as const;

/** Groups a Base32 secret in fours so it can be typed into an app without losing a character. */
export function formatSecretForDisplay(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

/**
 * Two-factor authentication on the Your account tab: enroll an authenticator app, confirm it with a
 * code, keep the recovery codes, or turn it off with the password.
 */
export function MfaSection() {
  const queryClient = useQueryClient();
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [showDisable, setShowDisable] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");

  const statusQuery = useQuery({
    queryKey: MFA_STATUS_QUERY_KEY,
    queryFn: getMfaStatus,
  });

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: MFA_STATUS_QUERY_KEY });

  const enroll = useMutation({
    mutationFn: startMfaEnrollment,
    onSuccess: (data) => {
      setEnrollment(data);
      setConfirmCode("");
      setRecoveryCodes(null);
    },
    onError: (error: unknown) =>
      toast.error(getApiErrorMessage(error, "Could not start enrollment.")),
  });

  const confirm = useMutation({
    mutationFn: confirmMfaEnrollment,
    onSuccess: async (data) => {
      setEnrollment(null);
      setConfirmCode("");
      setRecoveryCodes(data.recoveryCodes);
      toast.success("Two-factor authentication is on.");
      await refresh();
    },
    onError: (error: unknown) =>
      toast.error(getApiErrorMessage(error, "That code was not valid.")),
  });

  const disable = useMutation({
    mutationFn: disableMfa,
    onSuccess: async () => {
      setShowDisable(false);
      setDisablePassword("");
      setRecoveryCodes(null);
      toast.success("Two-factor authentication is off.");
      await refresh();
    },
    onError: (error: unknown) =>
      toast.error(getApiErrorMessage(error, "Could not turn it off.")),
  });

  const status = statusQuery.data;
  const enabled = Boolean(status?.enabled);

  const action = statusQuery.isLoading ? null : enabled ? (
    !showDisable ? (
      <Button variant="outline" size="sm" onClick={() => setShowDisable(true)}>
        Turn off
      </Button>
    ) : null
  ) : !enrollment ? (
    <Button
      variant="outline"
      size="sm"
      disabled={enroll.isPending}
      onClick={() => enroll.mutate()}
    >
      <ShieldCheckIcon aria-hidden />
      Set up authenticator app
    </Button>
  ) : null;

  return (
    <DetailSection
      title="Two-factor authentication"
      className="p-5"
      description="A six-digit code from an authenticator app is asked for after your password. Recommended for every administrator."
      action={action}
    >
      {statusQuery.isLoading ? (
        <Skeleton className="h-5 w-[180px]" />
      ) : statusQuery.isError ? (
        <p className="text-sm text-muted-foreground">
          Could not load the two-factor status.
        </p>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-muted-foreground">Status</span>
            {enabled ? (
              <Badge variant="secondary">On</Badge>
            ) : (
              <Badge variant="outline">Off</Badge>
            )}
            {enabled && status ? (
              <span className="text-muted-foreground">
                {status.recoveryCodesRemaining} recovery{" "}
                {status.recoveryCodesRemaining === 1 ? "code" : "codes"} left
              </span>
            ) : null}
          </div>

          {recoveryCodes ? (
            <Alert>
              <ShieldWarningIcon aria-hidden />
              <AlertTitle>Save your recovery codes now</AlertTitle>
              <AlertDescription>
                <p>
                  Each code signs you in once if you lose your authenticator.
                  They are shown only this once.
                </p>
                <ul
                  className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm"
                  data-testid="mfa-recovery-codes"
                >
                  {recoveryCodes.map((code) => (
                    <li key={code}>{code}</li>
                  ))}
                </ul>
                <Button
                  className="mt-3"
                  size="sm"
                  variant="outline"
                  onClick={() => setRecoveryCodes(null)}
                >
                  I saved them
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}

          {enrollment ? (
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                confirm.mutate({ code: confirmCode });
              }}
            >
              <div className="space-y-2 text-sm">
                <p>
                  Add CertPing to your authenticator app (Google Authenticator,
                  Microsoft Authenticator, 1Password, Bitwarden or any TOTP
                  app). Scan this code, enter the key below it, or open the link
                  on the device that has the app.
                </p>
                <div className="w-fit rounded-md border bg-white p-2">
                  <QRCodeSVG
                    value={enrollment.otpauthUri}
                    size={176}
                    title="Authenticator setup code"
                    data-testid="mfa-qr"
                  />
                </div>
                <p
                  className="rounded-md border bg-muted px-3 py-2 font-mono text-base tracking-wider"
                  data-testid="mfa-secret"
                >
                  {formatSecretForDisplay(enrollment.secret)}
                </p>
                <p className="text-muted-foreground">
                  Time-based, SHA-1, six digits, 30 seconds (the defaults).{" "}
                  <a
                    className="underline underline-offset-4"
                    href={enrollment.otpauthUri}
                  >
                    Open in authenticator app
                  </a>
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="mfa-confirm-code">Code from the app</Label>
                <Input
                  id="mfa-confirm-code"
                  className="max-w-xs font-mono tracking-widest"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  placeholder="123 456"
                  value={confirmCode}
                  onChange={(event) => setConfirmCode(event.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <Button
                  type="submit"
                  disabled={confirm.isPending || confirmCode.trim().length < 6}
                >
                  Turn on
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setEnrollment(null);
                    setConfirmCode("");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : null}

          {showDisable ? (
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                disable.mutate({ password: disablePassword });
              }}
            >
              <p className="text-sm">
                Turning this off makes your password the only thing protecting
                the account. Enter your password to confirm.
              </p>
              <div className="space-y-2">
                <Label htmlFor="mfa-disable-password">Password</Label>
                <Input
                  id="mfa-disable-password"
                  className="max-w-xs"
                  type="password"
                  autoComplete="current-password"
                  value={disablePassword}
                  onChange={(event) => setDisablePassword(event.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <Button
                  type="submit"
                  variant="destructive"
                  disabled={disable.isPending || disablePassword.length === 0}
                >
                  Turn off two-factor authentication
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowDisable(false);
                    setDisablePassword("");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          ) : null}
        </div>
      )}
    </DetailSection>
  );
}
