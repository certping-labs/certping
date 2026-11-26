// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { WarningCircleIcon } from "@phosphor-icons/react/dist/ssr";

import type { SignedOutReason } from "@/lib/signed-out-reason";

const NOTICES: Record<SignedOutReason, { title: string; detail: string }> = {
  "account-disabled": {
    title: "Your account is disabled",
    detail:
      "You were signed out because this account is disabled or deleted. Ask an organization admin or the people who run this CertPing installation to restore it.",
  },
  "organization-suspended": {
    title: "Your organization is suspended",
    detail:
      "You were signed out because your organization is suspended or inactive. Contact the people who run this CertPing installation to restore access.",
  },
};

interface SignedOutNoticeProps {
  reason: SignedOutReason;
}

export function SignedOutNotice({ reason }: SignedOutNoticeProps) {
  const { title, detail } = NOTICES[reason];
  return (
    <div
      role="alert"
      className="mb-5 flex gap-3 rounded-(--certping-radius-md) border border-destructive/50 bg-destructive/10 p-3 text-sm leading-6"
    >
      <WarningCircleIcon
        aria-hidden="true"
        className="mt-1 h-4 w-4 shrink-0 text-destructive"
      />
      <div className="min-w-0">
        <p className="font-semibold text-foreground">{title}</p>
        <p className="text-muted-foreground">{detail}</p>
      </div>
    </div>
  );
}
