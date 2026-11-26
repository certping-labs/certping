// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { CREDENTIALS_QUERY_KEY } from "@/hooks/credentials";
import { useTriggerDiscovery } from "@/hooks/discovery";
import { createDiscoveryCredentialReference } from "@/lib/backend/credentials";
import { getErrorMessage } from "@/lib/utils";

const DEFAULT_MEMBER_ROLE = "CertPingDiscoveryReadOnly";

type AuthMode = "INSTANCE_PROFILE" | "ASSUME_ROLE";

/** Splits "a, b c" into ["a", "b", "c"]. */
export function splitList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export interface AwsOrganizationForm {
  name: string;
  authMode: AuthMode;
  roleArn: string;
  region: string;
  memberRoleName: string;
  externalId: string;
  accountIds: string;
  regions: string;
}

/** Builds the discovery credential scope the agent reads. Empty optional fields are left out. */
export function buildAwsOrganizationConfig(
  form: AwsOrganizationForm,
): Record<string, unknown> {
  const config: Record<string, unknown> = {
    authMode: form.authMode,
    region: form.region.trim() || "us-east-1",
    memberRoleName: form.memberRoleName.trim() || DEFAULT_MEMBER_ROLE,
  };
  if (form.authMode === "ASSUME_ROLE") config.roleArn = form.roleArn.trim();
  if (form.externalId.trim()) config.externalId = form.externalId.trim();
  const accountIds = splitList(form.accountIds);
  if (accountIds.length > 0) config.accountIds = accountIds;
  const regions = splitList(form.regions);
  if (regions.length > 0) config.regions = regions;
  return config;
}

const EMPTY_FORM: AwsOrganizationForm = {
  name: "AWS",
  authMode: "INSTANCE_PROFILE",
  roleArn: "",
  region: "us-east-1",
  memberRoleName: DEFAULT_MEMBER_ROLE,
  externalId: "",
  accountIds: "",
  regions: "",
};

export function ConnectAwsOrganizationDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const triggerDiscovery = useTriggerDiscovery();
  const [form, setForm] = useState<AwsOrganizationForm>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const set =
    (field: keyof AwsOrganizationForm) =>
    (event: React.ChangeEvent<HTMLInputElement>) =>
      setForm((current) => ({ ...current, [field]: event.target.value }));

  const needsRole = form.authMode === "ASSUME_ROLE";
  const canSave =
    form.name.trim().length > 0 &&
    (!needsRole || form.roleArn.trim().length > 0);

  const handleConnect = async () => {
    setSaving(true);
    try {
      const credential = await createDiscoveryCredentialReference({
        provider: "AWS_ORGANIZATION",
        description: form.name.trim(),
        configJson: buildAwsOrganizationConfig(form),
      });
      void queryClient.invalidateQueries({ queryKey: CREDENTIALS_QUERY_KEY });
      await triggerDiscovery.mutateAsync({
        targetType: "AWS_ORGANIZATION",
        credentialXref: credential.credentialXref,
      });
      setForm(EMPTY_FORM);
      onOpenChange(false);
    } catch (error) {
      toast.error(getErrorMessage(error, "Could not connect AWS"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Connect AWS</DialogTitle>
          <DialogDescription>
            Read-only. CertPing finds ACM certificates in every enabled region
            of the agent&apos;s AWS account. If the agent can list your AWS
            Organization, it scans every account too. It cannot change anything.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="aws-org-name">Name</Label>
            <Input id="aws-org-name" value={form.name} onChange={set("name")} />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="aws-org-auth">How the agent signs in</Label>
            <Select
              value={form.authMode}
              onValueChange={(value) =>
                setForm((current) => ({
                  ...current,
                  authMode: value as AuthMode,
                }))
              }
            >
              <SelectTrigger id="aws-org-auth">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="INSTANCE_PROFILE">
                  The agent&apos;s own AWS identity
                </SelectItem>
                <SelectItem value="ASSUME_ROLE">Assume a hub role</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {needsRole ? (
            <div className="space-y-1.5">
              <Label htmlFor="aws-org-role">Hub role ARN</Label>
              <Input
                id="aws-org-role"
                placeholder="arn:aws:iam::111111111111:role/CertPingDiscoveryHub"
                value={form.roleArn}
                onChange={set("roleArn")}
              />
            </div>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="aws-org-member-role">
                Role in other accounts
              </Label>
              <Input
                id="aws-org-member-role"
                value={form.memberRoleName}
                onChange={set("memberRoleName")}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="aws-org-external-id">
                External ID (optional)
              </Label>
              <Input
                id="aws-org-external-id"
                value={form.externalId}
                onChange={set("externalId")}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="aws-org-region">Home region</Label>
              <Input
                id="aws-org-region"
                value={form.region}
                onChange={set("region")}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="aws-org-regions">
                Only these regions (optional)
              </Label>
              <Input
                id="aws-org-regions"
                placeholder="All enabled regions"
                value={form.regions}
                onChange={set("regions")}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="aws-org-accounts">
              Only these accounts (optional)
            </Label>
            <Input
              id="aws-org-accounts"
              placeholder="All active accounts in the organization"
              value={form.accountIds}
              onChange={set("accountIds")}
            />
          </div>

          <p className="text-xs text-muted-foreground">
            One account needs no extra setup beyond read access to ACM. For a
            whole organization, set up the roles with the templates in
            deploy/discovery/aws.
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleConnect}
            disabled={!canSave || saving}
            isPending={saving}
          >
            Connect and scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
