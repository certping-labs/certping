// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import Link from "next/link";
import React, { useState } from "react";
import { CheckIcon, CircleNotchIcon, CopyIcon } from "@phosphor-icons/react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  useAgentTokens,
  useCreateAgentToken,
  useRevokeAgentToken,
} from "@/hooks/agent-tokens";
import {
  AGENT_TOKEN_EXPIRY_OPTIONS,
  isAgentTokenExpired,
  type CreatedAgentToken,
} from "@/lib/backend/agent-tokens";
import { formatDate } from "@/lib/utils";

/** The confirmation shown before an agent token is revoked, here and on the Agents page. */
export const revokeAgentConfirmMessage = (tokenName: string) =>
  `Revoke "${tokenName}"? The agent using it stops connecting.`;

/** Asks before an agent token is revoked; open while `tokenName` is set. */
export function RevokeAgentTokenDialog({
  tokenName,
  onCancel,
  onConfirm,
}: {
  tokenName: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog
      open={tokenName !== null}
      onOpenChange={(open) => {
        if (!open) onCancel();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke agent token</AlertDialogTitle>
          <AlertDialogDescription>
            {tokenName !== null ? revokeAgentConfirmMessage(tokenName) : null}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={onConfirm}>
            Revoke
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Could not copy to the clipboard");
    }
  };
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">
          {label}
        </span>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5"
          onClick={copy}
          aria-label={`Copy ${label}`}
        >
          {copied ? (
            <CheckIcon className="h-4 w-4 text-success" />
          ) : (
            <CopyIcon className="h-4 w-4" />
          )}
          <span>{copied ? "Copied" : "Copy"}</span>
        </Button>
      </div>
      <pre className="overflow-x-auto rounded border border-border bg-muted p-2 font-mono text-xs break-all whitespace-pre-wrap">
        {value}
      </pre>
    </div>
  );
}

/**
 * "Add agent" for deployments whose agents connect over HTTPS: creates a token, shows it with
 * the command that starts an agent, and lists and revokes existing tokens.
 */
export function AgentTokensCard({
  organizationId,
  canManage,
}: {
  organizationId?: string | number | null;
  canManage: boolean;
}) {
  const {
    data: tokens,
    isLoading,
    error,
  } = useAgentTokens(organizationId, {
    enabled: canManage,
  });
  const createToken = useCreateAgentToken(organizationId);
  const revokeToken = useRevokeAgentToken(organizationId);
  const [name, setName] = useState("");
  // "" is Never; otherwise the number of days as a string.
  const [expiresIn, setExpiresIn] = useState("");
  const [created, setCreated] = useState<CreatedAgentToken | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<{
    id: number;
    name: string;
  } | null>(null);

  const serverUrl = typeof window === "undefined" ? "" : window.location.origin;

  const handleCreate = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      const expiresInDays = expiresIn ? Number(expiresIn) : undefined;
      const result = await createToken.mutateAsync({
        name: name.trim() || "agent",
        serverUrl,
        ...(expiresInDays ? { expiresInDays } : {}),
      });
      setCreated(result);
      setName("");
      setExpiresIn("");
    } catch {
      toast.error("Could not create the agent token");
    }
  };

  const handleRevoke = async () => {
    if (pendingRevoke === null) return;
    const tokenId = pendingRevoke.id;
    setPendingRevoke(null);
    try {
      await revokeToken.mutateAsync(tokenId);
      toast.success("Agent token revoked");
    } catch {
      toast.error("Could not revoke the agent token");
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <CardTitle>Agents</CardTitle>
          <Link
            href="/agents"
            className="shrink-0 text-sm font-medium text-brand hover:underline"
          >
            Manage agents
          </Link>
        </div>
        <CardDescription>
          Agents run in your network and connect to CertPing over outbound
          HTTPS. Each one needs its own token.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {canManage && (
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={handleCreate}
          >
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Agent name, for example datacenter-east"
              maxLength={100}
              aria-label="Agent name"
              className="h-9"
            />
            <label className="flex shrink-0 items-center gap-2 text-sm text-muted-foreground">
              Expires after
              <select
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
                aria-label="Expires after"
                className="h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground"
              >
                {AGENT_TOKEN_EXPIRY_OPTIONS.map((option) => (
                  <option key={option.label} value={option.days ?? ""}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <Button
              type="submit"
              size="sm"
              className="h-9 shrink-0"
              disabled={createToken.isPending}
            >
              {createToken.isPending ? (
                <CircleNotchIcon className="h-4 w-4 animate-spin" />
              ) : (
                "Add agent"
              )}
            </Button>
          </form>
        )}

        {created && (
          <div className="space-y-3 rounded border border-warning bg-warning/10 p-3">
            <p className="text-sm font-medium">
              Copy this token now. It is shown only once.
            </p>
            <CopyBlock label="Agent token" value={created.value} />
            <CopyBlock
              label="Start the agent with Docker"
              value={created.dockerCommand}
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setCreated(null)}
            >
              Done
            </Button>
          </div>
        )}

        {isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <CircleNotchIcon className="h-4 w-4 animate-spin" />
            Loading agents...
          </div>
        ) : error ? (
          <p className="text-sm text-destructive">
            Could not load agent tokens.
          </p>
        ) : tokens && tokens.length > 0 ? (
          <ul className="divide-y divide-border rounded border border-border">
            {tokens.map((token) => {
              const expired = !token.revokedAt && isAgentTokenExpired(token);
              return (
                <li
                  key={token.id}
                  className="flex items-center justify-between gap-3 p-3 text-sm"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate font-medium">{token.name}</span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {token.tokenPrefix}...
                      </span>
                      {token.revokedAt ? (
                        <Badge variant="secondary">Revoked</Badge>
                      ) : null}
                      {expired ? (
                        <Badge variant="destructive">Expired</Badge>
                      ) : null}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Last seen{" "}
                      {token.lastUsedAt
                        ? formatDate(token.lastUsedAt)
                        : "never"}
                      {" · "}created {formatDate(token.createdAt ?? null)}
                      {" · "}
                      {token.expiresAt
                        ? `${expired ? "expired" : "expires"} ${formatDate(token.expiresAt)}`
                        : "never expires"}
                    </div>
                  </div>
                  {canManage && !token.revokedAt ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setPendingRevoke({ id: token.id, name: token.name })
                      }
                      disabled={revokeToken.isPending}
                    >
                      Revoke
                    </Button>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            No agents yet. The agent bundled with a single-server install
            connects on its own.
          </p>
        )}
      </CardContent>
      <RevokeAgentTokenDialog
        tokenName={pendingRevoke?.name ?? null}
        onCancel={() => setPendingRevoke(null)}
        onConfirm={handleRevoke}
      />
    </Card>
  );
}
