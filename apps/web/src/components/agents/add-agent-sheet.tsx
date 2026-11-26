// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";
import { CircleNotchIcon } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { CopyBlock } from "@/components/settings/organizations/agent-tokens-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCreateAgentToken } from "@/hooks/agent-tokens";
import { AGENTS_QUERY_KEY } from "@/hooks/agents";
import {
  AGENT_TOKEN_EXPIRY_OPTIONS,
  type CreatedAgentToken,
} from "@/lib/backend/agent-tokens";
import {
  AGENT_DOCS,
  AGENT_SECRET_STORE_CHOICES,
  agentImageTag,
  buildDockerCommand,
  buildHelmCommand,
  type RemoteAgentSecretStore,
} from "@/lib/backend/agents";

export function AddAgentSheet({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const createToken = useCreateAgentToken();
  const [name, setName] = useState("");
  // "" is Never; otherwise the number of days as a string.
  const [expiresIn, setExpiresIn] = useState("");
  const [store, setStore] = useState<RemoteAgentSecretStore>(
    "AWS_SECRETS_MANAGER",
  );
  const [created, setCreated] = useState<CreatedAgentToken | null>(null);

  const serverUrl = typeof window === "undefined" ? "" : window.location.origin;

  const close = (next: boolean) => {
    if (!next) {
      // The token is shown once: closing the panel forgets it.
      setCreated(null);
      setName("");
      setExpiresIn("");
      setStore("AWS_SECRETS_MANAGER");
    }
    onOpenChange(next);
  };

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
      await queryClient.invalidateQueries({ queryKey: AGENTS_QUERY_KEY });
    } catch {
      toast.error("Could not create the agent token");
    }
  };

  // The server's own command names Azure Key Vault; the commands are built for the chosen
  // store instead, on the image tag of the server's release.
  const commandInput = created
    ? {
        store,
        serverUrl,
        token: created.value,
        imageTag: agentImageTag(created.dockerCommand),
      }
    : null;
  const dockerCommand = commandInput ? buildDockerCommand(commandInput) : "";
  const helmCommand = commandInput ? buildHelmCommand(commandInput) : "";

  return (
    <Sheet open={open} onOpenChange={close}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader className="space-y-2 pr-8 text-left">
          <SheetTitle>Add agent</SheetTitle>
          <SheetDescription>
            Each agent gets its own token. Run the agent in the network where
            your certificates live.
          </SheetDescription>
        </SheetHeader>

        {created ? (
          <div className="mt-6 space-y-4">
            <div className="space-y-3 rounded border border-warning bg-warning/10 p-3">
              <p className="text-sm font-medium">
                Copy this token now. It is shown only once.
              </p>
              <CopyBlock label="Agent token" value={created.value} />
            </div>

            <Tabs defaultValue="docker" className="space-y-3">
              <TabsList>
                <TabsTrigger value="docker">Docker</TabsTrigger>
                <TabsTrigger value="kubernetes">Kubernetes</TabsTrigger>
              </TabsList>
              <TabsContent value="docker">
                <CopyBlock
                  label="Start the agent with Docker"
                  value={dockerCommand}
                />
              </TabsContent>
              <TabsContent value="kubernetes">
                <CopyBlock
                  label="Install the agent with Helm"
                  value={helmCommand}
                />
              </TabsContent>
            </Tabs>

            <p className="text-sm text-muted-foreground">
              The agent connects to this server over outbound HTTPS. It accepts
              inbound connections only if you turn on SCEP for devices.
            </p>
            <p className="text-sm text-muted-foreground">
              Replace the values in angle brackets with your own. See{" "}
              <a
                href={AGENT_DOCS.agents}
                target="_blank"
                rel="noreferrer"
                className="text-brand underline-offset-2 hover:underline"
              >
                the agent docs
              </a>
              .
            </p>
            <Button type="button" size="sm" onClick={() => close(false)}>
              Done
            </Button>
          </div>
        ) : (
          <form className="mt-6 space-y-4" onSubmit={handleCreate}>
            <div className="space-y-1.5">
              <Label htmlFor="add-agent-name">Name</Label>
              <Input
                id="add-agent-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="For example datacenter-east"
                maxLength={100}
              />
            </div>
            <fieldset className="space-y-1.5">
              <legend className="text-sm font-medium">
                Where should this agent keep keys?
              </legend>
              {AGENT_SECRET_STORE_CHOICES.map((choice) => (
                <label
                  key={choice.value}
                  className="flex items-center gap-2 text-sm"
                >
                  <input
                    type="radio"
                    name="add-agent-store"
                    value={choice.value}
                    checked={store === choice.value}
                    onChange={() => setStore(choice.value)}
                  />
                  {choice.label}
                </label>
              ))}
              <p className="text-xs text-muted-foreground">
                Remote agents keep keys in your cloud secret manager. Local
                encrypted files are used only by the agent bundled with the
                server.
              </p>
              <p className="text-xs text-muted-foreground">
                The agent signs in with its cloud identity. No cloud secret is
                entered here.
              </p>
            </fieldset>
            <div className="space-y-1.5">
              <Label htmlFor="add-agent-expiry">Token expires after</Label>
              <select
                id="add-agent-expiry"
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm text-foreground"
              >
                {AGENT_TOKEN_EXPIRY_OPTIONS.map((option) => (
                  <option key={option.label} value={option.days ?? ""}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <Button type="submit" size="sm" disabled={createToken.isPending}>
              {createToken.isPending ? (
                <CircleNotchIcon className="h-4 w-4 animate-spin" />
              ) : null}
              Create token
            </Button>
          </form>
        )}
      </SheetContent>
    </Sheet>
  );
}
