// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useState } from "react";

import { DigiCertApiKeyInput } from "@/components/cert-manager/digicert-api-key-field";
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
  caKeyDeleteErrorMessage,
  useAddCaCredential,
  useDeleteCaCredential,
  useReplaceCaCredentialKey,
} from "@/hooks/ca-credentials";
import type { CertificateAuthorityCredential } from "@/lib/backend/certificate-authorities";
import { formatDate } from "@/lib/utils";

const PROVIDER = "DIGICERT";

export interface DigiCertKeyPermissions {
  canAdd: boolean;
  canReplace: boolean;
  canDelete: boolean;
}

type OpenDialog =
  | { kind: "add" }
  | { kind: "replace"; key: CertificateAuthorityCredential }
  | { kind: "delete"; key: CertificateAuthorityCredential }
  | null;

/** Saved DigiCert API keys: metadata only, with add, replace and delete. */
export function DigiCertKeys({
  credentials,
  permissions,
}: {
  credentials: CertificateAuthorityCredential[];
  permissions: DigiCertKeyPermissions;
}) {
  const [open, setOpen] = useState<OpenDialog>(null);
  const close = () => setOpen(null);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-sm font-medium text-foreground">Saved keys</h4>
        {permissions.canAdd ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setOpen({ kind: "add" })}
          >
            Add key
          </Button>
        ) : null}
      </div>

      {credentials.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No DigiCert key saved yet.
        </p>
      ) : (
        <ul className="divide-y divide-border rounded-md border border-border">
          {credentials.map((key) => (
            <li
              key={key.credentialXref}
              className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-foreground">
                  {key.description || key.credentialXref}
                </p>
                <p className="text-xs text-muted-foreground">
                  Added {formatDate(key.createdAt)} · Updated{" "}
                  {formatDate(key.updatedAt)}
                </p>
              </div>
              {permissions.canReplace || permissions.canDelete ? (
                <div className="flex shrink-0 gap-2">
                  {permissions.canReplace ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      aria-label={`Replace key ${key.description}`}
                      onClick={() => setOpen({ kind: "replace", key })}
                    >
                      Replace key
                    </Button>
                  ) : null}
                  {permissions.canDelete ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      aria-label={`Delete key ${key.description}`}
                      onClick={() => setOpen({ kind: "delete", key })}
                    >
                      Delete
                    </Button>
                  ) : null}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      <p className="text-xs text-muted-foreground">
        Keys are write-only. After you save a key, CertPing shows only its name
        and dates.
      </p>

      {open?.kind === "add" ? <AddKeyDialog onClose={close} /> : null}
      {open?.kind === "replace" ? (
        <ReplaceKeyDialog keyInfo={open.key} onClose={close} />
      ) : null}
      {open?.kind === "delete" ? (
        <DeleteKeyDialog keyInfo={open.key} onClose={close} />
      ) : null}
    </div>
  );
}

function AddKeyDialog({ onClose }: { onClose: () => void }) {
  const addKey = useAddCaCredential(PROVIDER);
  const [description, setDescription] = useState("");
  const [apiKey, setApiKey] = useState("");
  const canSave = description.trim() !== "" && apiKey.trim() !== "";

  const save = async () => {
    try {
      await addKey.mutateAsync({
        description: description.trim(),
        apiKey: apiKey.trim(),
      });
      onClose();
    } catch {
      // The mutation's toast reports the failure.
    }
  };

  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add DigiCert key</DialogTitle>
          <DialogDescription>
            Paste a CertCentral API key. You will not see it again after you
            save it.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="digicert-key-name">Name</Label>
            <Input
              id="digicert-key-name"
              placeholder="For example: Production account"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="digicert-key-value">API key</Label>
            <DigiCertApiKeyInput
              id="digicert-key-value"
              label="API key"
              value={apiKey}
              onChange={setApiKey}
            />
          </div>
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            disabled={!canSave || addKey.isPending}
            onClick={save}
          >
            Save key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ReplaceKeyDialog({
  keyInfo,
  onClose,
}: {
  keyInfo: CertificateAuthorityCredential;
  onClose: () => void;
}) {
  const replaceKey = useReplaceCaCredentialKey();
  const [apiKey, setApiKey] = useState("");

  const save = async () => {
    try {
      await replaceKey.mutateAsync({
        credentialXref: keyInfo.credentialXref,
        apiKey: apiKey.trim(),
      });
      onClose();
    } catch {
      // The mutation's toast reports the failure.
    }
  };

  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Replace key</DialogTitle>
          <DialogDescription>
            Paste the new CertCentral API key for {keyInfo.description}.
            Certificates that use this key switch to the new one.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="digicert-key-replace">New API key</Label>
          <DigiCertApiKeyInput
            id="digicert-key-replace"
            label="New API key"
            value={apiKey}
            onChange={setApiKey}
          />
        </div>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            disabled={!apiKey.trim() || replaceKey.isPending}
            onClick={save}
          >
            Replace key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DeleteKeyDialog({
  keyInfo,
  onClose,
}: {
  keyInfo: CertificateAuthorityCredential;
  onClose: () => void;
}) {
  const deleteKey = useDeleteCaCredential();
  const [error, setError] = useState<string | null>(null);

  const confirm = async () => {
    setError(null);
    try {
      await deleteKey.mutateAsync(keyInfo.credentialXref);
      onClose();
    } catch (failure) {
      setError(caKeyDeleteErrorMessage(failure));
    }
  };

  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {keyInfo.description}?</DialogTitle>
          <DialogDescription>
            CertPing removes the key from its vault. This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={deleteKey.isPending}
            onClick={confirm}
          >
            Delete key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
