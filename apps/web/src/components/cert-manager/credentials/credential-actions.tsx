// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import {
  DotsThreeIcon,
  PencilSimpleIcon,
  TrashIcon,
} from "@phosphor-icons/react";
import * as React from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { CredentialRecord } from "@/types/ssl";

interface CredentialActionsProps {
  credential: CredentialRecord;
  onDelete: (credential: CredentialRecord) => void;
  onEdit: (credential: CredentialRecord) => void;
}

export function CredentialActions({
  credential,
  onDelete,
  onEdit,
}: CredentialActionsProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="iconSm">
          <DotsThreeIcon />
          <span className="sr-only">Open credential actions</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuItem onClick={() => onEdit(credential)}>
          <PencilSimpleIcon />
          Update
        </DropdownMenuItem>
        <DropdownMenuItem
          className="text-destructive focus:text-destructive"
          onClick={() => onDelete(credential)}
        >
          <TrashIcon />
          Delete credential
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
