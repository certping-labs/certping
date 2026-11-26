// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { PlusIcon, TrashIcon } from "@phosphor-icons/react/dist/ssr";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  KUBERNETES_ALL_NAMESPACES,
  type KubernetesNsMapMode,
  type NamespaceSecretPair,
} from "@/lib/credential-config-schemas/kubernetes-secrets";

interface KubernetesNsMapEditorProps {
  allNamespacesSecret: string;
  mapMode: KubernetesNsMapMode;
  namespaceEditable?: boolean;
  onAddPair?: () => void;
  onAllNamespacesSecretChange: (value: string) => void;
  onMapModeChange: (value: KubernetesNsMapMode) => void;
  onPairChange: (
    index: number,
    field: keyof NamespaceSecretPair,
    value: string,
  ) => void;
  onRemovePair?: (index: number) => void;
  onResetDefaults?: () => void;
  pairs: NamespaceSecretPair[];
  supportsAllNamespaces: boolean;
}

export function KubernetesNsMapEditor({
  allNamespacesSecret,
  mapMode,
  namespaceEditable = false,
  onAddPair,
  onAllNamespacesSecretChange,
  onMapModeChange,
  onPairChange,
  onRemovePair,
  onResetDefaults,
  pairs,
  supportsAllNamespaces,
}: KubernetesNsMapEditorProps) {
  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <p className="text-xs font-medium text-muted-foreground">
          Mapping mode
        </p>
        <Select
          onValueChange={(value) =>
            onMapModeChange(value as KubernetesNsMapMode)
          }
          value={mapMode}
        >
          <SelectTrigger className="h-10">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="explicit">Explicit namespaces</SelectItem>
            <SelectItem
              value="all_namespaces"
              disabled={!supportsAllNamespaces}
            >
              {KUBERNETES_ALL_NAMESPACES}
            </SelectItem>
          </SelectContent>
        </Select>
        {!supportsAllNamespaces ? (
          <p className="text-xs text-muted-foreground">
            This credential only supports explicit namespace mappings.
          </p>
        ) : null}
      </div>

      {mapMode === "all_namespaces" ? (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">
            Secret name for all namespaces
          </p>
          <Input
            aria-label="Secret name for all namespaces"
            className="h-10"
            placeholder="example-tls"
            value={allNamespacesSecret}
            onChange={(event) =>
              onAllNamespacesSecretChange(event.target.value)
            }
          />
          <p className="text-xs text-muted-foreground">
            Same secret name will be used in every namespace.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-muted-foreground">
              Namespace to secret mapping
            </p>
            <div className="flex items-center gap-2">
              {onResetDefaults ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={onResetDefaults}
                >
                  Use generated defaults
                </Button>
              ) : null}
              {namespaceEditable && onAddPair ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={onAddPair}
                >
                  <PlusIcon className="mr-1 h-3.5 w-3.5" />
                  Add namespace
                </Button>
              ) : null}
            </div>
          </div>

          {pairs.length === 0 ? (
            <div className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
              No namespace rows available for this credential.
            </div>
          ) : null}

          <div className="space-y-2">
            {pairs.map((pair, index) => (
              <div
                key={`${pair.namespace || "ns"}-${index}`}
                className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto]"
              >
                <Input
                  aria-label={`Namespace ${index + 1}`}
                  className="h-9"
                  placeholder="namespace"
                  readOnly={!namespaceEditable}
                  value={pair.namespace}
                  onChange={(event) =>
                    onPairChange(index, "namespace", event.target.value)
                  }
                />
                <Input
                  aria-label={`Secret name ${index + 1}`}
                  className="h-9"
                  placeholder="secret-name"
                  value={pair.secretName}
                  onChange={(event) =>
                    onPairChange(index, "secretName", event.target.value)
                  }
                />
                {namespaceEditable && onRemovePair ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-9 w-9"
                    onClick={() => onRemovePair(index)}
                  >
                    <TrashIcon className="h-4 w-4" />
                    <span className="sr-only">Remove namespace row</span>
                  </Button>
                ) : (
                  <div aria-hidden className="h-9 w-9" />
                )}
              </div>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            Secret names must be lowercase DNS subdomain names.
          </p>
        </div>
      )}
    </div>
  );
}
