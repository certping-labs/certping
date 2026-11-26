// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowSquareOutIcon,
  CircleNotchIcon,
  GearSixIcon,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import { useQueries } from "@tanstack/react-query";

import { useSyncCertificateCredentialConfig } from "@/hooks/certificate-config";
import { useCredentials, useCanAddCredential } from "@/hooks/credentials";
import {
  useIsFeatureEnabled,
  useIsRouteAvailable,
} from "@/hooks/use-feature-flags";
import { FEATURE_DISABLED_BODY } from "@/lib/feature-disabled-copy";
import { FEATURE_FLAGS } from "@/lib/feature-flags";
import { useConvertCertificateToAutomated } from "@/hooks/ssl";
import {
  canConvertManualCertificateToAutomated,
  getCertificateManagementBadgeClass,
  getCertificateManagementDescription,
  getCertificateManagementLabel,
  getCertificateManagementState,
  getPrimaryDnsConfigXref,
} from "@/lib/certificate-management";
import type {
  CredentialRecord,
  SSLCertificateDetails,
  SSLCertificateListItem,
} from "@/types/ssl";
import type { SyncCertificateCredentialConfigInput } from "@/types/cert-manager";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  CredentialReferenceMultiSelect,
  CredentialReferenceSelect,
} from "./credential-reference-select";
import { getRootDomain } from "@/lib/utils";
import { MultiSelect } from "@/components/ui/multi-select";
import { CredentialReferenceTrigger } from "@/components/cert-manager/credential-reference-trigger";
import {
  defaultAzureAfdCertificateName,
  defaultAzureAfdSecretName,
  defaultAzureAppGatewaySslCertName,
  findKeyVaultCertificateNameCollision,
  getCredentialKeyVaultUri,
  getDeploymentTargetConfigKind,
  type KeyVaultCertificateTarget,
} from "@/lib/cert-manager/deployment-target-config";
import {
  createKubernetesSecretDraft,
  KUBERNETES_ALL_NAMESPACES,
  buildAllNamespacesSecretMap,
  buildNsSecretMapFromPairs,
  parseKubernetesCredentialConfig,
  parseSavedKubernetesDeploymentConfig,
  sanitizeNamespaceSecretPairs,
  type NamespaceSecretPair,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import { KubernetesNsMapEditor } from "@/components/cert-manager/kubernetes-ns-map-editor";
import { getDeploymentCredentialConfig } from "@/lib/backend/deployments";
import { parseAwsLoadBalancerCredentialConfig } from "@/lib/credential-config-schemas/aws-load-balancer";
import { parseAwsApiGatewayCredentialConfig } from "@/lib/credential-config-schemas/aws-api-gateway";
import { parseAzureAfdCredentialConfig } from "@/lib/credential-config-schemas/azure-afd";
import { parseAzureAppGwCredentialConfig } from "@/lib/credential-config-schemas/azure-app-gw";
import { parseAzureAgcCredentialConfig } from "@/lib/credential-config-schemas/azure-agc";
import type { DeploymentCredentialConfigLookup } from "@/types/cert-manager";
import { Separator } from "../ui/separator";

type ManagedCertificateRecord = SSLCertificateDetails | SSLCertificateListItem;

interface CertificateManagementDialogProps {
  certificate: ManagedCertificateRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface CertificateManagementSummaryCardProps {
  certificate: ManagedCertificateRecord;
  canManage: boolean;
  onManage: () => void;
  actionLabel?: string;
}

type DeploymentTargetDraft =
  | {
      kind: "AZURE_KV";
      certificateName: string;
    }
  | {
      kind: "GCP_CERT_MANAGER";
      certificateName: string;
    }
  | {
      kind: "AZURE_AFD";
      certificateName: string;
      secretName: string;
      domainNames: string[];
    }
  | {
      kind: "AZURE_APP_GW";
      sslCertName: string;
      listenerNames: string[];
    }
  | {
      kind: "AZURE_APP_GW_CONTAINERS";
      secrets: NamespaceSecretPair[];
    }
  | {
      kind: "AWS_LOAD_BALANCER";
      listenerArns: string[];
    }
  | {
      kind: "AWS_API_GATEWAY";
      domainNames: string[];
    };

interface KubernetesDeploymentTargetDraft {
  useDefault: boolean;
  mapMode: "explicit" | "all_namespaces";
  pairs: NamespaceSecretPair[];
  allNamespacesSecret: string;
}

const normalizeTargetStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
};

const createDefaultKubernetesDraft = (
  domain: string,
  allowedNamespaces: string[],
  supportsAllNamespaces: boolean,
): KubernetesDeploymentTargetDraft => ({
  useDefault: false,
  ...createKubernetesSecretDraft({
    domain,
    allowedNamespaces,
    supportsAllNamespaces,
  }),
});

function stringifyTargetsForSignature(value: unknown): string {
  // We use this for effect signatures; it must be stable even if the backend
  // returns object keys/array values in different orders.
  const stableSerialize = (input: unknown): unknown => {
    if (Array.isArray(input)) {
      // Arrays of primitives are sorted for stability; arrays of objects keep order.
      if (
        input.every((item) =>
          ["string", "number", "boolean"].includes(typeof item),
        )
      ) {
        return [...input].map((item) => String(item)).sort();
      }
      return input.map(stableSerialize);
    }
    if (!input || typeof input !== "object") {
      return input;
    }
    const record = input as Record<string, unknown>;
    const sortedEntries = Object.entries(record)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, stableSerialize(value)] as const);
    return Object.fromEntries(sortedEntries);
  };

  return JSON.stringify(stableSerialize(value));
}

function resolveLookupTargets(result?: {
  targets?: Record<string, unknown> | null;
  config?: Record<string, unknown> | null;
}): Record<string, unknown> | null {
  if (result?.targets && typeof result.targets === "object") {
    return result.targets;
  }

  const config = result?.config;
  if (!config || typeof config !== "object") {
    return null;
  }

  const nestedTargets = config.targets;
  if (nestedTargets && typeof nestedTargets === "object") {
    return nestedTargets as Record<string, unknown>;
  }

  return config;
}

function createSyntheticCredentialRecord(
  credentialXref: string,
  category: "dns_credential" | "deployment_target",
): CredentialRecord {
  const now = new Date(0).toISOString();

  return {
    id: Math.abs(
      Array.from(credentialXref).reduce(
        (hash, char) => (hash * 31 + char.charCodeAt(0)) | 0,
        17,
      ),
    ),
    alias: credentialXref,
    credentialXref,
    description: credentialXref,
    credentialType: category === "dns_credential" ? "dns" : "deployment",
    type: category === "dns_credential" ? "DNS" : "DEPLOYMENT",
    category,
    metadata: {},
    createdAt: now,
    updatedAt: now,
    nextRotationAt: now,
    rotationInterval: 0,
    version: 1,
    status: "ACTIVE",
  };
}

function withCurrentCredentialFallbacks(
  credentials: CredentialRecord[] | undefined,
  currentXrefs: string[],
  category: "dns_credential" | "deployment_target",
): CredentialRecord[] {
  const resolvedCredentials = credentials || [];
  const existingXrefs = new Set(
    resolvedCredentials
      .map((credential) => credential.credentialXref || credential.alias)
      .filter(Boolean),
  );

  const fallbackCredentials = currentXrefs
    .filter((credentialXref) => !existingXrefs.has(credentialXref))
    .map((credentialXref) =>
      createSyntheticCredentialRecord(credentialXref, category),
    );

  return [...resolvedCredentials, ...fallbackCredentials];
}

const ADD_DNS_CREDENTIAL_HREF = "/integrations/connections/add?type=DNS";
const ADD_DEPLOYMENT_CREDENTIAL_HREF =
  "/integrations/connections/add?type=DEPLOYMENT";
const MANAGE_INTEGRATIONS_HREF = "/integrations/dns";

export function CertificateManagementDialog({
  certificate,
  open,
  onOpenChange,
}: CertificateManagementDialogProps) {
  const isCertDeploymentEnabled = useIsFeatureEnabled("CERTIFICATE_DEPLOYMENT");
  const isDnsCredentialsEnabled = useIsFeatureEnabled(
    FEATURE_FLAGS.DNS_CREDENTIALS,
  );
  const isRouteAvailable = useIsRouteAvailable();
  const addDnsCredentialHref =
    useCanAddCredential("DNS") && isRouteAvailable(ADD_DNS_CREDENTIAL_HREF)
      ? ADD_DNS_CREDENTIAL_HREF
      : undefined;
  const addDeploymentCredentialHref =
    useCanAddCredential("DEPLOYMENT") &&
    isRouteAvailable(ADD_DEPLOYMENT_CREDENTIAL_HREF)
      ? ADD_DEPLOYMENT_CREDENTIAL_HREF
      : undefined;
  const dnsCredentialsQuery = useCredentials({
    enabled: open,
    category: "dns_credential",
  });
  const deploymentCredentialsQuery = useCredentials({
    enabled: open && isCertDeploymentEnabled,
    category: "deployment_target",
  });
  const syncConfigMutation = useSyncCertificateCredentialConfig();
  const convertToAutomatedMutation = useConvertCertificateToAutomated();

  const [dnsConfigXref, setDnsConfigXref] = useState("");
  const [deploymentCredentialXrefs, setDeploymentCredentialXrefs] = useState<
    string[]
  >([]);
  const [deploymentTargetDrafts, setDeploymentTargetDrafts] = useState<
    Record<string, DeploymentTargetDraft>
  >({});
  const [kubernetesTargetDrafts, setKubernetesTargetDrafts] = useState<
    Record<string, KubernetesDeploymentTargetDraft>
  >({});

  const currentDnsConfigXref =
    getPrimaryDnsConfigXref(certificate?.dnsConfigXref, certificate?.domain) ||
    "";
  const currentDeploymentCredentialXrefs = useMemo(
    () => certificate?.deploymentCredentialXrefs || [],
    [certificate?.deploymentCredentialXrefs],
  );

  const effectiveManagementState = certificate
    ? getCertificateManagementState(certificate)
    : "manual";
  const canEnableAutomation = certificate
    ? canConvertManualCertificateToAutomated(certificate)
    : false;

  // With DNS credentials off only CertPing DNS may be chosen, as the backend allows; the certificate's current
  // credential stays listed so its selection and summary keep their name.
  const dnsCredentials = useMemo(() => {
    const credentials = withCurrentCredentialFallbacks(
      dnsCredentialsQuery.data,
      currentDnsConfigXref ? [currentDnsConfigXref] : [],
      "dns_credential",
    );
    return isDnsCredentialsEnabled
      ? credentials
      : credentials.filter(
          (credential) =>
            (credential.credentialXref || credential.alias) ===
            currentDnsConfigXref,
        );
  }, [currentDnsConfigXref, dnsCredentialsQuery.data, isDnsCredentialsEnabled]);

  const deploymentCredentials = useMemo(
    () =>
      isCertDeploymentEnabled
        ? withCurrentCredentialFallbacks(
            deploymentCredentialsQuery.data,
            currentDeploymentCredentialXrefs,
            "deployment_target",
          )
        : [],
    [
      currentDeploymentCredentialXrefs,
      deploymentCredentialsQuery.data,
      isCertDeploymentEnabled,
    ],
  );

  useEffect(() => {
    if (!open) {
      setDnsConfigXref("");
      setDeploymentCredentialXrefs([]);
      setDeploymentTargetDrafts({});
      setKubernetesTargetDrafts({});
      return;
    }

    if (!certificate) {
      return;
    }

    setDnsConfigXref(
      getPrimaryDnsConfigXref(certificate.dnsConfigXref, certificate.domain) ||
        "",
    );
    setDeploymentCredentialXrefs(
      isCertDeploymentEnabled
        ? certificate.deploymentCredentialXrefs || []
        : currentDeploymentCredentialXrefs,
    );
  }, [
    certificate,
    currentDeploymentCredentialXrefs,
    isCertDeploymentEnabled,
    open,
  ]);

  const effectiveDnsConfigXref = dnsConfigXref || currentDnsConfigXref;
  const normalizedCurrentDeploymentTargets = useMemo(
    () => Array.from(new Set(currentDeploymentCredentialXrefs)),
    [currentDeploymentCredentialXrefs],
  );
  const dnsCredentialsByXref = useMemo(
    () =>
      new Map(
        dnsCredentials.map((credential) => [
          credential.credentialXref || credential.alias || "",
          credential,
        ]),
      ),
    [dnsCredentials],
  );
  const deploymentCredentialsByXref = useMemo(
    () =>
      new Map(
        deploymentCredentials.map((credential) => [
          credential.credentialXref || credential.alias || "",
          credential,
        ]),
      ),
    [deploymentCredentials],
  );
  const normalizedSelectedDeploymentTargets = useMemo(
    () => Array.from(new Set(deploymentCredentialXrefs)),
    [deploymentCredentialXrefs],
  );

  const selectedConfiguredDeploymentCredentials = useMemo(
    () =>
      deploymentCredentials.filter((credential) => {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref) {
          return false;
        }
        if (!normalizedSelectedDeploymentTargets.includes(credentialXref)) {
          return false;
        }

        const kind = getDeploymentTargetConfigKind({
          targetType: credential.targetType,
          providerName: credential.providerName,
        });

        return kind !== "NONE";
      }),
    [deploymentCredentials, normalizedSelectedDeploymentTargets],
  );

  const certificateXref = certificate?.certificateXref || "";
  const configuredTargetCredentialXrefs = useMemo(
    () =>
      selectedConfiguredDeploymentCredentials
        .map(
          (credential) => credential.credentialXref || credential.alias || "",
        )
        .filter(Boolean),
    [selectedConfiguredDeploymentCredentials],
  );
  const configuredTargetsLookupQueries = useQueries({
    queries: configuredTargetCredentialXrefs.map((credentialXref) => ({
      queryKey: [
        "deployment-credential-config",
        certificateXref,
        credentialXref,
      ],
      enabled: Boolean(open && certificateXref && credentialXref),
      retry: false,
      refetchOnWindowFocus: false,
      queryFn: () =>
        getDeploymentCredentialConfig(certificateXref, credentialXref),
    })),
  });
  const configuredTargetsSignatureRef = useRef<string>("");
  const configuredTargetsByCredentialXref = useMemo(() => {
    const map = new Map<
      string,
      {
        isError: boolean;
        isLoading: boolean;
        isSuccess: boolean;
        data?: DeploymentCredentialConfigLookup;
      }
    >();

    for (
      let index = 0;
      index < configuredTargetCredentialXrefs.length;
      index++
    ) {
      const credentialXref = configuredTargetCredentialXrefs[index] || "";
      const query = configuredTargetsLookupQueries[index];
      if (!credentialXref || !query) {
        continue;
      }

      map.set(credentialXref, {
        isError: query.isError,
        isLoading: query.isLoading,
        isSuccess: query.isSuccess,
        data: query.data,
      });
    }

    return map;
  }, [configuredTargetCredentialXrefs, configuredTargetsLookupQueries]);

  useEffect(() => {
    if (!open || !certificate) {
      return;
    }

    setDeploymentTargetDrafts((previous) => {
      let didChange = false;
      const nextDrafts: Record<string, DeploymentTargetDraft> = { ...previous };

      for (const credential of selectedConfiguredDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref || nextDrafts[credentialXref]) {
          continue;
        }

        const kind = getDeploymentTargetConfigKind({
          targetType: credential.targetType,
          providerName: credential.providerName,
        });

        if (kind === "AZURE_KV" || kind === "GCP_CERT_MANAGER") {
          didChange = true;
          nextDrafts[credentialXref] = {
            kind,
            certificateName: "",
          };
        } else if (kind === "AZURE_AFD") {
          didChange = true;
          nextDrafts[credentialXref] = {
            kind,
            certificateName: defaultAzureAfdCertificateName(certificate.domain),
            secretName: defaultAzureAfdSecretName(certificate.domain),
            domainNames: [],
          };
        } else if (kind === "AZURE_APP_GW") {
          didChange = true;
          const allowedListeners =
            parseAzureAppGwCredentialConfig(credential.configJson)?.listeners ||
            [];
          nextDrafts[credentialXref] = {
            kind,
            sslCertName: defaultAzureAppGatewaySslCertName(certificate.domain),
            listenerNames:
              allowedListeners.length > 0 ? [allowedListeners[0]] : [],
          };
        } else if (kind === "AZURE_APP_GW_CONTAINERS") {
          didChange = true;
          const allowedNamespaces =
            parseAzureAgcCredentialConfig(credential.configJson)
              ?.secretNamespaces || [];
          const defaultDraft = createKubernetesSecretDraft({
            domain: certificate.domain,
            allowedNamespaces,
            supportsAllNamespaces: false,
          });
          nextDrafts[credentialXref] = {
            kind,
            secrets: defaultDraft.pairs,
          };
        } else if (kind === "AWS_LOAD_BALANCER") {
          didChange = true;
          nextDrafts[credentialXref] = { kind, listenerArns: [] };
        } else if (kind === "AWS_API_GATEWAY") {
          didChange = true;
          nextDrafts[credentialXref] = {
            kind,
            domainNames: [],
          };
        }
      }

      return didChange ? nextDrafts : previous;
    });

    setKubernetesTargetDrafts((previous) => {
      let didChange = false;
      const next: Record<string, KubernetesDeploymentTargetDraft> = {
        ...previous,
      };

      for (const credential of selectedConfiguredDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref || next[credentialXref]) {
          continue;
        }

        const kind = getDeploymentTargetConfigKind({
          targetType: credential.targetType,
          providerName: credential.providerName,
        });
        if (kind !== "KUBERNETES_SECRETS") {
          continue;
        }
        didChange = true;

        const parsedConfig = parseKubernetesCredentialConfig(
          credential.configJson,
        );
        const allowedNamespaces = Array.isArray(parsedConfig?.namespaces)
          ? parsedConfig.namespaces
          : [];
        const supportsAllNamespaces =
          parsedConfig?.namespaces === KUBERNETES_ALL_NAMESPACES;

        next[credentialXref] = createDefaultKubernetesDraft(
          certificate.domain || "certificate",
          allowedNamespaces,
          supportsAllNamespaces,
        );
      }

      return didChange ? next : previous;
    });
  }, [certificate, open, selectedConfiguredDeploymentCredentials]);

  useEffect(() => {
    if (!open || !certificate || !certificateXref) {
      return;
    }

    const lookupResults = configuredTargetsLookupQueries
      .map((query) => query.data)
      .filter(Boolean);
    if (lookupResults.length === 0) {
      return;
    }

    const signature = lookupResults
      .map(
        (result) =>
          `${result?.deploymentCredentialXref || ""}:${stringifyTargetsForSignature(result?.config)}:${stringifyTargetsForSignature(result?.targets)}`,
      )
      .join("|");
    if (signature && signature === configuredTargetsSignatureRef.current) {
      return;
    }
    configuredTargetsSignatureRef.current = signature;

    setDeploymentTargetDrafts((previous) => {
      let didChange = false;
      const next = { ...previous };

      const sameStringSet = (a: string[], b: string[]) => {
        if (a.length !== b.length) {
          return false;
        }
        const aSorted = [...a]
          .map((v) => v.trim())
          .filter(Boolean)
          .sort();
        const bSorted = [...b]
          .map((v) => v.trim())
          .filter(Boolean)
          .sort();
        return aSorted.every((value, index) => value === bSorted[index]);
      };

      for (const result of lookupResults) {
        const credentialXref = result?.deploymentCredentialXref;
        if (!credentialXref) {
          continue;
        }

        const targets = resolveLookupTargets(result);
        if (!targets) {
          continue;
        }

        const currentDraft = next[credentialXref];
        if (!currentDraft) {
          continue;
        }

        if (
          currentDraft.kind === "AZURE_KV" ||
          currentDraft.kind === "GCP_CERT_MANAGER"
        ) {
          const certificateName =
            typeof targets.certificateName === "string"
              ? targets.certificateName
              : "";
          if (certificateName.trim()) {
            if (currentDraft.certificateName !== certificateName) {
              didChange = true;
              next[credentialXref] = {
                kind: currentDraft.kind,
                certificateName,
              };
            }
          }
        } else if (currentDraft.kind === "AZURE_AFD") {
          const certificateName =
            typeof targets.certificateName === "string"
              ? targets.certificateName.trim()
              : "";
          const secretName =
            typeof targets.secretName === "string"
              ? targets.secretName.trim()
              : "";
          const domainNames = normalizeTargetStringArray(
            (targets.domainNames as unknown) ?? [],
          );
          const nextCertificateName =
            certificateName || currentDraft.certificateName;
          const nextSecretName = secretName || currentDraft.secretName;
          const nextDomainNames =
            domainNames.length > 0 ? domainNames : currentDraft.domainNames;
          const sameDomains = sameStringSet(
            currentDraft.domainNames,
            nextDomainNames,
          );
          if (
            currentDraft.certificateName !== nextCertificateName ||
            currentDraft.secretName !== nextSecretName ||
            !sameDomains
          ) {
            didChange = true;
            next[credentialXref] = {
              kind: "AZURE_AFD",
              certificateName: nextCertificateName,
              secretName: nextSecretName,
              domainNames: nextDomainNames,
            };
          }
        } else if (currentDraft.kind === "AWS_LOAD_BALANCER") {
          const listenerArns = normalizeTargetStringArray(
            (targets.listenerArns as unknown) ?? [],
          );
          if (listenerArns.length > 0) {
            if (!sameStringSet(currentDraft.listenerArns, listenerArns)) {
              didChange = true;
              next[credentialXref] = {
                kind: "AWS_LOAD_BALANCER",
                listenerArns,
              };
            }
          }
        } else if (currentDraft.kind === "AZURE_APP_GW") {
          const sslCertName =
            typeof targets.sslCertName === "string" ? targets.sslCertName : "";
          const listenerNames = normalizeTargetStringArray(
            (targets.listenerNames as unknown) ?? [],
          );
          if (sslCertName.trim() && listenerNames.length > 0) {
            if (
              currentDraft.sslCertName !== sslCertName ||
              !sameStringSet(currentDraft.listenerNames, listenerNames)
            ) {
              didChange = true;
              next[credentialXref] = {
                kind: "AZURE_APP_GW",
                sslCertName,
                listenerNames,
              };
            }
          }
        } else if (currentDraft.kind === "AZURE_APP_GW_CONTAINERS") {
          const secretsRaw = (targets.secrets as unknown) ?? [];
          const secrets = Array.isArray(secretsRaw)
            ? secretsRaw
                .map((entry) =>
                  entry && typeof entry === "object"
                    ? {
                        namespace:
                          typeof (entry as { namespace?: unknown })
                            .namespace === "string"
                            ? (entry as { namespace: string }).namespace
                            : "",
                        secretName:
                          typeof (entry as { secretName?: unknown })
                            .secretName === "string"
                            ? (entry as { secretName: string }).secretName
                            : "",
                      }
                    : { namespace: "", secretName: "" },
                )
                .filter((pair) => pair.namespace && pair.secretName)
            : [];
          if (secrets.length > 0) {
            const sameSecrets =
              secrets.length === currentDraft.secrets.length &&
              secrets.every(
                (pair, index) =>
                  pair.namespace === currentDraft.secrets[index]?.namespace &&
                  pair.secretName === currentDraft.secrets[index]?.secretName,
              );
            if (!sameSecrets) {
              didChange = true;
              next[credentialXref] = {
                kind: "AZURE_APP_GW_CONTAINERS",
                secrets,
              };
            }
          }
        } else if (currentDraft.kind === "AWS_API_GATEWAY") {
          const domainNames = normalizeTargetStringArray(
            (targets.domainNames as unknown) ?? [],
          );
          if (domainNames.length > 0) {
            if (!sameStringSet(currentDraft.domainNames, domainNames)) {
              didChange = true;
              next[credentialXref] = {
                kind: "AWS_API_GATEWAY",
                domainNames,
              };
            }
          }
        }
      }

      return didChange ? next : previous;
    });

    setKubernetesTargetDrafts((previous) => {
      let didChange = false;
      const next = { ...previous };

      for (const result of lookupResults) {
        const credentialXref = result?.deploymentCredentialXref;
        if (!credentialXref) {
          continue;
        }

        const currentDraft = next[credentialXref];
        if (!currentDraft) {
          continue;
        }

        const config = result.config;
        if (!config) {
          continue;
        }

        const useDefault =
          typeof (config as { useDefault?: unknown }).useDefault === "boolean"
            ? Boolean((config as { useDefault?: boolean }).useDefault)
            : false;
        if (useDefault) {
          if (!currentDraft.useDefault) {
            didChange = true;
            next[credentialXref] = {
              ...currentDraft,
              useDefault: true,
            };
          }
          continue;
        }

        const parsed = parseSavedKubernetesDeploymentConfig(config);
        if (!parsed) {
          continue;
        }

        const samePairs =
          currentDraft.mapMode === parsed.mapMode &&
          currentDraft.allNamespacesSecret === parsed.allNamespacesSecret &&
          currentDraft.pairs.length === parsed.pairs.length &&
          currentDraft.pairs.every(
            (pair, index) =>
              pair.namespace === parsed.pairs[index]?.namespace &&
              pair.secretName === parsed.pairs[index]?.secretName,
          );
        if (!samePairs || currentDraft.useDefault) {
          didChange = true;
          next[credentialXref] = {
            useDefault: false,
            mapMode: parsed.mapMode,
            pairs: parsed.pairs,
            allNamespacesSecret: parsed.allNamespacesSecret,
          };
        }
      }

      return didChange ? next : previous;
    });
  }, [certificate, certificateXref, configuredTargetsLookupQueries, open]);

  useEffect(() => {
    if (!open) {
      return;
    }

    setKubernetesTargetDrafts((previous) => {
      let didChange = false;
      const next = { ...previous };

      for (const [credentialXref, draft] of Object.entries(previous)) {
        if (!draft.useDefault) {
          continue;
        }

        const lookup = configuredTargetsByCredentialXref.get(credentialXref);
        const savedConfig = lookup?.data?.config;
        const savedDraft = parseSavedKubernetesDeploymentConfig(savedConfig);
        const hasSavedDefaultConfig =
          Boolean(lookup?.isSuccess && savedDraft) && !lookup?.isError;

        if (!hasSavedDefaultConfig) {
          didChange = true;
          next[credentialXref] = { ...draft, useDefault: false };
        }
      }

      return didChange ? next : previous;
    });
  }, [configuredTargetsByCredentialXref, open]);

  const hasDeploymentTargetChanges =
    normalizedCurrentDeploymentTargets.length !==
      normalizedSelectedDeploymentTargets.length ||
    normalizedCurrentDeploymentTargets.some(
      (credentialXref) =>
        !normalizedSelectedDeploymentTargets.includes(credentialXref),
    );
  const hasDnsChange =
    Boolean(effectiveDnsConfigXref) &&
    effectiveDnsConfigXref !== currentDnsConfigXref;
  const hasDeploymentTargetConfigEditors =
    isCertDeploymentEnabled &&
    selectedConfiguredDeploymentCredentials.length > 0;
  const hasChanges =
    hasDnsChange ||
    hasDeploymentTargetChanges ||
    hasDeploymentTargetConfigEditors;
  const isSaving =
    syncConfigMutation.isPending || convertToAutomatedMutation.isPending;

  const handleSave = async () => {
    if (!certificate) {
      return;
    }

    const deploymentTargetConfigs: NonNullable<
      SyncCertificateCredentialConfigInput["deploymentTargetConfigs"]
    > = [];
    const keyVaultTargets: KeyVaultCertificateTarget[] = [];

    for (const credential of selectedConfiguredDeploymentCredentials) {
      const credentialXref = credential.credentialXref || credential.alias;
      if (!credentialXref) {
        continue;
      }

      const kind = getDeploymentTargetConfigKind({
        targetType: credential.targetType,
        providerName: credential.providerName,
      });

      if (kind === "KUBERNETES_SECRETS") {
        const draft = kubernetesTargetDrafts[credentialXref];
        if (!draft) {
          toast.error(
            `Missing configuration for deployment target ${credentialXref}.`,
          );
          return;
        }

        if (draft.useDefault) {
          deploymentTargetConfigs.push({
            credentialXref,
            config: { useDefault: true },
          });
          continue;
        }

        if (draft.mapMode === "all_namespaces") {
          const secretName = draft.allNamespacesSecret.trim();
          if (!secretName) {
            toast.error(
              `Provide all_namespaces secret name for ${credentialXref}.`,
            );
            return;
          }
          deploymentTargetConfigs.push({
            credentialXref,
            config: {
              useDefault: false,
              nsSecretMap: buildAllNamespacesSecretMap(secretName),
            },
          });
          continue;
        }

        let pairs: NamespaceSecretPair[];
        try {
          pairs = sanitizeNamespaceSecretPairs(draft.pairs || []);
        } catch (error) {
          toast.error(
            error instanceof Error
              ? `${credentialXref}: ${error.message}`
              : `Invalid namespace mapping for ${credentialXref}.`,
          );
          return;
        }

        if (pairs.length === 0) {
          toast.error(`Provide namespace mappings for ${credentialXref}.`);
          return;
        }

        deploymentTargetConfigs.push({
          credentialXref,
          config: {
            useDefault: false,
            nsSecretMap: buildNsSecretMapFromPairs(pairs),
          },
        });
        continue;
      }

      const draft = deploymentTargetDrafts[credentialXref];
      if (!draft) {
        toast.error(
          `Missing configuration for deployment target ${credentialXref}.`,
        );
        return;
      }

      if (draft.kind === "AZURE_KV" || draft.kind === "GCP_CERT_MANAGER") {
        const certificateName = draft.certificateName.trim();
        if (!certificateName) {
          toast.error(`Enter a certificate name for target ${credentialXref}.`);
          return;
        }
        deploymentTargetConfigs.push({
          credentialXref,
          targets: { certificateName },
        });
      } else if (draft.kind === "AZURE_AFD") {
        const certificateName = draft.certificateName.trim();
        const secretName = draft.secretName.trim();
        const domainNames = draft.domainNames
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (!certificateName || !secretName || domainNames.length === 0) {
          toast.error(
            `Enter certificate name, secret name, and at least one domain for Front Door target ${credentialXref}.`,
          );
          return;
        }

        const allowedDomains =
          parseAzureAfdCredentialConfig(credential.configJson)?.customDomains ||
          [];
        if (allowedDomains.length === 0) {
          toast.error(
            `No custom domains are configured on credential ${credentialXref}. Update the credential first.`,
          );
          return;
        }
        const allowedSet = new Set(allowedDomains);
        const invalid = domainNames.find((name) => !allowedSet.has(name));
        if (invalid) {
          toast.error(
            `Domain name is not in the credential allow-list for ${credentialXref}. Update the credential custom domains list and try again.`,
          );
          return;
        }
        deploymentTargetConfigs.push({
          credentialXref,
          targets: { certificateName, secretName, domainNames },
        });
      } else if (draft.kind === "AWS_LOAD_BALANCER") {
        const listenerArns = draft.listenerArns
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (listenerArns.length === 0) {
          toast.error(
            `Add at least one listener ARN for load balancer target ${credentialXref}.`,
          );
          return;
        }

        const allowedListeners =
          parseAwsLoadBalancerCredentialConfig(credential.configJson)
            ?.listeners || [];
        const allowedSet = new Set(allowedListeners);
        const invalid = listenerArns.find((arn) => !allowedSet.has(arn));
        if (invalid) {
          toast.error(
            `Listener ARN is not in the credential allow-list for ${credentialXref}. Update the credential listeners list and try again.`,
          );
          return;
        }
        deploymentTargetConfigs.push({
          credentialXref,
          targets: { listenerArns },
        });
      } else if (draft.kind === "AZURE_APP_GW") {
        const sslCertName = draft.sslCertName.trim();
        const listenerNames = draft.listenerNames
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (!sslCertName || listenerNames.length === 0) {
          toast.error(
            `Enter ssl cert name and at least one listener for App Gateway target ${credentialXref}.`,
          );
          return;
        }

        const allowedListeners =
          parseAzureAppGwCredentialConfig(credential.configJson)?.listeners ||
          [];
        const allowedSet = new Set(allowedListeners);
        const invalid = listenerNames.find((name) => !allowedSet.has(name));
        if (invalid) {
          toast.error(
            `Listener name is not in the credential allow-list for ${credentialXref}. Update the credential listeners list and try again.`,
          );
          return;
        }

        deploymentTargetConfigs.push({
          credentialXref,
          targets: { sslCertName, listenerNames },
        });
      } else if (draft.kind === "AZURE_APP_GW_CONTAINERS") {
        const allowedNamespaces =
          parseAzureAgcCredentialConfig(credential.configJson)
            ?.secretNamespaces || [];
        const allowedSet = new Set(allowedNamespaces);
        const secrets = sanitizeNamespaceSecretPairs(draft.secrets || []);
        if (secrets.length === 0) {
          toast.error(
            `Add at least one namespace secret mapping for AGC target ${credentialXref}.`,
          );
          return;
        }
        const invalid = secrets.find((pair) => !allowedSet.has(pair.namespace));
        if (invalid) {
          toast.error(
            `Namespace is not in the credential allow-list for ${credentialXref}. Update the credential secret namespaces list and try again.`,
          );
          return;
        }

        deploymentTargetConfigs.push({
          credentialXref,
          targets: { secrets },
        });
      } else if (draft.kind === "AWS_API_GATEWAY") {
        const domainNames = draft.domainNames
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (domainNames.length === 0) {
          toast.error(
            `Add at least one domain name for API Gateway target ${credentialXref}.`,
          );
          return;
        }

        const allowedDomains =
          parseAwsApiGatewayCredentialConfig(credential.configJson)
            ?.customDomains || [];
        const allowedSet = new Set(allowedDomains);
        const invalid = domainNames.find((name) => !allowedSet.has(name));
        if (invalid) {
          toast.error(
            `Domain name is not in the credential allow-list for ${credentialXref}. Update the credential custom domains list and try again.`,
          );
          return;
        }
        deploymentTargetConfigs.push({
          credentialXref,
          targets: { domainNames },
        });
      }

      if (draft.kind === "AZURE_KV" || draft.kind === "AZURE_AFD") {
        keyVaultTargets.push({
          credentialXref,
          kind: draft.kind,
          vaultUri: getCredentialKeyVaultUri(credential),
          certificateName: draft.certificateName,
        });
      }
    }

    const keyVaultCollision =
      findKeyVaultCertificateNameCollision(keyVaultTargets);
    if (keyVaultCollision) {
      toast.error(keyVaultCollision);
      return;
    }

    if (
      !effectiveDnsConfigXref &&
      normalizedSelectedDeploymentTargets.length > 0
    ) {
      toast.error(
        "Attach a DNS provider before adding deployment targets to this certificate.",
      );
      return;
    }

    if (canEnableAutomation) {
      if (!effectiveDnsConfigXref) {
        toast.error("Select a DNS provider to enable automation.");
        return;
      }

      const isWildcard = certificate.wildcard;

      const domains = Array.from(
        new Set([
          isWildcard ? `*.${certificate.domain}` : certificate.domain,
          ...(certificate.sanDomains || []),
        ]),

        // ["*.example.org"]
      );

      await convertToAutomatedMutation.mutateAsync({
        certificateXref: certificate.certificateXref || "",
        payload: {
          dnsMappings: domains.map((domain) => ({
            domain: getRootDomain(domain),
            credentialXref: effectiveDnsConfigXref,
          })),
          deploymentTargets: normalizedSelectedDeploymentTargets,
          activationMode: "NEXT_RENEWAL",
          inFlightPolicy: "WAIT",
        },
      });

      await syncConfigMutation.mutateAsync({
        domain: certificate.domain,
        currentDnsConfigXref: getPrimaryDnsConfigXref(
          certificate.dnsConfigXref,
          certificate.domain,
        ),
        dnsConfigXref: effectiveDnsConfigXref || undefined,
        currentDeploymentCredentialXrefs:
          certificate.deploymentCredentialXrefs || [],
        deploymentCredentialXrefs: normalizedSelectedDeploymentTargets,
        deploymentTargetConfigs,
      });

      onOpenChange(false);
      return;
    }

    await syncConfigMutation.mutateAsync({
      domain: certificate.domain,
      currentDnsConfigXref: getPrimaryDnsConfigXref(
        certificate.dnsConfigXref,
        certificate.domain,
      ),
      dnsConfigXref: effectiveDnsConfigXref || undefined,
      currentDeploymentCredentialXrefs:
        certificate.deploymentCredentialXrefs || [],
      deploymentCredentialXrefs: normalizedSelectedDeploymentTargets,
      deploymentTargetConfigs,
    });

    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-x-hidden overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {canEnableAutomation ? "Enable automation" : "Manage automation"}
          </DialogTitle>
          <DialogDescription className="wrap-break-word">
            {canEnableAutomation ? "Attach" : "Update"} saved DNS
            {isCertDeploymentEnabled ? " and deployment" : ""} credentials for{" "}
            <span className="font-medium break-all text-foreground">
              {certificate?.domain || "this certificate"}
            </span>
            . DNS credentials control automatic renewal.
            {isCertDeploymentEnabled
              ? " Deployment targets control redeployment after renewal."
              : ""}
          </DialogDescription>
        </DialogHeader>

        {certificate ? (
          <div className="space-y-5">
            <div className="grid gap-2 sm:grid-cols-[auto_1fr] sm:items-center">
              <Badge
                variant="outline"
                textOnly
                className={getCertificateManagementBadgeClass(
                  effectiveManagementState,
                )}
              >
                {getCertificateManagementLabel(effectiveManagementState)}
              </Badge>
              <p className="min-w-0 text-sm leading-5 text-muted-foreground">
                {getCertificateManagementDescription(effectiveManagementState)}
              </p>
            </div>

            <div
              className={
                isCertDeploymentEnabled ? "grid gap-5 lg:grid-cols-2" : ""
              }
            >
              <div className="space-y-2">
                <Label htmlFor="dns-config-xref">DNS credential</Label>
                <CredentialReferenceSelect
                  addCredentialHref={addDnsCredentialHref}
                  addCredentialLabel="Connect DNS provider"
                  credentials={dnsCredentials}
                  emptyOptionLabel={
                    currentDnsConfigXref
                      ? undefined
                      : "No DNS credential attached"
                  }
                  emptyOptionValue={
                    currentDnsConfigXref ? undefined : "__none__"
                  }
                  onValueChange={(value) =>
                    setDnsConfigXref(value === "__none__" ? "" : value)
                  }
                  placeholder="Select DNS credential"
                  value={
                    dnsConfigXref ||
                    (currentDnsConfigXref ? currentDnsConfigXref : undefined)
                  }
                />
              </div>

              {isCertDeploymentEnabled ? (
                <div className="min-w-0 space-y-2">
                  <Label htmlFor="deployment-targets">Deployment targets</Label>
                  <CredentialReferenceMultiSelect
                    addCredentialHref={addDeploymentCredentialHref}
                    addCredentialLabel="Add deployment target"
                    credentials={deploymentCredentials}
                    onValueChange={(nextDeploymentTargets) => {
                      if (
                        !effectiveDnsConfigXref &&
                        nextDeploymentTargets.length > 0
                      ) {
                        toast.error(
                          "Attach a DNS provider before adding deployment targets to this certificate.",
                        );
                        return;
                      }

                      setDeploymentCredentialXrefs(nextDeploymentTargets);
                    }}
                    placeholder="Select deployment targets"
                    value={deploymentCredentialXrefs}
                  />
                </div>
              ) : null}
            </div>

            {isCertDeploymentEnabled &&
            selectedConfiguredDeploymentCredentials.length > 0 ? (
              <div className="space-y-3">
                <div className="text-sm text-muted-foreground">
                  Deployment target configuration
                </div>
                <div className="space-y-3">
                  {selectedConfiguredDeploymentCredentials.map((credential) => {
                    const credentialXref =
                      credential.credentialXref || credential.alias || "";
                    if (!credentialXref) {
                      return null;
                    }

                    const kind = getDeploymentTargetConfigKind({
                      targetType: credential.targetType,
                      providerName: credential.providerName,
                    });

                    if (kind === "NONE") {
                      return null;
                    }

                    if (kind === "KUBERNETES_SECRETS") {
                      const draft = kubernetesTargetDrafts[credentialXref];
                      if (!draft) {
                        return null;
                      }

                      const lookup =
                        configuredTargetsByCredentialXref.get(credentialXref);
                      const savedConfig = lookup?.data?.config;
                      const savedDraft =
                        parseSavedKubernetesDeploymentConfig(savedConfig);
                      const hasSavedDefaultConfig =
                        Boolean(lookup?.isSuccess && savedDraft) &&
                        !lookup?.isError;

                      const parsedConfig = parseKubernetesCredentialConfig(
                        credential.configJson,
                      );
                      const allowedNamespaces = Array.isArray(
                        parsedConfig?.namespaces,
                      )
                        ? parsedConfig.namespaces
                        : [];
                      const supportsAllNamespaces =
                        parsedConfig?.namespaces === KUBERNETES_ALL_NAMESPACES;
                      const defaultDraft = createDefaultKubernetesDraft(
                        certificate?.domain || "certificate",
                        allowedNamespaces,
                        supportsAllNamespaces,
                      );

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              Kubernetes Secrets
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Namespace mapping for{" "}
                              <span className="font-mono">
                                {credentialXref}
                              </span>
                            </div>
                          </div>

                          <Select
                            value={draft.useDefault ? "saved" : "explicit"}
                            onValueChange={(value) =>
                              setKubernetesTargetDrafts((previous) => {
                                if (
                                  value === "saved" &&
                                  !hasSavedDefaultConfig
                                ) {
                                  return previous;
                                }
                                return {
                                  ...previous,
                                  [credentialXref]: {
                                    ...draft,
                                    useDefault: value === "saved",
                                  },
                                };
                              })
                            }
                          >
                            <SelectTrigger className="h-10">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="explicit">
                                Provide explicit mapping
                              </SelectItem>
                              <SelectItem
                                value="saved"
                                disabled={!hasSavedDefaultConfig}
                              >
                                Use saved default config
                              </SelectItem>
                            </SelectContent>
                          </Select>

                          {!draft.useDefault ? (
                            <KubernetesNsMapEditor
                              allNamespacesSecret={draft.allNamespacesSecret}
                              mapMode={draft.mapMode}
                              onAllNamespacesSecretChange={(value) =>
                                setKubernetesTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    ...draft,
                                    allNamespacesSecret: value,
                                  },
                                }))
                              }
                              onMapModeChange={(value) =>
                                setKubernetesTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    ...draft,
                                    mapMode: value,
                                  },
                                }))
                              }
                              onPairChange={(index, fieldName, value) =>
                                setKubernetesTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    ...draft,
                                    pairs: draft.pairs.map((pair, pairIndex) =>
                                      pairIndex === index
                                        ? { ...pair, [fieldName]: value }
                                        : pair,
                                    ),
                                  },
                                }))
                              }
                              onResetDefaults={() =>
                                setKubernetesTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    ...draft,
                                    pairs: defaultDraft.pairs,
                                  },
                                }))
                              }
                              pairs={draft.pairs}
                              supportsAllNamespaces={supportsAllNamespaces}
                            />
                          ) : null}
                        </div>
                      );
                    }

                    const draft = deploymentTargetDrafts[credentialXref];
                    if (!draft) {
                      return null;
                    }

                    if (
                      draft.kind === "AZURE_KV" ||
                      draft.kind === "GCP_CERT_MANAGER"
                    ) {
                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              Azure Key Vault
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Certificate name for{" "}
                              <span className="font-mono">
                                {credentialXref}
                              </span>
                            </div>
                          </div>
                          <Input
                            className="h-10"
                            value={draft.certificateName}
                            onChange={(event) => {
                              const certificateName = event.target.value;
                              setDeploymentTargetDrafts((previous) => ({
                                ...previous,
                                [credentialXref]: {
                                  kind: "AZURE_KV",
                                  certificateName,
                                },
                              }));
                            }}
                          />
                        </div>
                      );
                    }

                    if (draft.kind === "AZURE_AFD") {
                      const allowed =
                        parseAzureAfdCredentialConfig(credential.configJson)
                          ?.customDomains || [];
                      const optionValues = new Set(allowed);
                      for (const selected of draft.domainNames) {
                        optionValues.add(selected);
                      }
                      const options = Array.from(optionValues).map((value) => ({
                        value,
                        label: value,
                      }));

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              Azure Front Door
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Per-certificate settings for{" "}
                              <span className="font-mono">
                                {credentialXref}
                              </span>
                            </div>
                          </div>
                          <Input
                            className="h-10"
                            value={draft.certificateName}
                            onChange={(event) => {
                              const certificateName = event.target.value;
                              setDeploymentTargetDrafts((previous) => ({
                                ...previous,
                                [credentialXref]: {
                                  kind: "AZURE_AFD",
                                  certificateName,
                                  secretName: draft.secretName,
                                  domainNames: draft.domainNames,
                                },
                              }));
                            }}
                            placeholder="Certificate name"
                          />
                          <Input
                            className="h-10"
                            value={draft.secretName}
                            onChange={(event) => {
                              const secretName = event.target.value;
                              setDeploymentTargetDrafts((previous) => ({
                                ...previous,
                                [credentialXref]: {
                                  kind: "AZURE_AFD",
                                  certificateName: draft.certificateName,
                                  secretName,
                                  domainNames: draft.domainNames,
                                },
                              }));
                            }}
                            placeholder="Secret name"
                          />
                          {allowed.length === 0 ? (
                            <p className="text-xs text-muted-foreground">
                              Edit this credential and add custom domains first.
                            </p>
                          ) : (
                            <MultiSelect
                              options={options}
                              selected={draft.domainNames}
                              onChange={(domainNames) =>
                                setDeploymentTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    kind: "AZURE_AFD",
                                    certificateName: draft.certificateName,
                                    secretName: draft.secretName,
                                    domainNames,
                                  },
                                }))
                              }
                              placeholder="Select domains..."
                            />
                          )}
                        </div>
                      );
                    }

                    if (draft.kind === "AZURE_APP_GW") {
                      const allowed =
                        parseAzureAppGwCredentialConfig(credential.configJson)
                          ?.listeners || [];
                      const optionValues = new Set(allowed);
                      for (const selected of draft.listenerNames) {
                        optionValues.add(selected);
                      }
                      const options = Array.from(optionValues).map((value) => ({
                        value,
                        label: value,
                      }));

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              Azure Application Gateway
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Select listeners from the credential allow-list
                              for{" "}
                              <span className="font-mono break-all">
                                {credentialXref}
                              </span>
                            </div>
                          </div>
                          <Input
                            className="h-10"
                            value={draft.sslCertName}
                            onChange={(event) => {
                              const sslCertName = event.target.value;
                              setDeploymentTargetDrafts((previous) => ({
                                ...previous,
                                [credentialXref]: {
                                  kind: "AZURE_APP_GW",
                                  sslCertName,
                                  listenerNames: draft.listenerNames,
                                },
                              }));
                            }}
                            placeholder="SSL cert name"
                          />
                          {allowed.length === 0 ? (
                            <Alert>
                              <AlertTitle>Missing allow-list</AlertTitle>
                              <AlertDescription>
                                Edit the credential to add its listeners first.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            <MultiSelect
                              options={options}
                              selected={draft.listenerNames}
                              onChange={(listenerNames) =>
                                setDeploymentTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    kind: "AZURE_APP_GW",
                                    sslCertName: draft.sslCertName,
                                    listenerNames,
                                  },
                                }))
                              }
                              placeholder="Select listeners..."
                            />
                          )}
                        </div>
                      );
                    }

                    if (draft.kind === "AZURE_APP_GW_CONTAINERS") {
                      const allowedNamespaces =
                        parseAzureAgcCredentialConfig(credential.configJson)
                          ?.secretNamespaces || [];

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              Azure App Gateway for Containers
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Secret names for allowed namespaces on{" "}
                              <span className="font-mono break-all">
                                {credentialXref}
                              </span>
                            </div>
                          </div>

                          {allowedNamespaces.length === 0 ? (
                            <Alert>
                              <AlertTitle>Missing allow-list</AlertTitle>
                              <AlertDescription>
                                Edit the credential to add its secret namespaces
                                first.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            <div className="space-y-2">
                              {(draft.secrets || []).map((pair, index) => (
                                <div
                                  key={`${pair.namespace}-${index}`}
                                  className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]"
                                >
                                  <Input
                                    aria-label={`Namespace ${index + 1}`}
                                    className="h-9"
                                    readOnly
                                    value={pair.namespace}
                                  />
                                  <Input
                                    aria-label={`Secret name ${index + 1}`}
                                    className="h-9"
                                    placeholder="secret-name"
                                    value={pair.secretName}
                                    onChange={(event) => {
                                      const secretName = event.target.value;
                                      setDeploymentTargetDrafts((previous) => ({
                                        ...previous,
                                        [credentialXref]: {
                                          kind: "AZURE_APP_GW_CONTAINERS",
                                          secrets: (draft.secrets || []).map(
                                            (existingPair, pairIndex) =>
                                              pairIndex === index
                                                ? {
                                                    ...existingPair,
                                                    secretName,
                                                  }
                                                : existingPair,
                                          ),
                                        },
                                      }));
                                    }}
                                  />
                                </div>
                              ))}
                              <p className="text-xs text-muted-foreground">
                                Namespaces are loaded from the credential.
                                Secret names are per certificate.
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    }

                    if (draft.kind === "AWS_LOAD_BALANCER") {
                      const allowed =
                        parseAwsLoadBalancerCredentialConfig(
                          credential.configJson,
                        )?.listeners || [];
                      const optionValues = new Set(allowed);
                      for (const selected of draft.listenerArns) {
                        optionValues.add(selected);
                      }
                      const options = Array.from(optionValues).map((value) => ({
                        value,
                        label: value,
                      }));

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              AWS Load Balancer
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Select listener ARNs from the credential
                              allow-list for{" "}
                              <span className="font-mono break-all">
                                {credentialXref}
                              </span>
                            </div>
                          </div>
                          {allowed.length === 0 ? (
                            <Alert>
                              <AlertTitle>Missing allow-list</AlertTitle>
                              <AlertDescription>
                                Edit the credential to add its listener ARNs
                                first.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            <MultiSelect
                              options={options}
                              selected={draft.listenerArns}
                              onChange={(listenerArns) =>
                                setDeploymentTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    kind: "AWS_LOAD_BALANCER",
                                    listenerArns,
                                  },
                                }))
                              }
                              placeholder="Select listeners..."
                            />
                          )}
                        </div>
                      );
                    }

                    if (draft.kind === "AWS_API_GATEWAY") {
                      const allowed =
                        parseAwsApiGatewayCredentialConfig(
                          credential.configJson,
                        )?.customDomains || [];
                      const optionValues = new Set(allowed);
                      for (const selected of draft.domainNames) {
                        optionValues.add(selected);
                      }
                      const options = Array.from(optionValues).map((value) => ({
                        value,
                        label: value,
                      }));

                      return (
                        <div
                          key={credentialXref}
                          className="space-y-3 rounded-lg"
                        >
                          <div className="space-y-1">
                            <div className="text-sm font-medium text-foreground">
                              AWS API Gateway
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Select domain names from the credential allow-list
                              for{" "}
                              <span className="font-mono break-all">
                                {credentialXref}
                              </span>
                            </div>
                          </div>
                          {allowed.length === 0 ? (
                            <Alert>
                              <AlertTitle>Missing allow-list</AlertTitle>
                              <AlertDescription>
                                Edit the credential to add its custom domains
                                first.
                              </AlertDescription>
                            </Alert>
                          ) : (
                            <MultiSelect
                              options={options}
                              selected={draft.domainNames}
                              onChange={(domainNames) =>
                                setDeploymentTargetDrafts((previous) => ({
                                  ...previous,
                                  [credentialXref]: {
                                    kind: "AWS_API_GATEWAY",
                                    domainNames,
                                  },
                                }))
                              }
                              placeholder="Select domains..."
                            />
                          )}
                        </div>
                      );
                    }

                    return null;
                  })}
                </div>
              </div>
            ) : null}

            {!dnsCredentialsQuery.isLoading &&
            (!isCertDeploymentEnabled ||
              !deploymentCredentialsQuery.isLoading) &&
            dnsCredentials.length === 0 &&
            (!isCertDeploymentEnabled || deploymentCredentials.length === 0) ? (
              <Alert>
                <AlertTitle>No saved credentials available</AlertTitle>
                <AlertDescription>
                  {!addDnsCredentialHref &&
                  !(isCertDeploymentEnabled && addDeploymentCredentialHref)
                    ? FEATURE_DISABLED_BODY
                    : isCertDeploymentEnabled
                      ? "Use the credential selectors above to add the required DNS provider or deployment target."
                      : "Use the DNS selector above to add the required credential."}
                </AlertDescription>
              </Alert>
            ) : null}

            <div className="rounded-lg border bg-muted p-4 text-sm dark:bg-card">
              <div className="font-medium text-foreground">Current config</div>
              <div className="mt-3 space-y-2 text-muted-foreground">
                <div className="flex gap-2">
                  DNS credential:{" "}
                  {currentDnsConfigXref ? (
                    <div className="flex items-center gap-1 text-sm text-primary">
                      <span className="break-all">
                        {dnsCredentialsByXref.get(currentDnsConfigXref)
                          ?.description || currentDnsConfigXref}
                      </span>
                      <CredentialReferenceTrigger
                        credentialXref={currentDnsConfigXref}
                        className="inline-flex items-center"
                        ariaLabel={`View DNS credential ${currentDnsConfigXref}`}
                      >
                        <ArrowSquareOutIcon className="size-3.5 hover:text-primary-300" />
                      </CredentialReferenceTrigger>
                    </div>
                  ) : (
                    <span className="font-mono text-xs break-all text-foreground">
                      Not attached
                    </span>
                  )}
                </div>
                {isCertDeploymentEnabled ? (
                  <div className="flex gap-2">
                    Deployment targets:{" "}
                    {normalizedCurrentDeploymentTargets.length > 0 ? (
                      <div className="flex w-full justify-start gap-3 overflow-x-auto text-sm text-foreground">
                        {normalizedCurrentDeploymentTargets.map((target) => (
                          <div
                            key={target}
                            className="flex min-w-fit items-center gap-1 text-primary"
                          >
                            <span>
                              {deploymentCredentialsByXref.get(target)
                                ?.description || target}
                            </span>
                            <CredentialReferenceTrigger
                              credentialXref={target}
                              className="inline-flex items-center"
                              ariaLabel={`View deployment target ${target}`}
                            >
                              <ArrowSquareOutIcon className="size-3.5 hover:text-primary-300" />
                            </CredentialReferenceTrigger>
                            <Separator
                              orientation="vertical"
                              className="h-4 bg-foreground"
                            />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-foreground">None attached</span>
                    )}
                  </div>
                ) : null}
              </div>
            </div>

            {canEnableAutomation ? (
              <Alert>
                <AlertTitle>Automation starts on renewal</AlertTitle>
                <AlertDescription>
                  This keeps the current active certificate in place. Automated
                  renewal will use the selected DNS credential on the next
                  renewal cycle.
                </AlertDescription>
              </Alert>
            ) : null}
          </div>
        ) : null}

        <DialogFooter className="gap-2 sm:justify-between">
          {isRouteAvailable(MANAGE_INTEGRATIONS_HREF) ? (
            <Button asChild variant="outline">
              <Link href={MANAGE_INTEGRATIONS_HREF}>Manage integrations</Link>
            </Button>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              disabled={
                isSaving ||
                dnsCredentialsQuery.isLoading ||
                (isCertDeploymentEnabled &&
                  deploymentCredentialsQuery.isLoading) ||
                !certificate ||
                !hasChanges
              }
              onClick={handleSave}
            >
              {isSaving ? (
                <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              {canEnableAutomation ? "Enable automation" : "Save changes"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function CertificateManagementSummaryCard({
  certificate,
  canManage,
  onManage,
  actionLabel = "Manage automation",
}: CertificateManagementSummaryCardProps) {
  const managementState = getCertificateManagementState(certificate);

  return (
    <Card className="bg-card-background">
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <CardTitle className="flex flex-wrap items-center justify-start gap-2 text-base font-semibold">
            Automation
            <Badge
              variant="outline"
              className={getCertificateManagementBadgeClass(managementState)}
            >
              {getCertificateManagementLabel(managementState)}
            </Badge>
          </CardTitle>
          <CardDescription className="mt-1">
            DNS and deployment settings for renewals.
          </CardDescription>
        </div>
        {canManage ? (
          <Button onClick={onManage} className="w-full shrink-0 sm:w-auto">
            <GearSixIcon className="h-4 w-4" />
            {actionLabel}
          </Button>
        ) : null}
      </CardHeader>
    </Card>
  );
}
