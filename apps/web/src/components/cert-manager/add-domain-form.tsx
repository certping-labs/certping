// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  CheckIcon,
  CircleNotchIcon,
  PlusIcon,
  XIcon,
} from "@phosphor-icons/react";

import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  CredentialReferenceMultiSelect,
  CredentialReferenceSelect,
} from "@/components/cert-manager/credential-reference-select";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCanAddCredential, useCredentials } from "@/hooks/credentials";
import { useFeatureFlags } from "@/hooks/use-feature-flags";
import {
  useIssueCertificateRequest,
  useIssueManualCertificateRequest,
} from "@/hooks/ssl";
import {
  KUBERNETES_ALL_NAMESPACES,
  buildAllNamespacesSecretMap,
  buildNsSecretMapFromPairs,
  createKubernetesSecretDraft,
  isKubernetesSecretsTarget,
  parseKubernetesCredentialConfig,
  sanitizeNamespaceSecretPairs,
  type NamespaceSecretPair,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import {
  buildSanCredentialGroups,
  getSanGroupingKey,
  normalizeSanDomains,
} from "@/lib/cert-manager/san-domain-helpers";
import type { CredentialRecord } from "@/types/ssl";
import { KubernetesNsMapEditor } from "@/components/cert-manager/kubernetes-ns-map-editor";
import { MultiSelect } from "@/components/ui/multi-select";
import {
  defaultAzureAfdCertificateName,
  defaultAzureAfdSecretName,
  defaultAzureAppGatewaySslCertName,
  defaultAzureKvCertificateName,
  findKeyVaultCertificateNameCollision,
  getCredentialKeyVaultUri,
  getDeploymentTargetApiValue,
  getDeploymentTargetConfigKind,
  type KeyVaultCertificateTarget,
} from "@/lib/cert-manager/deployment-target-config";
import { parseAwsLoadBalancerCredentialConfig } from "@/lib/credential-config-schemas/aws-load-balancer";
import { parseAwsApiGatewayCredentialConfig } from "@/lib/credential-config-schemas/aws-api-gateway";
import { parseAzureAfdCredentialConfig } from "@/lib/credential-config-schemas/azure-afd";
import { parseAzureAppGwCredentialConfig } from "@/lib/credential-config-schemas/azure-app-gw";
import { parseAzureAgcCredentialConfig } from "@/lib/credential-config-schemas/azure-agc";
import { CertificateDomainField } from "@/components/cert-manager/certificate-domain-field";
import { DigiCertApiKeyField } from "@/components/cert-manager/digicert-api-key-field";
import { BetaBadge } from "@/components/common/beta-badge";
import { isBetaIntegration } from "@/lib/integration-maturity";
import {
  BASE_SAN_CREDENTIAL,
  CERTIFICATE_AUTHORITY_OPTIONS,
  VALIDITY_DEFAULT_DAYS,
  VALIDITY_PRESETS,
  buildSanEntries,
  caAcceptsRequestedValidity,
  caNeedsCustomerKey,
  certificateRequestSchema,
  dedupeDomains,
  isValidSanDomain,
  parseSanInput,
  type CertificateRequestPrefill,
  type CertificateRequestValues,
} from "@/lib/cert-manager/certificate-request-form";
import {
  connectDnsProviderHref,
  issueCertificateHref,
} from "@/lib/cert-manager/certificate-journeys";

function SelectionToggle({
  checked,
  description,
  label,
  onCheckedChange,
}: {
  checked: boolean;
  description: string;
  label: string;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onCheckedChange(!checked)}
      className={`rounded-lg border p-4 text-left transition ${
        checked
          ? "border-primary bg-primary/5"
          : "border-border bg-background hover:border-primary/40"
      }`}
    >
      <div className="flex items-start gap-3">
        <div
          className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border ${
            checked
              ? "border-primary bg-primary text-primary-foreground"
              : "border-muted-foreground/40 bg-background text-transparent"
          }`}
        >
          <CheckIcon className="h-3 w-3" />
        </div>
        <div className="space-y-1">
          <div className="font-medium">{label}</div>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>
    </button>
  );
}

function SanCredentialRow({
  rootDomain,
  credentialOptions,
  domains,
  connectDnsHref,
  onValueChange,
  value,
}: {
  rootDomain: string;
  credentialOptions: CredentialRecord[];
  domains: string[];
  /** Omitted when the viewer may not add a DNS credential. */
  connectDnsHref?: () => string;
  onValueChange: (value: string) => void;
  value: string;
}) {
  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3 lg:grid-cols-[minmax(0,1fr)_280px]">
      <div className="min-w-0">
        <div className="truncate text-sm font-medium">{rootDomain}</div>
        <div className="text-xs text-muted-foreground">
          Applies to {domains.length} SAN hostname
          {domains.length === 1 ? "" : "s"}.
        </div>
        <div className="mt-1 truncate text-xs text-muted-foreground">
          {domains.join(", ")}
        </div>
      </div>
      <div className="space-y-2">
        <CredentialReferenceSelect
          addCredentialHref={connectDnsHref}
          addCredentialLabel="Connect DNS provider"
          credentials={credentialOptions}
          emptyOptionLabel="Use base DNS provider"
          emptyOptionValue={BASE_SAN_CREDENTIAL}
          onValueChange={onValueChange}
          placeholder="Use base DNS provider"
          value={value}
        />
      </div>
    </div>
  );
}

interface KubernetesDeploymentTargetDraft {
  useDefault: boolean;
  mapMode: "explicit" | "all_namespaces";
  pairs: NamespaceSecretPair[];
  allNamespacesSecret: string;
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

export function CertificateRequestForm({
  initialDomain = "",
  initialValues,
  sourceCertificateXref,
}: {
  initialDomain?: string;
  initialValues?: CertificateRequestPrefill;
  sourceCertificateXref?: string;
}) {
  const router = useRouter();
  const [sanDraft, setSanDraft] = useState("");
  const [kubernetesTargetDrafts, setKubernetesTargetDrafts] = useState<
    Record<string, KubernetesDeploymentTargetDraft>
  >({});
  const [deploymentTargetDrafts, setDeploymentTargetDrafts] = useState<
    Record<string, DeploymentTargetDraft>
  >({});

  const { isEnabled: isFeatureEnabled } = useFeatureFlags();
  const isLetsEncryptEnabled = isFeatureEnabled("LETS_ENCRYPT");
  const isDigicertEnabled = isFeatureEnabled("DIGICERT");
  const isGlobalSignEnabled = isFeatureEnabled("GLOBALSIGN");
  const isManualIssuanceEnabled = isFeatureEnabled(
    "CERTIFICATE_MANUAL_ISSUANCE",
  );
  const isCertDeploymentEnabled = isFeatureEnabled("CERTIFICATE_DEPLOYMENT");
  const canAddDnsCredential = useCanAddCredential("DNS");
  const canAddDeploymentCredential = useCanAddCredential("DEPLOYMENT");

  const caFlagMap: Record<string, boolean> = {
    LETS_ENCRYPT: isLetsEncryptEnabled,
    DIGICERT: isDigicertEnabled,
    GLOBALSIGN: isGlobalSignEnabled,
  };

  const enabledCaOptions = CERTIFICATE_AUTHORITY_OPTIONS.filter(
    (ca) => ca.flagKey === null || caFlagMap[ca.flagKey] !== false,
  );

  const dnsCredentialsQuery = useCredentials({
    category: "dns_credential",
    pollWhilePending: false,
  });
  const deploymentCredentialsQuery = useCredentials({
    category: "deployment_target",
    enabled: isCertDeploymentEnabled,
    pollWhilePending: false,
  });

  const automatedIssueMutation = useIssueCertificateRequest();
  const manualIssueMutation = useIssueManualCertificateRequest();

  const defaultCa = enabledCaOptions[0]?.value ?? "LETS_ENCRYPT";

  const form = useForm<CertificateRequestValues>({
    resolver: zodResolver(certificateRequestSchema),
    mode: "onBlur",
    reValidateMode: "onChange",
    defaultValues: {
      mode: "automated",
      domain: initialDomain,
      wildcard: false,
      san: false,
      sanDomains: [],
      sanCredentialMap: {},
      caProvider: defaultCa,
      caCredentialXref: "",
      dnsCredentialXref: "",
      validityDays: VALIDITY_DEFAULT_DAYS,
      deploymentTargets: [],
      ...initialValues,
    },
  });

  const hasChosenModeRef = useRef(Boolean(initialValues?.mode));
  const chooseMode = useCallback(
    (nextMode: CertificateRequestValues["mode"]) => {
      hasChosenModeRef.current = true;
      form.setValue("mode", nextMode, {
        shouldDirty: true,
        shouldValidate: true,
      });
    },
    [form],
  );

  const connectDnsHref = useCallback(
    () =>
      connectDnsProviderHref(
        issueCertificateHref({
          domain: form.getValues("domain"),
          wildcard: form.getValues("wildcard"),
          from: sourceCertificateXref,
        }),
      ),
    [form, sourceCertificateXref],
  );

  // Tracks whether the validity dropdown is on a preset or the custom input.
  const [validityMode, setValidityMode] = useState<"preset" | "custom">(
    "preset",
  );
  // Raw string backing the custom-validity input (decoupled from the numeric
  // form value so the field stays fully editable - clearable, mid-string edits).
  const [customValidityDraft, setCustomValidityDraft] = useState("");

  const mode = form.watch("mode");
  const wildcard = form.watch("wildcard");
  const sanEnabled = form.watch("san");
  const sanDomains = form.watch("sanDomains");
  const sanCredentialMap = form.watch("sanCredentialMap");
  const selectedDeploymentTargets = form.watch("deploymentTargets");
  const sanCredentialGroups = useMemo(
    () => buildSanCredentialGroups(sanDomains),
    [sanDomains],
  );

  const loadedDnsCredentials = dnsCredentialsQuery.data;
  const dnsCredentials = useMemo(
    () => loadedDnsCredentials || [],
    [loadedDnsCredentials],
  );
  const deploymentCredentials = useMemo(
    () =>
      isCertDeploymentEnabled ? deploymentCredentialsQuery.data || [] : [],
    [deploymentCredentialsQuery.data, isCertDeploymentEnabled],
  );
  const selectedKubernetesDeploymentCredentials = useMemo(
    () =>
      deploymentCredentials.filter((credential) => {
        const credentialId =
          credential.credentialXref || credential.alias || "";
        if (!selectedDeploymentTargets.includes(credentialId)) {
          return false;
        }
        return isKubernetesSecretsTarget(
          credential.targetType || credential.providerName,
        );
      }),
    [deploymentCredentials, selectedDeploymentTargets],
  );

  const selectedConfiguredDeploymentCredentials = useMemo(
    () =>
      deploymentCredentials.filter((credential) => {
        const credentialId =
          credential.credentialXref || credential.alias || "";
        if (
          !credentialId ||
          !selectedDeploymentTargets.includes(credentialId)
        ) {
          return false;
        }

        const kind = getDeploymentTargetConfigKind({
          targetType: credential.targetType,
          providerName: credential.providerName,
        });

        return kind !== "NONE" && kind !== "KUBERNETES_SECRETS";
      }),
    [deploymentCredentials, selectedDeploymentTargets],
  );

  useEffect(() => {
    if (sanEnabled) {
      return;
    }

    form.setValue("sanDomains", []);
    form.setValue("sanCredentialMap", {});
    setSanDraft("");
  }, [form, sanEnabled]);

  const removeRedundantSanDomains = useCallback(() => {
    if (!sanEnabled) {
      return;
    }

    const currentSanDomains = form.getValues("sanDomains");
    if (currentSanDomains.length === 0) {
      return;
    }

    const normalized = normalizeSanDomains(
      currentSanDomains,
      form.getValues("domain"),
      wildcard,
    );

    if (normalized.accepted.length !== currentSanDomains.length) {
      form.setValue("sanDomains", normalized.accepted, {
        shouldDirty: true,
        shouldValidate: true,
      });
      form.setError("sanDomains", {
        type: "manual",
        message: `Removed redundant SAN: ${normalized.conflicts
          .map((item) => item.domain)
          .join(", ")}`,
      });
    }
  }, [form, sanEnabled, wildcard]);

  useEffect(() => {
    removeRedundantSanDomains();
  }, [removeRedundantSanDomains]);

  useEffect(() => {
    const currentDomain = form.getValues("domain") || "certificate";
    setKubernetesTargetDrafts((previous) => {
      const next: Record<string, KubernetesDeploymentTargetDraft> = {};

      for (const credential of selectedKubernetesDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref) {
          continue;
        }
        const parsedConfig = parseKubernetesCredentialConfig(
          credential.configJson,
        );
        const allowedNamespaces = Array.isArray(parsedConfig?.namespaces)
          ? parsedConfig.namespaces
          : [];
        const supportsAllNamespaces =
          parsedConfig?.namespaces === KUBERNETES_ALL_NAMESPACES;
        next[credentialXref] =
          previous[credentialXref] ||
          createDefaultKubernetesDraft(
            currentDomain,
            allowedNamespaces,
            supportsAllNamespaces,
          );
      }

      return next;
    });
  }, [form, selectedKubernetesDeploymentCredentials]);

  useEffect(() => {
    const currentDomain = form.getValues("domain") || "certificate";
    setDeploymentTargetDrafts((previous) => {
      const next: Record<string, DeploymentTargetDraft> = {};

      for (const credential of selectedConfiguredDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref) {
          continue;
        }

        const apiValue = getDeploymentTargetApiValue({
          targetType: credential.targetType,
          providerName: credential.providerName,
        });
        const existing = previous[credentialXref];

        if (apiValue === "AZURE_KV" || apiValue === "GCP_CERT_MANAGER") {
          next[credentialXref] =
            existing &&
            (existing.kind === "AZURE_KV" ||
              existing.kind === "GCP_CERT_MANAGER")
              ? existing
              : {
                  kind:
                    apiValue === "GCP_CERT_MANAGER"
                      ? "GCP_CERT_MANAGER"
                      : "AZURE_KV",
                  certificateName: defaultAzureKvCertificateName(currentDomain),
                };
        } else if (apiValue === "AZURE_AFD") {
          const allowedDomains =
            parseAzureAfdCredentialConfig(credential.configJson)
              ?.customDomains || [];
          const normalizedCurrentDomain = currentDomain.trim();
          const defaultDomain =
            allowedDomains.length > 0
              ? allowedDomains.includes(normalizedCurrentDomain)
                ? normalizedCurrentDomain
                : allowedDomains[0]
              : normalizedCurrentDomain;
          next[credentialXref] =
            existing && existing.kind === "AZURE_AFD"
              ? existing
              : {
                  kind: "AZURE_AFD",
                  certificateName:
                    defaultAzureAfdCertificateName(defaultDomain),
                  secretName: defaultAzureAfdSecretName(defaultDomain),
                  domainNames: defaultDomain ? [defaultDomain] : [],
                };
        } else if (apiValue === "AZURE_APP_GW") {
          const allowedListeners =
            parseAzureAppGwCredentialConfig(credential.configJson)?.listeners ||
            [];
          const defaultListener =
            allowedListeners.length > 0 ? [allowedListeners[0]] : [];

          next[credentialXref] =
            existing && existing.kind === "AZURE_APP_GW"
              ? existing
              : {
                  kind: "AZURE_APP_GW",
                  sslCertName: defaultAzureAppGatewaySslCertName(currentDomain),
                  listenerNames: defaultListener,
                };
        } else if (apiValue === "AZURE_APP_GW_CONTAINERS") {
          const namespaces =
            parseAzureAgcCredentialConfig(credential.configJson)
              ?.secretNamespaces || [];
          const defaultDraft = createKubernetesSecretDraft({
            domain: currentDomain,
            allowedNamespaces: namespaces,
            supportsAllNamespaces: false,
          });

          next[credentialXref] =
            existing && existing.kind === "AZURE_APP_GW_CONTAINERS"
              ? existing
              : {
                  kind: "AZURE_APP_GW_CONTAINERS",
                  secrets: defaultDraft.pairs,
                };
        } else if (apiValue === "AWS_ALB" || apiValue === "AWS_NLB") {
          next[credentialXref] =
            existing && existing.kind === "AWS_LOAD_BALANCER"
              ? existing
              : { kind: "AWS_LOAD_BALANCER", listenerArns: [] };
        } else if (
          apiValue === "AWS_API_GW_REST" ||
          apiValue === "AWS_API_GW_HTTP"
        ) {
          const allowedDomains =
            parseAwsApiGatewayCredentialConfig(credential.configJson)
              ?.customDomains || [];
          const normalizedCurrentDomain = currentDomain.trim();
          const defaultDomain =
            allowedDomains.length > 0
              ? allowedDomains.includes(normalizedCurrentDomain)
                ? normalizedCurrentDomain
                : allowedDomains[0]
              : normalizedCurrentDomain;
          next[credentialXref] =
            existing && existing.kind === "AWS_API_GATEWAY"
              ? existing
              : {
                  kind: "AWS_API_GATEWAY",
                  domainNames: defaultDomain ? [defaultDomain] : [],
                };
        }
      }

      return next;
    });
  }, [form, selectedConfiguredDeploymentCredentials]);

  // If the currently selected CA gets disabled (e.g. an admin toggles it off
  // while the form is open), fall back to the first available enabled CA.
  const selectedCa = form.watch("caProvider");
  const acceptsRequestedValidity = caAcceptsRequestedValidity(selectedCa);
  useEffect(() => {
    const stillAvailable = enabledCaOptions.some(
      (ca) => ca.value === selectedCa,
    );
    if (!stillAvailable && enabledCaOptions.length > 0) {
      form.setValue("caProvider", enabledCaOptions[0].value, {
        shouldDirty: true,
      });
    }
  }, [enabledCaOptions, form, selectedCa]);

  useEffect(() => {
    if (!loadedDnsCredentials) {
      return;
    }
    const selectedDnsCredential = form.getValues("dnsCredentialXref");
    if (
      selectedDnsCredential &&
      !loadedDnsCredentials.some(
        (credential) =>
          (credential.credentialXref || credential.alias) ===
          selectedDnsCredential,
      )
    ) {
      form.setValue("dnsCredentialXref", "");
    }
    if (
      loadedDnsCredentials.length === 0 &&
      isManualIssuanceEnabled &&
      !hasChosenModeRef.current
    ) {
      form.setValue("mode", "manual");
    }
  }, [form, isManualIssuanceEnabled, loadedDnsCredentials]);

  const loadedDeploymentCredentials = deploymentCredentialsQuery.data;
  useEffect(() => {
    if (!loadedDeploymentCredentials) {
      return;
    }
    const known = new Set(
      loadedDeploymentCredentials.map(
        (credential) => credential.credentialXref || credential.alias,
      ),
    );
    const currentTargets = form.getValues("deploymentTargets");
    const keptTargets = currentTargets.filter((target) => known.has(target));
    if (keptTargets.length !== currentTargets.length) {
      form.setValue("deploymentTargets", keptTargets);
    }
  }, [form, loadedDeploymentCredentials]);

  // If manual issuance gets disabled while the form is open, switch back to automated.
  useEffect(() => {
    if (!isManualIssuanceEnabled && mode === "manual") {
      form.setValue("mode", "automated", { shouldDirty: true });
    }
  }, [isManualIssuanceEnabled, mode, form]);

  useEffect(() => {
    if (!isCertDeploymentEnabled && selectedDeploymentTargets.length > 0) {
      form.setValue("deploymentTargets", [], {
        shouldDirty: true,
        shouldValidate: true,
      });
    }
  }, [form, isCertDeploymentEnabled, selectedDeploymentTargets.length]);

  const isSubmitting =
    automatedIssueMutation.isPending || manualIssueMutation.isPending;

  const commitSanDraft = () => {
    if (!sanDraft.trim()) {
      return;
    }

    const baseDomain = form.getValues("domain").trim().toLowerCase();
    const wildcardEnabled = form.getValues("wildcard");
    const parsedDomains = parseSanInput(sanDraft);
    const invalidDomains = parsedDomains.filter(
      (domain) => !isValidSanDomain(domain),
    );

    if (invalidDomains.length > 0) {
      form.setError("sanDomains", {
        type: "manual",
        message: `Invalid SAN domain: ${invalidDomains[0]}`,
      });
      return;
    }

    const currentValues = form
      .getValues("sanDomains")
      .map((item) => item.toLowerCase());
    const normalized = normalizeSanDomains(
      [...currentValues, ...parsedDomains],
      baseDomain,
      wildcardEnabled,
    );
    if (normalized.conflicts.length > 0) {
      const firstConflict = normalized.conflicts[0];
      form.setError("sanDomains", {
        type: "manual",
        message: `${firstConflict.domain} is ${firstConflict.reason}.`,
      });
      return;
    }

    const nextValues = dedupeDomains(normalized.accepted);

    form.setValue("sanDomains", nextValues, {
      shouldDirty: true,
      shouldValidate: true,
    });
    form.clearErrors("sanDomains");
    setSanDraft("");
  };

  const removeSanDomain = (domain: string) => {
    const nextDomains = form
      .getValues("sanDomains")
      .filter((item) => item !== domain);
    const nextCredentialMap = { ...form.getValues("sanCredentialMap") };
    delete nextCredentialMap[domain];

    form.setValue("sanDomains", nextDomains, {
      shouldDirty: true,
      shouldValidate: true,
    });
    form.setValue("sanCredentialMap", nextCredentialMap, {
      shouldDirty: true,
    });
  };

  useEffect(() => {
    const allowedKeys = new Set<string>();
    for (const sanDomain of sanDomains) {
      allowedKeys.add(sanDomain);
      allowedKeys.add(getSanGroupingKey(sanDomain));
    }

    const currentMap = form.getValues("sanCredentialMap");
    const nextMap: Record<string, string> = {};
    for (const [key, value] of Object.entries(currentMap)) {
      if (allowedKeys.has(key)) {
        nextMap[key] = value;
      }
    }

    if (Object.keys(nextMap).length !== Object.keys(currentMap).length) {
      form.setValue("sanCredentialMap", nextMap, {
        shouldDirty: true,
      });
    }
  }, [form, sanDomains]);

  const onSubmit = form.handleSubmit(async (values) => {
    const primaryDomain = values.domain.trim().toLowerCase();
    const sanDomainEntries = buildSanEntries(values);

    if (values.mode === "automated") {
      const deploymentTargetConfigs = [];
      for (const credential of selectedKubernetesDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref) {
          continue;
        }

        const draft = kubernetesTargetDrafts[credentialXref];
        if (!draft) {
          form.setError("deploymentTargets", {
            type: "manual",
            message: `Missing Kubernetes config draft for ${credentialXref}`,
          });
          return;
        }

        if (draft.useDefault) {
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            config: { useDefault: true },
          });
          continue;
        }

        if (draft.mapMode === "all_namespaces") {
          const secretName = draft.allNamespacesSecret.trim();
          if (!secretName) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide all_namespaces secret for ${credentialXref}`,
            });
            return;
          }
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
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
          form.setError("deploymentTargets", {
            type: "manual",
            message:
              error instanceof Error
                ? `${credentialXref}: ${error.message}`
                : `Invalid namespace mapping for ${credentialXref}`,
          });
          return;
        }

        if (pairs.length === 0) {
          form.setError("deploymentTargets", {
            type: "manual",
            message: `Provide namespace mappings for ${credentialXref}`,
          });
          return;
        }

        deploymentTargetConfigs.push({
          deploymentCredentialXref: credentialXref,
          config: {
            useDefault: false,
            nsSecretMap: buildNsSecretMapFromPairs(pairs),
          },
        });
      }

      const keyVaultTargets: KeyVaultCertificateTarget[] = [];
      for (const credential of selectedConfiguredDeploymentCredentials) {
        const credentialXref = credential.credentialXref || credential.alias;
        if (!credentialXref) {
          continue;
        }

        const draft = deploymentTargetDrafts[credentialXref];
        if (!draft) {
          form.setError("deploymentTargets", {
            type: "manual",
            message: `Missing deployment config draft for ${credentialXref}`,
          });
          return;
        }

        if (draft.kind === "AZURE_KV" || draft.kind === "GCP_CERT_MANAGER") {
          const certificateName = draft.certificateName.trim();
          if (!certificateName) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide certificateName for ${credentialXref}`,
            });
            return;
          }
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            targets: { certificateName },
          });
        } else if (draft.kind === "AZURE_AFD") {
          const certificateName = draft.certificateName.trim();
          const secretName = draft.secretName.trim();
          const domainNames = (draft.domainNames || [])
            .map((value) => value.trim())
            .filter((value) => value.length > 0);

          if (!certificateName || !secretName || domainNames.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide certificateName, secretName, and at least one domainName for ${credentialXref}`,
            });
            return;
          }

          const allowedDomains =
            parseAzureAfdCredentialConfig(credential.configJson)
              ?.customDomains || [];
          if (allowedDomains.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: no custom domains are configured on this credential`,
            });
            return;
          }
          const allowedSet = new Set(allowedDomains);
          const invalid = domainNames.find((name) => !allowedSet.has(name));
          if (invalid) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: domain name must be selected from the credential allow-list`,
            });
            return;
          }

          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            targets: { certificateName, secretName, domainNames },
          });
        } else if (draft.kind === "AWS_LOAD_BALANCER") {
          const listenerArns = (draft.listenerArns || [])
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
          if (listenerArns.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide at least one listenerArn for ${credentialXref}`,
            });
            return;
          }

          const allowedListeners =
            parseAwsLoadBalancerCredentialConfig(credential.configJson)
              ?.listeners || [];
          const allowedSet = new Set(allowedListeners);
          const invalid = listenerArns.find((arn) => !allowedSet.has(arn));
          if (invalid) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: listener ARN must be selected from the credential allow-list`,
            });
            return;
          }
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            targets: { listenerArns },
          });
        } else if (draft.kind === "AZURE_APP_GW") {
          const sslCertName = draft.sslCertName.trim();
          const listenerNames = (draft.listenerNames || [])
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
          if (!sslCertName || listenerNames.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide sslCertName and at least one listener for ${credentialXref}`,
            });
            return;
          }

          const allowedListeners =
            parseAzureAppGwCredentialConfig(credential.configJson)?.listeners ||
            [];
          const allowedSet = new Set(allowedListeners);
          const invalid = listenerNames.find((name) => !allowedSet.has(name));
          if (invalid) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: listener must be selected from the credential allow-list`,
            });
            return;
          }
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            targets: { sslCertName, listenerNames },
          });
        } else if (draft.kind === "AZURE_APP_GW_CONTAINERS") {
          const allowedNamespaces =
            parseAzureAgcCredentialConfig(credential.configJson)
              ?.secretNamespaces || [];
          const allowedSet = new Set(allowedNamespaces);

          const secrets = sanitizeNamespaceSecretPairs(draft.secrets || []);
          if (secrets.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide at least one namespace secret mapping for ${credentialXref}`,
            });
            return;
          }
          const invalid = secrets.find(
            (pair) => !allowedSet.has(pair.namespace),
          );
          if (invalid) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: namespace must be selected from the credential allow-list`,
            });
            return;
          }

          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
            targets: { secrets },
          });
        } else if (draft.kind === "AWS_API_GATEWAY") {
          const domainNames = (draft.domainNames || [])
            .map((value) => value.trim())
            .filter((value) => value.length > 0);
          if (domainNames.length === 0) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `Provide at least one domainName for ${credentialXref}`,
            });
            return;
          }

          const allowedDomains =
            parseAwsApiGatewayCredentialConfig(credential.configJson)
              ?.customDomains || [];
          const allowedSet = new Set(allowedDomains);
          const invalid = domainNames.find((name) => !allowedSet.has(name));
          if (invalid) {
            form.setError("deploymentTargets", {
              type: "manual",
              message: `${credentialXref}: domain name must be selected from the credential allow-list`,
            });
            return;
          }
          deploymentTargetConfigs.push({
            deploymentCredentialXref: credentialXref,
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
        form.setError("deploymentTargets", {
          type: "manual",
          message: keyVaultCollision,
        });
        return;
      }

      const result = await automatedIssueMutation.mutateAsync({
        domain: primaryDomain,
        wildcard: values.wildcard,
        san: values.san,
        caProvider: values.caProvider,
        caCredentialXref: caNeedsCustomerKey(values.caProvider)
          ? values.caCredentialXref
          : undefined,
        dnsCredentialXref: values.dnsCredentialXref,
        validityDays: caAcceptsRequestedValidity(values.caProvider)
          ? values.validityDays
          : undefined,
        sanDomainEntries,
        deploymentTargets: values.deploymentTargets,
        deploymentTargetConfigs:
          deploymentTargetConfigs.length > 0
            ? deploymentTargetConfigs
            : undefined,
      });

      router.push(
        `/cert-manager/manage/${encodeURIComponent(result.certificateXref)}`,
      );
      return;
    }

    const result = await manualIssueMutation.mutateAsync({
      domain: primaryDomain,
      wildcard: values.wildcard,
      san: values.san,
      sanDomainEntries,
    });

    router.push(
      `/cert-manager/manage/${encodeURIComponent(result.certificateXref)}`,
    );
  });

  return (
    <>
      <Card className="w-full max-w-3xl">
        <CardContent className="p-5 sm:p-6">
          <Form {...form}>
            <form className="space-y-6" onSubmit={onSubmit}>
              <div className="space-y-5">
                <div className="space-y-3">
                  <FormLabel>Issuance mode</FormLabel>
                  <Tabs
                    value={mode}
                    onValueChange={(value) =>
                      chooseMode(value as CertificateRequestValues["mode"])
                    }
                  >
                    <TabsList className="">
                      <TabsTrigger value="automated">
                        Automatic (connect your DNS provider)
                      </TabsTrigger>
                      {isManualIssuanceEnabled && (
                        <TabsTrigger value="manual">
                          I&apos;ll add a DNS record
                        </TabsTrigger>
                      )}
                    </TabsList>
                  </Tabs>
                </div>

                <CertificateDomainField
                  control={form.control}
                  onDomainBlur={removeRedundantSanDomains}
                  wildcard={wildcard}
                />

                <div className="grid gap-3 md:grid-cols-2">
                  <SelectionToggle
                    checked={wildcard}
                    label="Wildcard"
                    description="Include first-level subdomains."
                    onCheckedChange={(checked) =>
                      form.setValue("wildcard", checked, {
                        shouldDirty: true,
                      })
                    }
                  />
                  <SelectionToggle
                    checked={sanEnabled}
                    label="SAN"
                    description="Add extra hostnames to the same certificate."
                    onCheckedChange={(checked) =>
                      form.setValue("san", checked, {
                        shouldDirty: true,
                        shouldValidate: true,
                      })
                    }
                  />
                </div>

                {sanEnabled ? (
                  <div className="space-y-4 rounded-xl border bg-muted/20 p-4">
                    <div className="space-y-2">
                      <FormLabel>Additional SAN domains</FormLabel>
                      <div className="flex flex-col gap-3 sm:flex-row">
                        <Input
                          value={sanDraft}
                          onBlur={commitSanDraft}
                          onChange={(event) => setSanDraft(event.target.value)}
                          onKeyDown={(event) => {
                            if (event.key === "Enter" || event.key === ",") {
                              event.preventDefault();
                              commitSanDraft();
                            }
                          }}
                          className="h-10"
                          placeholder="www.example.com, api.example.com"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          className="shrink-0"
                          onClick={commitSanDraft}
                        >
                          <PlusIcon className="h-4 w-4" />
                          Add
                        </Button>
                      </div>
                      {form.formState.errors.sanDomains?.message ? (
                        <p className="text-sm font-medium text-destructive">
                          {String(form.formState.errors.sanDomains.message)}
                        </p>
                      ) : null}
                    </div>

                    {sanDomains.length > 0 ? (
                      <div className="space-y-4">
                        <div className="flex flex-wrap gap-2">
                          {sanDomains.map((domain) => (
                            <Badge
                              key={domain}
                              variant="secondary"
                              className="max-w-full gap-2 px-3 py-1"
                            >
                              <span className="truncate">{domain}</span>
                              <button
                                type="button"
                                onClick={() => removeSanDomain(domain)}
                                className="rounded-full text-muted-foreground hover:text-foreground"
                              >
                                <XIcon className="h-3 w-3" />
                                <span className="sr-only">Remove {domain}</span>
                              </button>
                            </Badge>
                          ))}
                        </div>

                        {mode === "automated" ? (
                          <div className="space-y-3">
                            <div className="text-sm font-medium">
                              SAN DNS credentials
                            </div>
                            <div className="space-y-3">
                              {sanCredentialGroups.map((group) => (
                                <SanCredentialRow
                                  key={group.key}
                                  connectDnsHref={
                                    canAddDnsCredential
                                      ? connectDnsHref
                                      : undefined
                                  }
                                  credentialOptions={dnsCredentials}
                                  rootDomain={group.key}
                                  domains={group.domains}
                                  value={
                                    sanCredentialMap[group.key] ||
                                    BASE_SAN_CREDENTIAL
                                  }
                                  onValueChange={(value) => {
                                    const nextMap = {
                                      ...form.getValues("sanCredentialMap"),
                                    };
                                    if (value === BASE_SAN_CREDENTIAL) {
                                      delete nextMap[group.key];
                                    } else {
                                      nextMap[group.key] = value;
                                    }
                                    form.setValue("sanCredentialMap", nextMap, {
                                      shouldDirty: true,
                                    });
                                  }}
                                />
                              ))}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                ) : null}

                <div className="border-t pt-6">
                  {mode === "manual" ? (
                    <div className="space-y-4">
                      <Alert>
                        <AlertDescription>
                          After you request it, we show the TXT records to add,
                          one for each name on the certificate. Once
                          they&apos;re published, select Validate DNS to finish.
                          Manual certificates don&apos;t renew automatically.
                        </AlertDescription>
                      </Alert>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <FormField
                        control={form.control}
                        name="dnsCredentialXref"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Main DNS credential</FormLabel>
                            <FormControl>
                              <CredentialReferenceSelect
                                addCredentialHref={
                                  canAddDnsCredential
                                    ? connectDnsHref
                                    : undefined
                                }
                                addCredentialLabel="Connect DNS provider"
                                credentials={dnsCredentials}
                                onValueChange={field.onChange}
                                placeholder="Select a DNS connection"
                                value={field.value}
                              />
                            </FormControl>
                            <FormDescription>
                              Used for the main domain and as the default SAN
                              credential.
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="caProvider"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Certificate authority</FormLabel>
                            <Select
                              onValueChange={field.onChange}
                              value={field.value}
                            >
                              <FormControl>
                                <SelectTrigger className="h-10">
                                  <SelectValue placeholder="Select a CA" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                {enabledCaOptions.map((ca) => (
                                  <SelectItem key={ca.value} value={ca.value}>
                                    <span className="flex items-center gap-2">
                                      <span>{ca.label}</span>
                                      {isBetaIntegration("CA", ca.value) ? (
                                        <BetaBadge />
                                      ) : null}
                                    </span>
                                  </SelectItem>
                                ))}
                                {enabledCaOptions.length === 0 && (
                                  <div className="px-2 py-3 text-sm text-muted-foreground">
                                    No certificate authority is available. Ask
                                    your CertPing administrator.
                                  </div>
                                )}
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      {mode === "automated" &&
                      caNeedsCustomerKey(selectedCa) ? (
                        <DigiCertApiKeyField form={form} />
                      ) : null}

                      {acceptsRequestedValidity ? (
                        <FormField
                          control={form.control}
                          name="validityDays"
                          render={({ field }) => {
                            const isPreset = VALIDITY_PRESETS.some(
                              (preset) => preset.value === field.value,
                            );
                            const showCustom =
                              validityMode === "custom" || !isPreset;
                            return (
                              <FormItem>
                                <FormLabel>Certificate validity</FormLabel>
                                <Select
                                  value={
                                    showCustom ? "custom" : String(field.value)
                                  }
                                  onValueChange={(value) => {
                                    if (value === "custom") {
                                      setCustomValidityDraft(
                                        typeof field.value === "number"
                                          ? String(field.value)
                                          : "",
                                      );
                                      setValidityMode("custom");
                                      return;
                                    }
                                    setValidityMode("preset");
                                    field.onChange(Number(value));
                                  }}
                                >
                                  <FormControl>
                                    <SelectTrigger className="h-10">
                                      <SelectValue placeholder="Select validity" />
                                    </SelectTrigger>
                                  </FormControl>
                                  <SelectContent>
                                    {VALIDITY_PRESETS.map((preset) => (
                                      <SelectItem
                                        key={preset.value}
                                        value={String(preset.value)}
                                      >
                                        {preset.label}
                                      </SelectItem>
                                    ))}
                                    <SelectItem value="custom">
                                      Custom
                                    </SelectItem>
                                  </SelectContent>
                                </Select>
                                {showCustom ? (
                                  <FormControl>
                                    <Input
                                      type="text"
                                      inputMode="numeric"
                                      className="h-10"
                                      placeholder="Days (1–398)"
                                      value={customValidityDraft}
                                      onChange={(event) => {
                                        const raw = event.target.value
                                          .replace(/[^0-9]/g, "")
                                          .slice(0, 3);
                                        setCustomValidityDraft(raw);
                                        field.onChange(
                                          raw === "" ? undefined : Number(raw),
                                        );
                                      }}
                                    />
                                  </FormControl>
                                ) : null}
                                <FormDescription>
                                  Requested lifetime for paid CAs. Each CA
                                  enforces its own cap, so the issued
                                  certificate may be shorter than requested.
                                </FormDescription>
                                <FormMessage />
                              </FormItem>
                            );
                          }}
                        />
                      ) : null}

                      {isCertDeploymentEnabled ? (
                        <div className="space-y-3">
                          <div>
                            <h3 className="text-sm font-medium">
                              Deployment targets
                            </h3>
                            <p className="text-sm text-muted-foreground">
                              Optional saved deployment targets to use after
                              issuance.
                            </p>
                          </div>
                          <CredentialReferenceMultiSelect
                            addCredentialHref={
                              canAddDeploymentCredential
                                ? "/integrations/connections/add?type=DEPLOYMENT"
                                : undefined
                            }
                            addCredentialLabel="Add deployment target"
                            credentials={deploymentCredentials}
                            onValueChange={(values) =>
                              form.setValue("deploymentTargets", values, {
                                shouldDirty: true,
                                shouldValidate: true,
                              })
                            }
                            placeholder="Select deployment targets"
                            value={selectedDeploymentTargets}
                          />
                          {deploymentCredentials.length === 0 ? (
                            <Alert>
                              <AlertTitle>No deployment targets yet</AlertTitle>
                              <AlertDescription>
                                You can still issue now and attach deployment
                                targets later. Choose “Add deployment target”
                                above to create one now.
                              </AlertDescription>
                            </Alert>
                          ) : null}
                          {form.formState.errors.deploymentTargets?.message ? (
                            <p className="text-sm font-medium text-destructive">
                              {String(
                                form.formState.errors.deploymentTargets.message,
                              )}
                            </p>
                          ) : null}
                        </div>
                      ) : null}
                      {selectedKubernetesDeploymentCredentials.length > 0 ? (
                        <div className="space-y-4 rounded-xl">
                          <div className="space-y-1">
                            <h4 className="text-sm font-medium">
                              Kubernetes deployment target configs
                            </h4>
                            <p className="text-xs text-muted-foreground">
                              For each Kubernetes target, provide `useDefault`
                              or explicit `nsSecretMap` config.
                            </p>
                          </div>
                          {selectedKubernetesDeploymentCredentials.map(
                            (credential) => {
                              const credentialXref =
                                credential.credentialXref ||
                                credential.alias ||
                                "";
                              const draft =
                                kubernetesTargetDrafts[credentialXref];
                              if (!draft) {
                                return null;
                              }

                              const parsedConfig =
                                parseKubernetesCredentialConfig(
                                  credential.configJson,
                                );
                              const allowedNamespaces = Array.isArray(
                                parsedConfig?.namespaces,
                              )
                                ? parsedConfig.namespaces
                                : [];
                              const supportsAllNamespaces =
                                parsedConfig?.namespaces ===
                                KUBERNETES_ALL_NAMESPACES;
                              const defaultDraft = createDefaultKubernetesDraft(
                                form.getValues("domain") || "certificate",
                                allowedNamespaces,
                                supportsAllNamespaces,
                              );

                              return (
                                <div
                                  key={credentialXref}
                                  className="space-y-3 rounded-lg border bg-background p-3"
                                >
                                  <div className="text-sm font-medium">
                                    {credential.description || credentialXref}
                                  </div>

                                  <Select
                                    value={
                                      draft.useDefault ? "saved" : "explicit"
                                    }
                                    onValueChange={(value) =>
                                      setKubernetesTargetDrafts((previous) => ({
                                        ...previous,
                                        [credentialXref]: {
                                          ...draft,
                                          useDefault: value === "saved",
                                        },
                                      }))
                                    }
                                  >
                                    <SelectTrigger className="h-10">
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="explicit">
                                        Provide explicit mapping
                                      </SelectItem>
                                      <SelectItem value="saved">
                                        Use saved default config
                                      </SelectItem>
                                    </SelectContent>
                                  </Select>

                                  {!draft.useDefault ? (
                                    <KubernetesNsMapEditor
                                      allNamespacesSecret={
                                        draft.allNamespacesSecret
                                      }
                                      mapMode={draft.mapMode}
                                      onAllNamespacesSecretChange={(value) =>
                                        setKubernetesTargetDrafts(
                                          (previous) => ({
                                            ...previous,
                                            [credentialXref]: {
                                              ...draft,
                                              allNamespacesSecret: value,
                                            },
                                          }),
                                        )
                                      }
                                      onMapModeChange={(value) =>
                                        setKubernetesTargetDrafts(
                                          (previous) => ({
                                            ...previous,
                                            [credentialXref]: {
                                              ...draft,
                                              mapMode: value,
                                            },
                                          }),
                                        )
                                      }
                                      onPairChange={(index, fieldName, value) =>
                                        setKubernetesTargetDrafts(
                                          (previous) => ({
                                            ...previous,
                                            [credentialXref]: {
                                              ...draft,
                                              pairs: draft.pairs.map(
                                                (pair, pairIndex) =>
                                                  pairIndex === index
                                                    ? {
                                                        ...pair,
                                                        [fieldName]: value,
                                                      }
                                                    : pair,
                                              ),
                                            },
                                          }),
                                        )
                                      }
                                      onResetDefaults={() =>
                                        setKubernetesTargetDrafts(
                                          (previous) => ({
                                            ...previous,
                                            [credentialXref]: {
                                              ...draft,
                                              pairs: defaultDraft.pairs,
                                            },
                                          }),
                                        )
                                      }
                                      pairs={draft.pairs}
                                      supportsAllNamespaces={
                                        supportsAllNamespaces
                                      }
                                    />
                                  ) : null}
                                </div>
                              );
                            },
                          )}
                        </div>
                      ) : null}

                      {selectedConfiguredDeploymentCredentials.length > 0 ? (
                        <div className="space-y-4 rounded-xl">
                          <div className="space-y-1">
                            <h4 className="text-sm font-medium">
                              Deployment target configs
                            </h4>
                            <p className="text-xs text-muted-foreground">
                              Some deployment targets require per-domain
                              metadata. These values are sent as `targets`
                              during issuance.
                            </p>
                          </div>

                          {selectedConfiguredDeploymentCredentials.map(
                            (credential) => {
                              const credentialXref =
                                credential.credentialXref ||
                                credential.alias ||
                                "";
                              const draft =
                                deploymentTargetDrafts[credentialXref];
                              if (!credentialXref || !draft) {
                                return null;
                              }

                              if (
                                draft.kind === "AZURE_KV" ||
                                draft.kind === "GCP_CERT_MANAGER"
                              ) {
                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <div className="space-y-1">
                                      <FormLabel className="text-xs text-muted-foreground">
                                        Certificate name
                                      </FormLabel>
                                      <Input
                                        className="h-10"
                                        value={draft.certificateName}
                                        onChange={(event) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                certificateName:
                                                  event.target.value,
                                              },
                                            }),
                                          )
                                        }
                                      />
                                    </div>
                                  </div>
                                );
                              }

                              if (draft.kind === "AZURE_AFD") {
                                const allowed =
                                  parseAzureAfdCredentialConfig(
                                    credential.configJson,
                                  )?.customDomains || [];
                                const optionValues = new Set(allowed);
                                for (const selected of draft.domainNames) {
                                  optionValues.add(selected);
                                }
                                const options = Array.from(optionValues).map(
                                  (value) => ({ value, label: value }),
                                );

                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <div className="space-y-1">
                                      <FormLabel className="text-xs text-muted-foreground">
                                        Certificate name
                                      </FormLabel>
                                      <Input
                                        className="h-10"
                                        value={draft.certificateName}
                                        onChange={(event) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                certificateName:
                                                  event.target.value,
                                              },
                                            }),
                                          )
                                        }
                                      />
                                    </div>
                                    <div className="space-y-1">
                                      <FormLabel className="text-xs text-muted-foreground">
                                        Secret name
                                      </FormLabel>
                                      <Input
                                        className="h-10"
                                        value={draft.secretName}
                                        onChange={(event) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                secretName: event.target.value,
                                              },
                                            }),
                                          )
                                        }
                                      />
                                    </div>
                                    <FormLabel className="text-xs text-muted-foreground">
                                      Domain names (from allow-list)
                                    </FormLabel>
                                    {allowed.length === 0 ? (
                                      <p className="text-xs text-muted-foreground">
                                        Edit this credential and add custom
                                        domains first.
                                      </p>
                                    ) : (
                                      <MultiSelect
                                        options={options}
                                        selected={draft.domainNames}
                                        onChange={(domainNames) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                domainNames,
                                              },
                                            }),
                                          )
                                        }
                                        placeholder="Select domains..."
                                      />
                                    )}
                                  </div>
                                );
                              }

                              if (draft.kind === "AZURE_APP_GW") {
                                const allowed =
                                  parseAzureAppGwCredentialConfig(
                                    credential.configJson,
                                  )?.listeners || [];
                                const optionValues = new Set(allowed);
                                for (const selected of draft.listenerNames) {
                                  optionValues.add(selected);
                                }
                                const options = Array.from(optionValues).map(
                                  (value) => ({ value, label: value }),
                                );

                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <div className="space-y-1">
                                      <FormLabel className="text-xs text-muted-foreground">
                                        SSL certificate name
                                      </FormLabel>
                                      <Input
                                        className="h-10"
                                        value={draft.sslCertName}
                                        onChange={(event) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                sslCertName: event.target.value,
                                              },
                                            }),
                                          )
                                        }
                                      />
                                    </div>
                                    <div className="space-y-1">
                                      <FormLabel className="text-xs text-muted-foreground">
                                        Listener names (from allow-list)
                                      </FormLabel>
                                      {allowed.length === 0 ? (
                                        <p className="text-xs text-muted-foreground">
                                          Edit this credential and add listener
                                          names first.
                                        </p>
                                      ) : (
                                        <MultiSelect
                                          options={options}
                                          selected={draft.listenerNames}
                                          onChange={(listenerNames) =>
                                            setDeploymentTargetDrafts(
                                              (previous) => ({
                                                ...previous,
                                                [credentialXref]: {
                                                  ...draft,
                                                  listenerNames,
                                                },
                                              }),
                                            )
                                          }
                                          placeholder="Select listeners..."
                                        />
                                      )}
                                    </div>
                                  </div>
                                );
                              }

                              if (draft.kind === "AZURE_APP_GW_CONTAINERS") {
                                const allowedNamespaces =
                                  parseAzureAgcCredentialConfig(
                                    credential.configJson,
                                  )?.secretNamespaces || [];

                                const secrets = draft.secrets || [];
                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <FormLabel className="text-xs text-muted-foreground">
                                      Namespace secrets (from allow-list)
                                    </FormLabel>
                                    {allowedNamespaces.length === 0 ? (
                                      <p className="text-xs text-muted-foreground">
                                        Edit this credential and add allowed
                                        secret namespaces first.
                                      </p>
                                    ) : (
                                      <div className="space-y-2">
                                        {secrets.map((pair, index) => (
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
                                              onChange={(event) =>
                                                setDeploymentTargetDrafts(
                                                  (previous) => ({
                                                    ...previous,
                                                    [credentialXref]: {
                                                      ...draft,
                                                      secrets: (
                                                        draft.secrets || []
                                                      ).map(
                                                        (
                                                          secretPair,
                                                          pairIndex,
                                                        ) =>
                                                          pairIndex === index
                                                            ? {
                                                                ...secretPair,
                                                                secretName:
                                                                  event.target
                                                                    .value,
                                                              }
                                                            : secretPair,
                                                      ),
                                                    },
                                                  }),
                                                )
                                              }
                                            />
                                          </div>
                                        ))}
                                        <p className="text-xs text-muted-foreground">
                                          Namespaces are loaded from the
                                          credential. Secret names are per
                                          certificate.
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
                                const options = Array.from(optionValues).map(
                                  (value) => ({ value, label: value }),
                                );

                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <FormLabel className="text-xs text-muted-foreground">
                                      Listener ARNs (from allow-list)
                                    </FormLabel>
                                    {allowed.length === 0 ? (
                                      <p className="text-xs text-muted-foreground">
                                        Edit this credential and add listener
                                        ARNs first.
                                      </p>
                                    ) : (
                                      <MultiSelect
                                        options={options}
                                        selected={draft.listenerArns}
                                        onChange={(listenerArns) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                listenerArns,
                                              },
                                            }),
                                          )
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
                                const options = Array.from(optionValues).map(
                                  (value) => ({ value, label: value }),
                                );

                                return (
                                  <div
                                    key={credentialXref}
                                    className="space-y-3 rounded-lg border bg-background p-3"
                                  >
                                    <div className="text-sm font-medium">
                                      {credential.description || credentialXref}
                                    </div>
                                    <FormLabel className="text-xs text-muted-foreground">
                                      Domain names (from allow-list)
                                    </FormLabel>
                                    {allowed.length === 0 ? (
                                      <p className="text-xs text-muted-foreground">
                                        Edit this credential and add custom
                                        domains first.
                                      </p>
                                    ) : (
                                      <MultiSelect
                                        options={options}
                                        selected={draft.domainNames}
                                        onChange={(domainNames) =>
                                          setDeploymentTargetDrafts(
                                            (previous) => ({
                                              ...previous,
                                              [credentialXref]: {
                                                ...draft,
                                                domainNames,
                                              },
                                            }),
                                          )
                                        }
                                        placeholder="Select domains..."
                                      />
                                    )}
                                  </div>
                                );
                              }

                              return null;
                            },
                          )}
                        </div>
                      ) : null}
                      {!dnsCredentialsQuery.isLoading &&
                      dnsCredentials.length === 0 ? (
                        <Alert>
                          <AlertTitle>
                            {canAddDnsCredential
                              ? "Connect your DNS provider first"
                              : "No DNS provider is connected"}
                          </AlertTitle>
                          <AlertDescription className="space-y-3">
                            <p>
                              {canAddDnsCredential ? (
                                <>
                                  CertPing adds the validation record for you
                                  and renews on its own. You come back here when
                                  you&apos;re done.
                                </>
                              ) : (
                                "Automatic issuance needs a connected DNS provider."
                              )}
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {canAddDnsCredential ? (
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => router.push(connectDnsHref())}
                                >
                                  Connect DNS provider
                                </Button>
                              ) : null}
                              {isManualIssuanceEnabled ? (
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => chooseMode("manual")}
                                >
                                  I&apos;ll add a DNS record instead
                                </Button>
                              ) : null}
                            </div>
                          </AlertDescription>
                        </Alert>
                      ) : null}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
                <Button
                  className="sm:min-w-40"
                  disabled={isSubmitting}
                  type="submit"
                >
                  {isSubmitting ? (
                    <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
                  ) : null}
                  {mode === "automated"
                    ? "Request certificate"
                    : "Create manual order"}
                </Button>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </>
  );
}
