// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, {
  useEffect,
  useId,
  useMemo,
  useState,
  type ChangeEvent,
} from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CircleNotchIcon } from "@phosphor-icons/react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { CertificateReferenceSelect } from "@/components/cert-manager/certificate-reference-select";
import { CredentialReferenceSelect } from "@/components/cert-manager/credential-reference-select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useCanAddCredential, useCredentials } from "@/hooks/credentials";
import {
  useDeployCertificate,
  useDeploymentCredentialConfig,
} from "@/hooks/deployments";
import { useCertificateHistories } from "@/hooks/ssl";
import { useProgressiveCertificateList } from "@/hooks/use-progressive-certificate-list";
import { getProviderPresentation } from "@/lib/credential-providers";
import {
  KUBERNETES_ALL_NAMESPACES,
  buildAllNamespacesSecretMap,
  buildNsSecretMapFromPairs,
  createKubernetesSecretDraft,
  isKubernetesSecretsTarget,
  parseKubernetesCredentialConfig,
  parseSavedKubernetesDeploymentConfig,
  sanitizeNamespaceSecretPairs,
  type NamespaceSecretPair,
} from "@/lib/credential-config-schemas/kubernetes-secrets";
import { KubernetesNsMapEditor } from "@/components/cert-manager/kubernetes-ns-map-editor";
import { StringListEditor } from "@/components/common/string-list-editor";
import {
  defaultAzureAfdCertificateName,
  defaultAzureAfdSecretName,
  defaultAzureAppGatewaySslCertName,
  defaultAzureKvCertificateName,
  getDeploymentTargetApiValue,
  getDeploymentTargetConfigKind,
} from "@/lib/cert-manager/deployment-target-config";
import { MultiSelect } from "@/components/ui/multi-select";
import { parseAwsLoadBalancerCredentialConfig } from "@/lib/credential-config-schemas/aws-load-balancer";
import { parseAwsApiGatewayCredentialConfig } from "@/lib/credential-config-schemas/aws-api-gateway";
import { parseAzureAfdCredentialConfig } from "@/lib/credential-config-schemas/azure-afd";
import { parseAzureAppGwCredentialConfig } from "@/lib/credential-config-schemas/azure-app-gw";
import { parseAzureAgcCredentialConfig } from "@/lib/credential-config-schemas/azure-agc";
import {
  getLifecycleHistoryIdsToResolve,
  getDeployableCertificates,
  resolveDeployableCertificateXref,
} from "@/lib/cert-manager/deployable-certificate-selection";
import type { CertificateHistoryItem } from "@/types/cert-manager";
import type { SSLCertificateListItem } from "@/types/ssl";

const deployFormSchema = z.object({
  certificateXref: z.string().min(1, "Select a certificate"),
  deploymentCredentialXref: z.string().min(1, "Select a deployment target"),
  useDefaultConfig: z.boolean().default(true),
  k8sMapMode: z.enum(["explicit", "all_namespaces"]).default("explicit"),
  k8sAllNamespacesSecret: z.string().trim().default(""),
});

type DeployFormValues = z.infer<typeof deployFormSchema>;

interface DeployNewCertDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialCertificateId?: string;
}

const getCredentialLabel = (credential: {
  description?: string;
  credentialXref?: string;
  providerDisplayName?: string;
  providerName?: string;
}) => {
  const primary =
    credential.description || credential.credentialXref || "Credential";
  const providerLabel = credential.providerDisplayName
    ? credential.providerDisplayName
    : getProviderPresentation(credential.providerName).label;

  return providerLabel ? `${primary} (${providerLabel})` : primary;
};

const EMPTY_K8S_PAIRS: NamespaceSecretPair[] = [];
const EMPTY_LIST: string[] = [];

function RequiredNameInput({
  label,
  value,
  onChange,
  showError,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  showError: boolean;
}) {
  const id = useId();
  const invalid = showError && !value.trim();
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        aria-invalid={invalid}
        className="h-10"
        id={id}
        value={value}
        onChange={(event: ChangeEvent<HTMLInputElement>) =>
          onChange(event.target.value)
        }
      />
      {invalid ? (
        <p className="text-sm font-medium text-destructive" role="alert">
          {label} is required.
        </p>
      ) : null}
    </div>
  );
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

const resolveLookupTargets = (
  lookup?: {
    targets?: Record<string, unknown> | null;
    config?: Record<string, unknown> | null;
  } | null,
): Record<string, unknown> | null => {
  if (lookup?.targets && typeof lookup.targets === "object") {
    return lookup.targets;
  }

  const config = lookup?.config;
  if (!config || typeof config !== "object") {
    return null;
  }

  const nestedTargets = config.targets;
  if (nestedTargets && typeof nestedTargets === "object") {
    return nestedTargets as Record<string, unknown>;
  }

  return config;
};

const toCertificateListItem = (
  item: CertificateHistoryItem,
): SSLCertificateListItem => ({
  certificateXref: item.certificateXref,
  userDomainCertId: item.userDomainCertId,
  domain: item.domain,
  status: item.status,
  caProvider: item.caProvider,
  validFrom: item.validFrom,
  validTo: item.validTo,
  wildcard: item.wildcard,
  san: item.san,
  sanDomains: item.sanDomains,
  dnsConfigXref:
    typeof item.dnsConfigXref === "string" ? item.dnsConfigXref : undefined,
  deploymentCredentialXrefs: item.deploymentCredentialXrefs,
});

export function DeployNewCertDialog({
  open,
  onOpenChange,
  initialCertificateId,
}: DeployNewCertDialogProps) {
  const certificatesQuery = useProgressiveCertificateList({
    enabled: open,
    pollWhilePending: false,
  });
  const canAddDeploymentCredential = useCanAddCredential("DEPLOYMENT");
  const deploymentCredentialsQuery = useCredentials({
    category: "deployment_target",
    enabled: open,
    pollWhilePending: false,
  });
  const deployMutation = useDeployCertificate();

  const [k8sPairs, setK8sPairs] =
    useState<NamespaceSecretPair[]>(EMPTY_K8S_PAIRS);
  const [agcPairs, setAgcPairs] =
    useState<NamespaceSecretPair[]>(EMPTY_K8S_PAIRS);
  const [deployConfigError, setDeployConfigError] = useState<string>("");
  const [showNameErrors, setShowNameErrors] = useState(false);
  const [azureKvCertificateName, setAzureKvCertificateName] = useState("");
  const [gcpCertManagerCertificateName, setGcpCertManagerCertificateName] =
    useState("");
  const [azureAfdCertificateName, setAzureAfdCertificateName] = useState("");
  const [azureAfdSecretName, setAzureAfdSecretName] = useState("");
  const [azureAfdDomainNames, setAzureAfdDomainNames] =
    useState<string[]>(EMPTY_LIST);
  const [azureAppGwSslCertName, setAzureAppGwSslCertName] = useState("");
  const [azureAppGwListenerNames, setAzureAppGwListenerNames] =
    useState<string[]>(EMPTY_LIST);
  const [awsListenerArns, setAwsListenerArns] = useState<string[]>(EMPTY_LIST);
  const [awsApiGwDomainNames, setAwsApiGwDomainNames] =
    useState<string[]>(EMPTY_LIST);
  const [prefillAppliedFor, setPrefillAppliedFor] = useState("");

  const form = useForm<DeployFormValues>({
    resolver: zodResolver(deployFormSchema),
    defaultValues: {
      certificateXref: "",
      deploymentCredentialXref: "",
      useDefaultConfig: true,
      k8sMapMode: "explicit",
      k8sAllNamespacesSecret: "",
    },
  });

  const allCertificates = useMemo(
    () => certificatesQuery.data || [],
    [certificatesQuery.data],
  );
  const renewalLifecycleHistoryIds = useMemo(
    () => getLifecycleHistoryIdsToResolve(allCertificates),
    [allCertificates],
  );
  const lifecycleHistoryQueries = useCertificateHistories(
    renewalLifecycleHistoryIds,
    {
      enabled: open && renewalLifecycleHistoryIds.length > 0,
      pollWhilePending: false,
    },
  );
  const lifecycleHistoryCertificates = useMemo(
    () =>
      lifecycleHistoryQueries.flatMap(
        (query) => query.data?.items.map(toCertificateListItem) ?? [],
      ),
    [lifecycleHistoryQueries],
  );
  const isResolvingLifecycleHistory = lifecycleHistoryQueries.some(
    (query) => query.isPending || query.isFetching,
  );
  const hasLifecycleHistoryError = lifecycleHistoryQueries.some(
    (query) => query.isError,
  );
  const selectableCertificates = useMemo(
    () => [...allCertificates, ...lifecycleHistoryCertificates],
    [allCertificates, lifecycleHistoryCertificates],
  );
  const certificates = useMemo(
    () => getDeployableCertificates(selectableCertificates),
    [selectableCertificates],
  );
  const resolvedInitialCertificateXref = useMemo(
    () =>
      resolveDeployableCertificateXref(
        selectableCertificates,
        initialCertificateId,
      ),
    [initialCertificateId, selectableCertificates],
  );

  useEffect(() => {
    if (!open) {
      return;
    }

    if (initialCertificateId && certificatesQuery.isFetched) {
      const nextCertificateXref = resolvedInitialCertificateXref || "";
      const currentCertificateXref = form.getValues("certificateXref");
      if (
        nextCertificateXref &&
        currentCertificateXref !== nextCertificateXref
      ) {
        form.setValue("certificateXref", nextCertificateXref, {
          shouldDirty: false,
        });
      }
      return;
    }

    const currentCertificateXref = form.getValues("certificateXref");
    if (
      currentCertificateXref &&
      !certificates.some(
        (certificate) =>
          (certificate.certificateXref || certificate.domain) ===
          currentCertificateXref,
      )
    ) {
      form.setValue("certificateXref", "", { shouldDirty: false });
    }
  }, [
    certificates,
    certificatesQuery.isFetched,
    form,
    initialCertificateId,
    open,
    resolvedInitialCertificateXref,
  ]);

  const deploymentCredentials = useMemo(
    () => deploymentCredentialsQuery.data || [],
    [deploymentCredentialsQuery.data],
  );

  const selectedCredentialXref = form.watch("deploymentCredentialXref");
  const selectedCertificateXref = form.watch("certificateXref");
  const useDefaultConfig = form.watch("useDefaultConfig");
  const k8sMapMode = form.watch("k8sMapMode");

  const selectedCredential = useMemo(
    () =>
      deploymentCredentials.find(
        (credential) =>
          (credential.credentialXref || credential.alias) ===
          selectedCredentialXref,
      ),
    [deploymentCredentials, selectedCredentialXref],
  );
  const selectedCertificate = useMemo(
    () =>
      certificates.find(
        (certificate) =>
          (certificate.certificateXref || certificate.domain) ===
          selectedCertificateXref,
      ),
    [certificates, selectedCertificateXref],
  );

  const isKubernetesCredential = isKubernetesSecretsTarget(
    selectedCredential?.targetType || selectedCredential?.providerName,
  );
  const credentialAllowedListeners = useMemo(() => {
    if (!selectedCredential) {
      return EMPTY_LIST;
    }
    return (
      parseAwsLoadBalancerCredentialConfig(selectedCredential.configJson)
        ?.listeners || EMPTY_LIST
    );
  }, [selectedCredential]);
  const credentialAllowedApiGwDomains = useMemo(() => {
    if (!selectedCredential) {
      return EMPTY_LIST;
    }
    return (
      parseAwsApiGatewayCredentialConfig(selectedCredential.configJson)
        ?.customDomains || EMPTY_LIST
    );
  }, [selectedCredential]);
  const credentialAllowedAfdDomains = useMemo(() => {
    if (!selectedCredential) {
      return EMPTY_LIST;
    }
    return (
      parseAzureAfdCredentialConfig(selectedCredential.configJson)
        ?.customDomains || EMPTY_LIST
    );
  }, [selectedCredential]);
  const credentialAllowedAppGwListeners = useMemo(() => {
    if (!selectedCredential) {
      return EMPTY_LIST;
    }
    return (
      parseAzureAppGwCredentialConfig(selectedCredential.configJson)
        ?.listeners || EMPTY_LIST
    );
  }, [selectedCredential]);
  const credentialAllowedAgcNamespaces = useMemo(() => {
    if (!selectedCredential) {
      return EMPTY_LIST;
    }
    return (
      parseAzureAgcCredentialConfig(selectedCredential.configJson)
        ?.secretNamespaces || EMPTY_LIST
    );
  }, [selectedCredential]);
  const deploymentConfigKind = selectedCredential
    ? getDeploymentTargetConfigKind({
        targetType: selectedCredential.targetType,
        providerName: selectedCredential.providerName,
      })
    : "NONE";
  const selectionKey = `${selectedCertificateXref}::${selectedCredentialXref}`;

  const credentialConfig = useMemo(
    () => parseKubernetesCredentialConfig(selectedCredential?.configJson),
    [selectedCredential?.configJson],
  );
  const { allowedNamespaces, supportsAllNamespaces } = useMemo(() => {
    const namespaces = credentialConfig?.namespaces;
    return {
      allowedNamespaces: Array.isArray(namespaces) ? namespaces : [],
      supportsAllNamespaces: namespaces === KUBERNETES_ALL_NAMESPACES,
    };
  }, [credentialConfig?.namespaces]);

  const domainForDefaultSecret =
    selectedCertificate?.domain || selectedCertificateXref || "certificate";

  const defaultKubernetesDraft = useMemo(
    () =>
      createKubernetesSecretDraft({
        domain: domainForDefaultSecret,
        allowedNamespaces,
        supportsAllNamespaces,
      }),
    [allowedNamespaces, domainForDefaultSecret, supportsAllNamespaces],
  );
  const defaultAgcDraft = useMemo(
    () =>
      createKubernetesSecretDraft({
        domain: domainForDefaultSecret,
        allowedNamespaces: credentialAllowedAgcNamespaces,
        supportsAllNamespaces: false,
      }),
    [credentialAllowedAgcNamespaces, domainForDefaultSecret],
  );

  const credentialConfigQuery = useDeploymentCredentialConfig(
    selectedCertificateXref,
    selectedCredentialXref,
  );
  const savedConfigDraft = useMemo(
    () =>
      parseSavedKubernetesDeploymentConfig(credentialConfigQuery.data?.config),
    [credentialConfigQuery.data?.config],
  );
  const hasSavedDefaultConfig = Boolean(savedConfigDraft);
  const isDeploymentConfigLookupPending =
    Boolean(selectedCertificateXref && selectedCredentialXref) &&
    credentialConfigQuery.isLoading;
  const isK8sConfigLookupPending =
    isKubernetesCredential && isDeploymentConfigLookupPending;

  useEffect(() => {
    const domain =
      selectedCertificate?.domain || selectedCertificateXref || "certificate";
    setShowNameErrors(false);
    setAzureKvCertificateName(
      deploymentConfigKind === "AZURE_KV"
        ? defaultAzureKvCertificateName(domain)
        : "",
    );
    setGcpCertManagerCertificateName(
      deploymentConfigKind === "GCP_CERT_MANAGER"
        ? defaultAzureKvCertificateName(domain)
        : "",
    );

    if (deploymentConfigKind === "AZURE_AFD") {
      setAzureAfdCertificateName(defaultAzureAfdCertificateName(domain));
      setAzureAfdSecretName(defaultAzureAfdSecretName(domain));
      setAzureAfdDomainNames([]);
    } else {
      setAzureAfdCertificateName("");
      setAzureAfdSecretName("");
      setAzureAfdDomainNames([]);
    }

    if (deploymentConfigKind === "AZURE_APP_GW") {
      setAzureAppGwSslCertName(defaultAzureAppGatewaySslCertName(domain));
      setAzureAppGwListenerNames(
        credentialAllowedAppGwListeners.length > 0
          ? [credentialAllowedAppGwListeners[0]]
          : [],
      );
    } else {
      setAzureAppGwSslCertName("");
      setAzureAppGwListenerNames([]);
    }

    if (deploymentConfigKind === "AZURE_APP_GW_CONTAINERS") {
      setAgcPairs(defaultAgcDraft.pairs);
    } else {
      setAgcPairs(EMPTY_K8S_PAIRS);
    }

    if (deploymentConfigKind === "AWS_API_GATEWAY") {
      setAwsApiGwDomainNames([]);
    } else {
      setAwsApiGwDomainNames([]);
    }

    if (deploymentConfigKind === "AWS_LOAD_BALANCER") {
      setAwsListenerArns([]);
    } else {
      setAwsListenerArns([]);
    }

    if (!isKubernetesCredential) {
      setK8sPairs(EMPTY_K8S_PAIRS);
      setDeployConfigError("");
      setPrefillAppliedFor("");
      form.setValue("useDefaultConfig", true, { shouldDirty: false });
      form.setValue("k8sMapMode", "explicit", { shouldDirty: false });
      form.setValue("k8sAllNamespacesSecret", "", { shouldDirty: false });
      return;
    }

    setK8sPairs(defaultKubernetesDraft.pairs);
    setDeployConfigError("");
    setPrefillAppliedFor("");
    form.setValue("useDefaultConfig", true, { shouldDirty: false });
    form.setValue("k8sMapMode", defaultKubernetesDraft.mapMode, {
      shouldDirty: false,
    });
    form.setValue(
      "k8sAllNamespacesSecret",
      defaultKubernetesDraft.allNamespacesSecret,
      {
        shouldDirty: false,
      },
    );
  }, [
    credentialAllowedAppGwListeners,
    defaultAgcDraft.pairs,
    defaultKubernetesDraft,
    deploymentConfigKind,
    form,
    isKubernetesCredential,
    selectedCertificate?.domain,
    selectedCertificateXref,
    selectionKey,
  ]);

  useEffect(() => {
    if (
      !isKubernetesCredential ||
      !selectedCredentialXref ||
      !selectedCertificateXref
    ) {
      return;
    }

    if (
      !credentialConfigQuery.isFetched ||
      credentialConfigQuery.isLoading ||
      prefillAppliedFor === selectionKey
    ) {
      return;
    }

    if (!savedConfigDraft) {
      form.setValue("useDefaultConfig", false, { shouldDirty: false });
      return;
    }

    form.setValue("useDefaultConfig", true, { shouldDirty: false });

    if (
      savedConfigDraft.mapMode === "all_namespaces" &&
      supportsAllNamespaces
    ) {
      form.setValue("k8sMapMode", "all_namespaces", { shouldDirty: false });
      form.setValue(
        "k8sAllNamespacesSecret",
        savedConfigDraft.allNamespacesSecret,
        {
          shouldDirty: false,
        },
      );
      setK8sPairs(defaultKubernetesDraft.pairs);
      setPrefillAppliedFor(selectionKey);
      return;
    }

    const savedSecretMap = new Map(
      savedConfigDraft.pairs.map((pair) => [pair.namespace, pair.secretName]),
    );
    if (allowedNamespaces.length > 0) {
      setK8sPairs(
        allowedNamespaces.map((namespace) => ({
          namespace,
          secretName:
            savedSecretMap.get(namespace) ||
            defaultKubernetesDraft.pairs.find(
              (pair) => pair.namespace === namespace,
            )?.secretName ||
            "",
        })),
      );
    } else {
      setK8sPairs(savedConfigDraft.pairs);
    }

    form.setValue("k8sMapMode", "explicit", { shouldDirty: false });
    setPrefillAppliedFor(selectionKey);
  }, [
    allowedNamespaces,
    credentialConfigQuery.isFetched,
    credentialConfigQuery.isLoading,
    defaultKubernetesDraft.pairs,
    form,
    isKubernetesCredential,
    prefillAppliedFor,
    savedConfigDraft,
    selectedCertificateXref,
    selectedCredentialXref,
    selectionKey,
    supportsAllNamespaces,
  ]);

  useEffect(() => {
    if (!selectedCredentialXref || !selectedCertificateXref) {
      return;
    }

    if (
      !credentialConfigQuery.isFetched ||
      credentialConfigQuery.isLoading ||
      prefillAppliedFor === selectionKey
    ) {
      return;
    }

    if (isKubernetesCredential) {
      return;
    }

    const targets = resolveLookupTargets(credentialConfigQuery.data);
    if (!targets) {
      return;
    }

    if (deploymentConfigKind === "AZURE_KV") {
      const certificateName =
        typeof targets.certificateName === "string"
          ? targets.certificateName
          : "";
      if (certificateName.trim()) {
        setAzureKvCertificateName(certificateName);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }
    if (deploymentConfigKind === "GCP_CERT_MANAGER") {
      const certificateName =
        typeof targets.certificateName === "string"
          ? targets.certificateName
          : "";
      if (certificateName.trim()) {
        setGcpCertManagerCertificateName(certificateName);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    if (deploymentConfigKind === "AZURE_AFD") {
      const certificateName =
        typeof targets.certificateName === "string"
          ? targets.certificateName.trim()
          : "";
      const secretName =
        typeof targets.secretName === "string" ? targets.secretName.trim() : "";
      const domainNames = normalizeTargetStringArray(
        (targets.domainNames as unknown) ?? [],
      );
      if (certificateName) {
        setAzureAfdCertificateName(certificateName);
      }
      if (secretName) {
        setAzureAfdSecretName(secretName);
      }
      if (domainNames.length > 0) {
        setAzureAfdDomainNames(domainNames);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    if (deploymentConfigKind === "AWS_LOAD_BALANCER") {
      const listenerArns = normalizeTargetStringArray(
        (targets.listenerArns as unknown) ?? [],
      );
      if (listenerArns.length > 0) {
        setAwsListenerArns(listenerArns);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    if (deploymentConfigKind === "AZURE_APP_GW") {
      const sslCertName =
        typeof targets.sslCertName === "string" ? targets.sslCertName : "";
      const listenerNames = normalizeTargetStringArray(
        (targets.listenerNames as unknown) ?? [],
      );
      if (sslCertName.trim()) {
        setAzureAppGwSslCertName(sslCertName);
      }
      if (listenerNames.length > 0) {
        setAzureAppGwListenerNames(listenerNames);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    if (deploymentConfigKind === "AZURE_APP_GW_CONTAINERS") {
      const secretsRaw = (targets.secrets as unknown) ?? [];
      const secrets = Array.isArray(secretsRaw)
        ? secretsRaw
            .map((entry) =>
              entry && typeof entry === "object"
                ? {
                    namespace:
                      typeof (entry as { namespace?: unknown }).namespace ===
                      "string"
                        ? (entry as { namespace: string }).namespace
                        : "",
                    secretName:
                      typeof (entry as { secretName?: unknown }).secretName ===
                      "string"
                        ? (entry as { secretName: string }).secretName
                        : "",
                  }
                : { namespace: "", secretName: "" },
            )
            .filter((pair) => pair.namespace && pair.secretName)
        : [];
      if (secrets.length > 0) {
        setAgcPairs(secrets);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    if (deploymentConfigKind === "AWS_API_GATEWAY") {
      const domainNames = normalizeTargetStringArray(
        (targets.domainNames as unknown) ?? [],
      );
      if (domainNames.length > 0) {
        setAwsApiGwDomainNames(domainNames);
      }
      setPrefillAppliedFor(selectionKey);
      return;
    }

    setPrefillAppliedFor(selectionKey);
  }, [
    credentialConfigQuery.isFetched,
    credentialConfigQuery.data,
    credentialConfigQuery.isLoading,
    deploymentConfigKind,
    isKubernetesCredential,
    prefillAppliedFor,
    selectedCertificateXref,
    selectedCredentialXref,
    selectionKey,
  ]);

  const onSubmit = form.handleSubmit(async (values) => {
    setDeployConfigError("");

    const payload = {
      certificateXref: values.certificateXref,
      deploymentCredentialXref: values.deploymentCredentialXref,
      targetType: selectedCredential?.targetType || "AZURE_KV",
    } as const;

    if (!isKubernetesCredential) {
      const apiValue = selectedCredential
        ? getDeploymentTargetApiValue({
            targetType: selectedCredential.targetType,
            providerName: selectedCredential.providerName,
          })
        : "";

      if (apiValue === "AZURE_KV") {
        const certificateName = azureKvCertificateName.trim();
        if (!certificateName) {
          setShowNameErrors(true);
          return;
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { certificateName },
        });
      } else if (apiValue === "GCP_CERT_MANAGER") {
        const certificateName = gcpCertManagerCertificateName.trim();
        if (!certificateName) {
          setShowNameErrors(true);
          return;
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { certificateName },
        });
      } else if (apiValue === "AZURE_AFD") {
        const certificateName = azureAfdCertificateName.trim();
        const secretName = azureAfdSecretName.trim();
        const domainNames = (azureAfdDomainNames || [])
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (!certificateName || !secretName) {
          setShowNameErrors(true);
          return;
        }
        if (domainNames.length === 0) {
          setDeployConfigError("Provide at least one domain name.");
          return;
        }
        if (credentialAllowedAfdDomains.length > 0) {
          const allowSet = new Set(credentialAllowedAfdDomains);
          const invalid = domainNames.find((name) => !allowSet.has(name));
          if (invalid) {
            setDeployConfigError(
              "Selected domain is not in this credential's configured custom domains list.",
            );
            return;
          }
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { certificateName, secretName, domainNames },
        });
      } else if (apiValue === "AWS_ALB" || apiValue === "AWS_NLB") {
        const listenerArns = (awsListenerArns || [])
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (listenerArns.length === 0) {
          setDeployConfigError("Provide at least one listener ARN.");
          return;
        }
        if (credentialAllowedListeners.length > 0) {
          const allowSet = new Set(credentialAllowedListeners);
          const invalid = listenerArns.find((arn) => !allowSet.has(arn));
          if (invalid) {
            setDeployConfigError(
              "Selected listener is not in this credential's configured listeners list.",
            );
            return;
          }
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { listenerArns },
        });
      } else if (apiValue === "AZURE_APP_GW") {
        const sslCertName = azureAppGwSslCertName.trim();
        const listenerNames = (azureAppGwListenerNames || [])
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (!sslCertName) {
          setShowNameErrors(true);
          return;
        }
        if (listenerNames.length === 0) {
          setDeployConfigError("Select at least one listener.");
          return;
        }
        if (credentialAllowedAppGwListeners.length > 0) {
          const allowSet = new Set(credentialAllowedAppGwListeners);
          const invalid = listenerNames.find((name) => !allowSet.has(name));
          if (invalid) {
            setDeployConfigError(
              "Selected listener is not in this credential's configured listeners list.",
            );
            return;
          }
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { sslCertName, listenerNames },
        });
      } else if (apiValue === "AZURE_APP_GW_CONTAINERS") {
        const secrets = sanitizeNamespaceSecretPairs(agcPairs);
        if (secrets.length === 0) {
          setDeployConfigError(
            "Provide at least one namespace secret mapping.",
          );
          return;
        }
        const allowedSet = new Set(credentialAllowedAgcNamespaces);
        const invalid = secrets.find((pair) => !allowedSet.has(pair.namespace));
        if (invalid) {
          setDeployConfigError(
            "Selected namespace is not in this credential's configured namespaces list.",
          );
          return;
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { secrets },
        });
      } else if (
        apiValue === "AWS_API_GW_REST" ||
        apiValue === "AWS_API_GW_HTTP"
      ) {
        const domainNames = (awsApiGwDomainNames || [])
          .map((value) => value.trim())
          .filter((value) => value.length > 0);
        if (domainNames.length === 0) {
          setDeployConfigError("Provide at least one domain name.");
          return;
        }
        if (credentialAllowedApiGwDomains.length > 0) {
          const allowSet = new Set(credentialAllowedApiGwDomains);
          const invalid = domainNames.find((name) => !allowSet.has(name));
          if (invalid) {
            setDeployConfigError(
              "Selected domain is not in this credential's configured custom domains list.",
            );
            return;
          }
        }
        await deployMutation.mutateAsync({
          ...payload,
          targets: { domainNames },
        });
      } else {
        await deployMutation.mutateAsync(payload);
      }
    } else {
      if (isK8sConfigLookupPending) {
        setDeployConfigError(
          "Please wait while we load Kubernetes deployment config.",
        );
        return;
      }

      if (values.useDefaultConfig) {
        if (!hasSavedDefaultConfig) {
          setDeployConfigError(
            "No saved config found for this certificate and credential. Provide explicit namespace mapping.",
          );
          return;
        }

        await deployMutation.mutateAsync({
          ...payload,
          useDefault: true,
        });
      } else if (values.k8sMapMode === "all_namespaces") {
        const secretName = values.k8sAllNamespacesSecret.trim();
        if (!secretName) {
          setDeployConfigError(
            "Secret name is required for all_namespaces mode.",
          );
          return;
        }

        await deployMutation.mutateAsync({
          ...payload,
          useDefault: false,
          config: buildAllNamespacesSecretMap(secretName),
        });
      } else {
        let sanitizedPairs: NamespaceSecretPair[];
        try {
          sanitizedPairs = sanitizeNamespaceSecretPairs(k8sPairs);
        } catch (error) {
          setDeployConfigError(
            error instanceof Error
              ? error.message
              : "Invalid namespace to secret mapping",
          );
          return;
        }

        if (sanitizedPairs.length === 0) {
          setDeployConfigError("Provide at least one namespace mapping.");
          return;
        }

        await deployMutation.mutateAsync({
          ...payload,
          useDefault: false,
          config: buildNsSecretMapFromPairs(sanitizedPairs),
        });
      }
    }

    form.reset({
      certificateXref: resolvedInitialCertificateXref || "",
      deploymentCredentialXref: "",
      useDefaultConfig: true,
      k8sMapMode: "explicit",
      k8sAllNamespacesSecret: "",
    });
    setK8sPairs(EMPTY_K8S_PAIRS);
    setDeployConfigError("");
    setPrefillAppliedFor("");
    onOpenChange(false);
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-hidden sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Deploy certificate</DialogTitle>
          <DialogDescription>
            Deploy a certificate using your integrated deployment targets.
          </DialogDescription>
        </DialogHeader>

        {deploymentCredentials.length === 0 &&
        !deploymentCredentialsQuery.isLoading ? (
          <Alert>
            <AlertTitle>No deployment targets available</AlertTitle>
            <AlertDescription>
              {canAddDeploymentCredential
                ? "Use “Add deployment target” below to create one before you start a deployment."
                : "A deployment target is required before you start a deployment."}
            </AlertDescription>
          </Alert>
        ) : null}

        <Form {...form}>
          <form
            className="flex max-h-[calc(90vh-9rem)] flex-col"
            onSubmit={onSubmit}
          >
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="certificateXref"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Certificate</FormLabel>
                    <FormControl>
                      <CertificateReferenceSelect
                        certificates={certificates}
                        onValueChange={field.onChange}
                        value={field.value}
                      />
                    </FormControl>
                    {isResolvingLifecycleHistory ? (
                      <p
                        className="flex items-center gap-2 text-xs text-muted-foreground"
                        role="status"
                      >
                        <CircleNotchIcon className="h-3.5 w-3.5 animate-spin" />
                        Checking renewing certificate versions…
                      </p>
                    ) : null}
                    {hasLifecycleHistoryError ? (
                      <p className="text-xs text-destructive" role="alert">
                        Some renewing certificates could not be checked. Reopen
                        the dialog to retry.
                      </p>
                    ) : null}
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="deploymentCredentialXref"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Deployment target</FormLabel>
                    <FormControl>
                      <CredentialReferenceSelect
                        addCredentialHref={
                          canAddDeploymentCredential
                            ? "/integrations/connections/add?type=DEPLOYMENT"
                            : undefined
                        }
                        addCredentialLabel="Add deployment target"
                        credentials={deploymentCredentials}
                        onValueChange={field.onChange}
                        placeholder="Select a deployment target"
                        value={field.value}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {isKubernetesCredential ? (
                <div className="space-y-4 rounded-lg">
                  {isK8sConfigLookupPending ? (
                    <div className="flex items-center gap-2 rounded-md border bg-background p-3 text-xs text-muted-foreground">
                      <CircleNotchIcon className="h-4 w-4 animate-spin" />
                      Loading saved Kubernetes deployment config...
                    </div>
                  ) : null}

                  <FormField
                    control={form.control}
                    name="useDefaultConfig"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Config source</FormLabel>
                        <Select
                          onValueChange={(value) =>
                            field.onChange(value === "saved")
                          }
                          value={field.value ? "saved" : "explicit"}
                        >
                          <FormControl>
                            <SelectTrigger
                              className="h-10"
                              disabled={isK8sConfigLookupPending}
                            >
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="explicit">
                              Provide explicit namespace map
                            </SelectItem>
                            <SelectItem
                              value="saved"
                              disabled={!hasSavedDefaultConfig}
                            >
                              Use saved default config for this cert +
                              credential
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        {!hasSavedDefaultConfig && !isK8sConfigLookupPending ? (
                          <p className="text-xs text-muted-foreground">
                            No saved config exists for this certificate +
                            deployment target yet.
                          </p>
                        ) : null}
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {!useDefaultConfig ? (
                    <>
                      <KubernetesNsMapEditor
                        allNamespacesSecret={form.watch(
                          "k8sAllNamespacesSecret",
                        )}
                        mapMode={k8sMapMode}
                        onAllNamespacesSecretChange={(value) =>
                          form.setValue("k8sAllNamespacesSecret", value, {
                            shouldDirty: true,
                          })
                        }
                        onMapModeChange={(value) => {
                          form.setValue("k8sMapMode", value, {
                            shouldDirty: true,
                          });
                          if (value === "explicit") {
                            form.setValue("k8sAllNamespacesSecret", "", {
                              shouldDirty: true,
                            });
                          }
                        }}
                        onPairChange={(index, fieldName, value) =>
                          setK8sPairs((previous) =>
                            previous.map((pair, pairIndex) =>
                              pairIndex === index
                                ? { ...pair, [fieldName]: value }
                                : pair,
                            ),
                          )
                        }
                        onResetDefaults={() =>
                          setK8sPairs(defaultKubernetesDraft.pairs)
                        }
                        pairs={k8sPairs}
                        supportsAllNamespaces={supportsAllNamespaces}
                      />
                      {deployConfigError ? (
                        <p
                          className="text-sm font-medium text-destructive"
                          role="alert"
                        >
                          {deployConfigError}
                        </p>
                      ) : null}
                    </>
                  ) : null}
                </div>
              ) : null}

              {!isKubernetesCredential && isDeploymentConfigLookupPending ? (
                <div className="flex items-center gap-2 rounded-md border bg-background p-3 text-xs text-muted-foreground">
                  <CircleNotchIcon className="h-4 w-4 animate-spin" />
                  Loading saved deployment config...
                </div>
              ) : null}

              {deploymentConfigKind === "AZURE_KV" ? (
                <div className="space-y-3 rounded-lg">
                  <RequiredNameInput
                    label="Certificate name"
                    value={azureKvCertificateName}
                    onChange={setAzureKvCertificateName}
                    showError={showNameErrors}
                  />
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}
              {deploymentConfigKind === "GCP_CERT_MANAGER" ? (
                <div className="space-y-3 rounded-lg">
                  <RequiredNameInput
                    label="Certificate name"
                    value={gcpCertManagerCertificateName}
                    onChange={setGcpCertManagerCertificateName}
                    showError={showNameErrors}
                  />
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {deploymentConfigKind === "AZURE_AFD" ? (
                <div className="space-y-3 rounded-lg">
                  <RequiredNameInput
                    label="Certificate name"
                    value={azureAfdCertificateName}
                    onChange={setAzureAfdCertificateName}
                    showError={showNameErrors}
                  />
                  <RequiredNameInput
                    label="Secret name"
                    value={azureAfdSecretName}
                    onChange={setAzureAfdSecretName}
                    showError={showNameErrors}
                  />
                  {credentialAllowedAfdDomains.length > 0 ? (
                    <div className="space-y-2">
                      <FormLabel>Domain names</FormLabel>
                      <MultiSelect
                        options={credentialAllowedAfdDomains.map((domain) => ({
                          label: domain,
                          value: domain,
                        }))}
                        selected={azureAfdDomainNames}
                        onChange={setAzureAfdDomainNames}
                        placeholder="Select one or more domains"
                      />
                    </div>
                  ) : (
                    <StringListEditor
                      label="Domain names"
                      values={azureAfdDomainNames}
                      placeholder="api.example.com"
                      addLabel="Add domain"
                      onChange={setAzureAfdDomainNames}
                    />
                  )}
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {deploymentConfigKind === "AWS_LOAD_BALANCER" ? (
                <div className="space-y-3 rounded-lg">
                  {credentialAllowedListeners.length > 0 ? (
                    <div className="space-y-2">
                      <FormLabel>Listener ARNs</FormLabel>
                      <MultiSelect
                        options={credentialAllowedListeners.map((listener) => ({
                          label: listener,
                          value: listener,
                        }))}
                        selected={awsListenerArns}
                        onChange={setAwsListenerArns}
                        placeholder="Select one or more listeners"
                      />
                      <p className="text-xs text-muted-foreground">
                        Loaded from this credential&apos;s saved listener list.
                      </p>
                    </div>
                  ) : (
                    <StringListEditor
                      label="Listener ARNs"
                      values={awsListenerArns}
                      placeholder="arn:aws:elasticloadbalancing:...:listener/..."
                      addLabel="Add listener ARN"
                      onChange={setAwsListenerArns}
                    />
                  )}
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {deploymentConfigKind === "AZURE_APP_GW" ? (
                <div className="space-y-3 rounded-lg">
                  <RequiredNameInput
                    label="SSL cert name"
                    value={azureAppGwSslCertName}
                    onChange={setAzureAppGwSslCertName}
                    showError={showNameErrors}
                  />
                  {credentialAllowedAppGwListeners.length > 0 ? (
                    <div className="space-y-2">
                      <FormLabel>Listener names</FormLabel>
                      <MultiSelect
                        options={credentialAllowedAppGwListeners.map(
                          (listener) => ({
                            label: listener,
                            value: listener,
                          }),
                        )}
                        selected={azureAppGwListenerNames}
                        onChange={setAzureAppGwListenerNames}
                        placeholder="Select one or more listeners"
                      />
                      <p className="text-xs text-muted-foreground">
                        Loaded from this credential&apos;s saved listener list.
                      </p>
                    </div>
                  ) : (
                    <Alert>
                      <AlertTitle>No listeners configured</AlertTitle>
                      <AlertDescription>
                        Edit this deployment target and add listeners first.
                      </AlertDescription>
                    </Alert>
                  )}
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {deploymentConfigKind === "AZURE_APP_GW_CONTAINERS" ? (
                <div className="space-y-3 rounded-lg">
                  {credentialAllowedAgcNamespaces.length === 0 ? (
                    <Alert>
                      <AlertTitle>No namespaces configured</AlertTitle>
                      <AlertDescription>
                        Edit this deployment target and add secret namespaces
                        first.
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <div className="space-y-2">
                      <FormLabel>Namespace secrets</FormLabel>
                      <div className="space-y-2">
                        {agcPairs.map((pair, index) => (
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
                              onChange={(
                                event: ChangeEvent<HTMLInputElement>,
                              ) =>
                                setAgcPairs((previous) =>
                                  previous.map((existingPair, pairIndex) =>
                                    pairIndex === index
                                      ? {
                                          ...existingPair,
                                          secretName: event.target.value,
                                        }
                                      : existingPair,
                                  ),
                                )
                              }
                            />
                          </div>
                        ))}
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Namespaces are loaded from this credential&apos;s saved
                        allow-list.
                      </p>
                    </div>
                  )}
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {deploymentConfigKind === "AWS_API_GATEWAY" ? (
                <div className="space-y-3 rounded-lg">
                  {credentialAllowedApiGwDomains.length > 0 ? (
                    <div className="space-y-2">
                      <FormLabel>Domain names</FormLabel>
                      <MultiSelect
                        options={credentialAllowedApiGwDomains.map(
                          (domain) => ({
                            label: domain,
                            value: domain,
                          }),
                        )}
                        selected={awsApiGwDomainNames}
                        onChange={setAwsApiGwDomainNames}
                        placeholder="Select one or more domains"
                      />
                      <p className="text-xs text-muted-foreground">
                        Loaded from this credential&apos;s saved custom domains
                        list.
                      </p>
                    </div>
                  ) : (
                    <StringListEditor
                      label="Domain names"
                      values={awsApiGwDomainNames}
                      placeholder="api.example.com"
                      addLabel="Add domain"
                      onChange={setAwsApiGwDomainNames}
                    />
                  )}
                  {deployConfigError ? (
                    <p
                      className="text-sm font-medium text-destructive"
                      role="alert"
                    >
                      {deployConfigError}
                    </p>
                  ) : null}
                </div>
              ) : null}

              {selectedCredential?.targetType ? (
                <Alert>
                  <AlertDescription>
                    <span className="font-medium">
                      {getCredentialLabel(selectedCredential)}
                    </span>{" "}
                    will deploy to{" "}
                    {
                      getProviderPresentation(selectedCredential.targetType)
                        .label
                    }
                    .
                  </AlertDescription>
                </Alert>
              ) : null}
            </div>

            <DialogFooter className="mt-4 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button
                disabled={
                  deployMutation.isPending ||
                  deploymentCredentials.length === 0 ||
                  certificates.length === 0 ||
                  isDeploymentConfigLookupPending
                }
                type="submit"
              >
                {deployMutation.isPending ? (
                  <CircleNotchIcon className="mr-2 h-4 w-4 animate-spin" />
                ) : null}
                Request deployment
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
