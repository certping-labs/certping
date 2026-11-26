// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiClient, apiRoutes } from "@/lib/api";
import type {
  AddDeploymentTargetInput,
  DomainCredentialConfig,
  PatchDnsCredentialConfigInput,
  SyncCertificateCredentialConfigInput,
  SyncCertificateCredentialConfigResult,
} from "@/types/cert-manager";

export const patchDnsCredentialConfig = async (
  domain: string,
  payload: PatchDnsCredentialConfigInput,
): Promise<DomainCredentialConfig> => {
  const response = await apiClient.patch<DomainCredentialConfig>(
    apiRoutes.mutation.domainCredentialConfig.patchDns(domain),
    payload,
  );
  return response.data;
};

export const addDeploymentTarget = async (
  domain: string,
  payload: AddDeploymentTargetInput,
): Promise<DomainCredentialConfig> => {
  const response = await apiClient.post<DomainCredentialConfig>(
    apiRoutes.mutation.domainCredentialConfig.addDeploymentTarget(domain),
    payload,
  );
  return response.data;
};

export const removeDeploymentTarget = async (
  domain: string,
  credentialXref: string,
): Promise<DomainCredentialConfig> => {
  const response = await apiClient.delete<DomainCredentialConfig>(
    apiRoutes.mutation.domainCredentialConfig.removeDeploymentTarget(
      domain,
      credentialXref,
    ),
  );
  return response.data;
};

export const syncCertificateCredentialConfig = async ({
  domain,
  currentDnsConfigXref,
  dnsConfigXref,
  currentDeploymentCredentialXrefs = [],
  deploymentCredentialXrefs = [],
  deploymentTargetConfigs = [],
}: SyncCertificateCredentialConfigInput): Promise<SyncCertificateCredentialConfigResult> => {
  let latestConfig: DomainCredentialConfig | undefined;
  let updatedDnsConfig = false;

  const normalizedCurrentDeploymentTargets = Array.from(
    new Set(currentDeploymentCredentialXrefs.filter(Boolean)),
  );
  const normalizedNextDeploymentTargets = Array.from(
    new Set(deploymentCredentialXrefs.filter(Boolean)),
  );

  if (dnsConfigXref && dnsConfigXref !== currentDnsConfigXref) {
    latestConfig = await patchDnsCredentialConfig(domain, {
      targetDomain: domain,
      credentialXref: dnsConfigXref,
    });
    updatedDnsConfig = true;
  }

  const currentTargetsSet = new Set(normalizedCurrentDeploymentTargets);
  const nextTargetsSet = new Set(normalizedNextDeploymentTargets);
  const addedDeploymentTargets = normalizedNextDeploymentTargets.filter(
    (credentialXref) => !currentTargetsSet.has(credentialXref),
  );
  const removedDeploymentTargets = normalizedCurrentDeploymentTargets.filter(
    (credentialXref) => !nextTargetsSet.has(credentialXref),
  );

  const configuredTargets = new Set(
    deploymentTargetConfigs
      .map((config) => config?.credentialXref)
      .filter((credentialXref): credentialXref is string =>
        Boolean(credentialXref),
      ),
  );

  for (const credentialXref of removedDeploymentTargets) {
    latestConfig = await removeDeploymentTarget(domain, credentialXref);
  }

  for (const credentialXref of addedDeploymentTargets) {
    if (configuredTargets.has(credentialXref)) {
      continue;
    }
    latestConfig = await addDeploymentTarget(domain, { credentialXref });
  }

  for (const config of deploymentTargetConfigs) {
    const credentialXref = config?.credentialXref;
    const targets = config?.targets;
    const deploymentConfig = config?.config;
    if (!credentialXref) {
      continue;
    }
    if (!targets && !deploymentConfig) {
      continue;
    }
    if (!nextTargetsSet.has(credentialXref)) {
      continue;
    }

    latestConfig = await addDeploymentTarget(domain, {
      credentialXref,
      ...(targets ? { targets } : {}),
      ...(deploymentConfig ? { config: deploymentConfig } : {}),
    });
  }

  return {
    didChange:
      updatedDnsConfig ||
      addedDeploymentTargets.length > 0 ||
      removedDeploymentTargets.length > 0 ||
      deploymentTargetConfigs.length > 0,
    latestConfig,
    updatedDnsConfig,
    addedDeploymentTargets,
    removedDeploymentTargets,
  };
};
