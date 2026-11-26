// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.CertDeploymentConfigEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.service.deployment.config.DeploymentConfigEnvelope;
import com.certmanagement.service.deployment.config.DeploymentResultMerger;
import com.certmanagement.service.deployment.config.DeploymentResultMergerRegistry;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidatorRegistry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertDeploymentConfigService {

    private static final String PROVIDER_K8S = "KUBERNETES_SECRETS";
    private static final String ALL_NAMESPACES = "all_namespaces";

    private final CertDeploymentConfigRepository repository;
    private final CredentialReferenceRepository credentialReferenceRepository;
    private final KubernetesNamespaceNameValidator namespaceNameValidator;
    private final KubernetesSecretNameValidator secretNameValidator;
    private final DeploymentResultMergerRegistry resultMergerRegistry;
    private final DeploymentTargetsValidatorRegistry targetsValidatorRegistry;
    private final ObjectMapper objectMapper;

    @Transactional
    public String requireReconciledConfigJson(
            Long organizationId,
            Long userDomainCertId,
            CredentialReferenceEntity deploymentCredential) {
        if (!PROVIDER_K8S.equals(deploymentCredential.getProvider())) {
            throw new BadRequestException("config is supported only for provider KUBERNETES_SECRETS");
        }
        if (deploymentCredential.getId() == null) {
            throw new BadRequestException("Deployment credential is invalid for kubernetes configuration");
        }
        CertDeploymentConfigEntity entity = repository
                .findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                        organizationId, userDomainCertId, deploymentCredential.getId())
                .orElseThrow(() -> new BadRequestException(
                        "Default kubernetes deployment config not found for this certificate and deployment credential"));
        return reconcileAndPersistIfChanged(entity, deploymentCredential);
    }

    @Transactional
    public Optional<String> findReconciledConfigJson(
            Long organizationId,
            Long userDomainCertId,
            CredentialReferenceEntity deploymentCredential) {
        if (deploymentCredential.getId() == null) {
            return Optional.empty();
        }
        Optional<CertDeploymentConfigEntity> found = repository
                .findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                        organizationId, userDomainCertId, deploymentCredential.getId());
        if (found.isEmpty()) {
            return Optional.empty();
        }
        // Kubernetes: reconcile against current credential scope before returning the legacy flat config.
        if (PROVIDER_K8S.equals(deploymentCredential.getProvider())) {
            return Optional.of(reconcileAndPersistIfChanged(found.get(), deploymentCredential));
        }
        // Non-Kubernetes: return the envelope ({"targets":..., "result":...}) as-is for the dispatcher to split.
        return Optional.ofNullable(found.get().getConfigJson());
    }

    /**
     * Persists the per-certificate deployment slice returned by the agent into
     * {@code cert_deployment_config.config}, updating only the {@code result} side of the
     * envelope and preserving any existing {@code targets}.
     *
     * <p>Provider behavior is delegated to {@link DeploymentResultMerger}s registered in
     * {@link DeploymentResultMergerRegistry}. Providers without a registered merger are
     * silently ignored.
     *
     * <p>Kubernetes is intentionally skipped here — its persistence flows through
     * {@link #validateAndUpsertKubernetesConfig} and uses a legacy flat shape.
     */
    @Transactional
    public void mergeDeploymentResultFromAgent(
            Long organizationId,
            Long userDomainCertId,
            String deploymentCredentialXref,
            String targetTypeStr,
            String perDomainJson) {
        if (organizationId == null
                || userDomainCertId == null
                || deploymentCredentialXref == null
                || deploymentCredentialXref.isBlank()
                || targetTypeStr == null
                || perDomainJson == null
                || perDomainJson.isBlank()) {
            return;
        }

        TargetType targetType;
        try {
            targetType = TargetType.valueOf(targetTypeStr);
        } catch (IllegalArgumentException ex) {
            log.warn("mergeDeploymentResultFromAgent: unknown targetType '{}' — skipping", targetTypeStr);
            return;
        }

        Optional<DeploymentResultMerger> mergerOpt = resultMergerRegistry.find(targetType);
        if (mergerOpt.isEmpty()) {
            log.debug("mergeDeploymentResultFromAgent: no merger registered for {} — skipping", targetType);
            return;
        }
        DeploymentResultMerger merger = mergerOpt.get();

        CredentialReferenceEntity cred = credentialReferenceRepository
                .findByCredentialXref(deploymentCredentialXref)
                .orElse(null);
        if (cred == null || cred.getId() == null) {
            log.warn("mergeDeploymentResultFromAgent: credential xref={} not found — skipping", deploymentCredentialXref);
            return;
        }

        try {
            JsonNode fromAgent = objectMapper.readTree(perDomainJson);

            CertDeploymentConfigEntity entity = repository
                    .findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                            organizationId, userDomainCertId, cred.getId())
                    .orElseGet(() -> CertDeploymentConfigEntity.builder()
                            .organizationId(organizationId)
                            .userDomainCertId(userDomainCertId)
                            .deploymentCredentialId(cred.getId())
                            .deploymentCredentialXref(deploymentCredentialXref)
                            .provider(cred.getProvider())
                            .build());

            DeploymentConfigEnvelope envelope = DeploymentConfigEnvelope.read(objectMapper, entity.getConfigJson());
            JsonNode newResult = merger.merge(envelope.result(), fromAgent);
            if (newResult == null || newResult == envelope.result()) {
                log.debug("mergeDeploymentResultFromAgent: merger produced no change for {}", targetType);
                return;
            }

            entity.setDeploymentCredentialXref(deploymentCredentialXref);
            entity.setProvider(cred.getProvider());
            entity.setConfigJson(envelope.withResult(newResult).write(objectMapper));
            repository.save(entity);
            log.info("Merged deployment result: cred={}, userDomainCertId={}, targetType={}",
                    deploymentCredentialXref, userDomainCertId, targetType);
        } catch (Exception e) {
            log.error("mergeDeploymentResultFromAgent failed for cred={}, userDomainCertId={}: {}",
                    deploymentCredentialXref, userDomainCertId, e.getMessage(), e);
        }
    }

    /**
     * Generic non-Kubernetes upsert of the {@code targets} side of the envelope.
     *
     * <p>Validates the targets via the per-provider {@link DeploymentTargetsValidator} when one
     * is registered; for a provider with none, the payload is stored as-is with a warning. Preserves any existing
     * {@code result} so subsequent deploys remain "subsequent" (the adapter re-imports against
     * the prior identifier).
     *
     * @param requestedTargets nullable; when null/empty, an empty {@code targets} object is stored
     */
    @Transactional
    public void upsertGenericTargets(
            Long organizationId,
            Long userDomainCertId,
            CredentialReferenceEntity deploymentCredential,
            JsonNode requestedTargets) {
        if (PROVIDER_K8S.equals(deploymentCredential.getProvider())) {
            throw new BadRequestException(
                    "Use validateAndUpsertKubernetesConfig for KUBERNETES_SECRETS provider");
        }
        if (deploymentCredential.getId() == null) {
            throw new BadRequestException("Deployment credential is invalid");
        }

        TargetType targetType;
        try {
            targetType = TargetType.valueOf(deploymentCredential.getProvider());
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException(
                    "Unknown deployment provider: " + deploymentCredential.getProvider());
        }

        JsonNode validatedTargets;
        if (requestedTargets == null || requestedTargets.isNull() || requestedTargets.isEmpty()) {
            validatedTargets = objectMapper.createObjectNode();
        } else {
            DeploymentTargetsValidator validator = targetsValidatorRegistry.find(targetType).orElse(null);
            if (validator != null) {
                validatedTargets = validator.validate(requestedTargets, deploymentCredential);
            } else {
                log.warn("No DeploymentTargetsValidator registered for {} — storing targets unvalidated",
                        targetType);
                validatedTargets = requestedTargets;
            }
        }

        CertDeploymentConfigEntity entity = repository
                .findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                        organizationId, userDomainCertId, deploymentCredential.getId())
                .orElseGet(() -> CertDeploymentConfigEntity.builder()
                        .organizationId(organizationId)
                        .userDomainCertId(userDomainCertId)
                        .deploymentCredentialId(deploymentCredential.getId())
                        .deploymentCredentialXref(deploymentCredential.getCredentialXref())
                        .provider(deploymentCredential.getProvider())
                        .build());

        DeploymentConfigEnvelope envelope = DeploymentConfigEnvelope.read(objectMapper, entity.getConfigJson());
        entity.setDeploymentCredentialXref(deploymentCredential.getCredentialXref());
        entity.setProvider(deploymentCredential.getProvider());
        entity.setConfigJson(envelope.withTargets(validatedTargets).write(objectMapper));
        repository.save(entity);
    }

    @Transactional
    public String validateAndUpsertKubernetesConfig(
            Long organizationId,
            Long userDomainCertId,
            CredentialReferenceEntity deploymentCredential,
            JsonNode requestedNsSecretMap) {
        if (!PROVIDER_K8S.equals(deploymentCredential.getProvider())) {
            throw new BadRequestException("Kubernetes deployment config can be used only with provider KUBERNETES_SECRETS");
        }
        if (requestedNsSecretMap == null || requestedNsSecretMap.isNull()) {
            throw new BadRequestException("config is required for KUBERNETES_SECRETS when useDefault=false");
        }
        if (deploymentCredential.getId() == null) {
            throw new BadRequestException("Deployment credential is invalid for kubernetes configuration");
        }

        CredentialScope credentialScope = parseCredentialScope(deploymentCredential.getConfigJson());
        JsonNode nsMapsNode = buildValidatedNsMaps(requestedNsSecretMap, credentialScope.allowedNamespaces);
        String configJson = buildStoredConfigJson(credentialScope.authMethod, credentialScope.clusterName, nsMapsNode);

        CertDeploymentConfigEntity entity = repository
                .findByOrganizationIdAndUserDomainCertIdAndDeploymentCredentialIdAndIsDeletedFalse(
                        organizationId, userDomainCertId, deploymentCredential.getId())
                .orElseGet(() -> CertDeploymentConfigEntity.builder()
                        .organizationId(organizationId)
                        .userDomainCertId(userDomainCertId)
                        .deploymentCredentialId(deploymentCredential.getId())
                        .deploymentCredentialXref(deploymentCredential.getCredentialXref())
                        .provider(deploymentCredential.getProvider())
                        .build());
        entity.setDeploymentCredentialXref(deploymentCredential.getCredentialXref());
        entity.setProvider(deploymentCredential.getProvider());
        entity.setConfigJson(configJson);
        repository.save(entity);
        return configJson;
    }

    private CredentialScope parseCredentialScope(String configJson) {
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode authMethodNode = root.path("authMethod");
            JsonNode clusterNameNode = root.path("clusterName");
            JsonNode namespacesNode = root.path("namespaces");
            if (!authMethodNode.isString() || authMethodNode.asString().isBlank()) {
                throw new BadRequestException("Invalid deployment credential config: authMethod is required");
            }
            if (!clusterNameNode.isString() || clusterNameNode.asString().isBlank()) {
                throw new BadRequestException("Invalid deployment credential config: clusterName is required");
            }
            if (namespacesNode.isString()) {
                if (!ALL_NAMESPACES.equals(namespacesNode.asString())) {
                    throw new BadRequestException("Invalid deployment credential config: namespaces string must be all_namespaces");
                }
                return new CredentialScope(authMethodNode.asString(), clusterNameNode.asString(), null);
            }
            if (!namespacesNode.isArray() || namespacesNode.isEmpty()) {
                throw new BadRequestException("Invalid deployment credential config: namespaces must be non-empty array or all_namespaces");
            }
            Set<String> allowed = new LinkedHashSet<>();
            for (JsonNode namespaceNode : namespacesNode) {
                if (!namespaceNode.isString() || namespaceNode.asString().isBlank()) {
                    throw new BadRequestException("Invalid deployment credential config: namespaces must contain non-empty strings");
                }
                allowed.add(namespaceNode.asString());
            }
            return new CredentialScope(authMethodNode.asString(), clusterNameNode.asString(), allowed);
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Invalid deployment credential config format", ex);
        }
    }

    private JsonNode buildValidatedNsMaps(JsonNode requestedNsSecretMap, Set<String> allowedNamespaces) {
        if (requestedNsSecretMap.isObject()) {
            return validateAllNamespacesMap(requestedNsSecretMap, allowedNamespaces);
        }

        if (!requestedNsSecretMap.isArray() || requestedNsSecretMap.isEmpty()) {
            throw new BadRequestException("config.nsSecretMap must be either {\"all_namespaces\":\"secret\"} or non-empty namespace map array");
        }
        if (allowedNamespaces == null) {
            throw new BadRequestException("config.nsSecretMap must use all_namespaces because credential is configured for all_namespaces");
        }
        return validateScopedNamespaceArray(requestedNsSecretMap, allowedNamespaces);
    }

    private JsonNode validateAllNamespacesMap(JsonNode requestedNsSecretMap, Set<String> allowedNamespaces) {
        if (allowedNamespaces != null) {
            throw new BadRequestException("config.nsSecretMap must be namespace list because credential does not allow all_namespaces");
        }
        Iterator<Map.Entry<String, JsonNode>> fields = requestedNsSecretMap.properties().iterator();
        if (!fields.hasNext()) {
            throw new BadRequestException("config.nsSecretMap cannot be empty");
        }
        Map.Entry<String, JsonNode> entry = fields.next();
        if (fields.hasNext()) {
            throw new BadRequestException("config.nsSecretMap object form supports only all_namespaces");
        }
        if (!ALL_NAMESPACES.equals(entry.getKey())) {
            throw new BadRequestException("config.nsSecretMap object key must be all_namespaces");
        }
        if (!entry.getValue().isString() || entry.getValue().asString().isBlank()) {
            throw new BadRequestException("config.nsSecretMap all_namespaces value must be a non-empty secret name");
        }
        String secret = entry.getValue().asString();
        if (!secretNameValidator.isValid(secret)) {
            throw new BadRequestException("Invalid kubernetes secret name for all_namespaces");
        }
        return requestedNsSecretMap;
    }

    private JsonNode validateScopedNamespaceArray(JsonNode requestedNsSecretMap, Set<String> allowedNamespaces) {
        Set<String> seenNamespaces = new HashSet<>();
        for (JsonNode item : requestedNsSecretMap) {
            if (!item.isObject() || item.size() != 1) {
                throw new BadRequestException("Each config.nsSecretMap item must contain exactly one namespace->secret mapping");
            }
            Iterator<Map.Entry<String, JsonNode>> fields = item.properties().iterator();
            Map.Entry<String, JsonNode> entry = fields.next();
            String namespace = entry.getKey();
            if (!entry.getValue().isString() || entry.getValue().asString().isBlank()) {
                throw new BadRequestException("config.nsSecretMap secret values must be non-empty strings");
            }
            String secret = entry.getValue().asString();
            if (!namespaceNameValidator.isValid(namespace)) {
                throw new BadRequestException("Invalid kubernetes namespace name: " + namespace);
            }
            if (!secretNameValidator.isValid(secret)) {
                throw new BadRequestException("Invalid kubernetes secret name for namespace: " + namespace);
            }
            if (!allowedNamespaces.contains(namespace)) {
                throw new BadRequestException("Namespace '" + namespace + "' is not allowed by deployment credential config");
            }
            if (!seenNamespaces.add(namespace)) {
                throw new BadRequestException("Duplicate namespace in config.nsSecretMap: " + namespace);
            }
        }
        return requestedNsSecretMap;
    }

    private String buildStoredConfigJson(String authMethod, String clusterName, JsonNode nsMapsNode) {
        try {
            Map<String, Object> config = new LinkedHashMap<>();
            config.put("authProvider", authMethod);
            config.put("clusterName", clusterName);
            config.put("nsMaps", objectMapper.treeToValue(nsMapsNode, Object.class));
            return objectMapper.writeValueAsString(config);
        } catch (Exception ex) {
            throw new BadRequestException("Unable to prepare kubernetes deployment configuration", ex);
        }
    }

    private String reconcileAndPersistIfChanged(
            CertDeploymentConfigEntity entity,
            CredentialReferenceEntity deploymentCredential) {
        CredentialScope credentialScope = parseCredentialScope(deploymentCredential.getConfigJson());
        JsonNode storedNsMapsNode = extractNsMapsFromStoredConfig(entity.getConfigJson());
        JsonNode validatedNsMapsNode = buildValidatedNsMaps(storedNsMapsNode, credentialScope.allowedNamespaces);
        String reconciled = buildStoredConfigJson(
                credentialScope.authMethod,
                credentialScope.clusterName,
                validatedNsMapsNode);
        if (!reconciled.equals(entity.getConfigJson())) {
            entity.setConfigJson(reconciled);
            repository.save(entity);
        }
        return reconciled;
    }

    private JsonNode extractNsMapsFromStoredConfig(String configJson) {
        try {
            JsonNode root = objectMapper.readTree(configJson);
            JsonNode nsMaps = root.path("nsMaps");
            if (nsMaps.isMissingNode() || nsMaps.isNull()) {
                throw new BadRequestException("Stored kubernetes deployment config is missing nsMaps");
            }
            return nsMaps;
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Stored kubernetes deployment config is invalid JSON", ex);
        }
    }

    private record CredentialScope(String authMethod, String clusterName, Set<String> allowedNamespaces) {}
}
