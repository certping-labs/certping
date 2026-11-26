// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1DeleteOptions;
import io.kubernetes.client.openapi.models.V1Namespace;
import io.kubernetes.client.openapi.models.V1NamespaceList;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.util.ClientBuilder;
import io.kubernetes.client.util.KubeConfig;
import io.kubernetes.client.util.credentials.AccessTokenAuthentication;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

@Slf4j
@Component
public class KubernetesSecretService {

    private static final String TLS_SECRET_TYPE = "kubernetes.io/tls";
    private static final String FIELD_MANAGER = "certping-agent";
    private static final String DNS_SUBDOMAIN_PATTERN = "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
    private static final String ALL_NAMESPACES_KEY = "all_namespaces";
    private static final String DRY_RUN_ALL = "All";
    private static final String STAGED_SECRET_SUFFIX = "--cp-stage-";
    private static final int MAX_DNS_SUBDOMAIN_LENGTH = 253;
    private static final int ROLLOUT_ID_LENGTH = 12;

    private final KubernetesApiClientFactory apiClientFactory;
    private volatile KubeApis.Core cachedCoreV1Api;

    public KubernetesSecretService() {
        this(new KubernetesApiClientFactory());
    }

    @Autowired
    public KubernetesSecretService(KubernetesApiClientFactory apiClientFactory) {
        this.apiClientFactory = apiClientFactory;
    }

    /**
     * Executes the cluster-side part of a Kubernetes deployment after the adapter has validated the message.
     */
    public KubernetesDeploymentSummary deployTlsSecrets(CertificateBundle bundle,
            String clusterName,
            String domain,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            Map<String, String> namespaceSecretOverrides,
            boolean allNamespaces,
            String organizationId,
            String certificateXref) {
        KubeApis.Core api = getOrCreateCoreV1Api(authConfigSupplier.get());
        ApiExecutionResult<Map<String, String>> namespaceResolution = executeWithAuthRefreshRetry(
                api,
                authConfigSupplier,
                authRefreshEnabled,
                "resolve Kubernetes target namespaces",
                "DEPLOY_K8S_NAMESPACE_LIST_FAILED",
                null,
                null,
                currentApi -> resolveNamespaceSecretsInternal(currentApi, namespaceSecretOverrides, allNamespaces));
        api = namespaceResolution.api();
        Map<String, String> namespaceSecrets = namespaceResolution.value();
        String rolloutId = buildRolloutId();
        Map<String, String> stagedNamespaceSecrets = buildStagedSecretNames(namespaceSecrets, rolloutId);

        List<RolloutTarget> rolloutTargets = new ArrayList<>();
        for (Map.Entry<String, String> entry : namespaceSecrets.entrySet()) {
            String namespace = entry.getKey();
            String stableSecretName = entry.getValue();
            String stagedSecretName = stagedNamespaceSecrets.get(namespace);
            rolloutTargets.add(new RolloutTarget(namespace, stableSecretName, stagedSecretName, domain));
        }

        // Preflight every staged and live write before mutating the cluster so RBAC/admission failures stop the
        // deployment with zero live-secret changes.
        api = preflightRolloutTargets(api,
            authConfigSupplier,
            authRefreshEnabled,
            bundle,
            rolloutTargets,
            organizationId,
            certificateXref,
            clusterName);

        List<NamespaceSecretRef> stagedSecrets = new ArrayList<>();
        List<String> deployedSecretRefs = new ArrayList<>();
        List<AppliedSecret> appliedSecrets = new ArrayList<>();
        try {
            // Writing staged secrets first keeps the stable secret names untouched until the whole target set has
            // proven it can accept the rollout.
            api = stageRolloutTargets(api,
                authConfigSupplier,
                authRefreshEnabled,
                bundle,
                rolloutTargets,
                organizationId,
                certificateXref,
                clusterName,
                stagedSecrets);
            api = promoteRolloutTargets(api,
                authConfigSupplier,
                authRefreshEnabled,
                bundle,
                rolloutTargets,
                organizationId,
                certificateXref,
                clusterName,
                deployedSecretRefs,
                appliedSecrets);
        } finally {
            cleanupStagedSecretsBestEffort(api, authConfigSupplier, authRefreshEnabled, stagedSecrets);
        }

        return new KubernetesDeploymentSummary(namespaceSecrets.size(), deployedSecretRefs, appliedSecrets);
    }

    /**
     * Writes one or more TLS secrets within a single namespace using a staged rollout. Used for AGC where
     * each hostname maps to a dedicated Secret referenced by a Gateway/Ingress resource.
     */
    public KubernetesDeploymentSummary deployTlsSecretsForNamespace(CertificateBundle bundle,
            String clusterName,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            String namespace,
            Map<String, String> secretDomainMap,
            String organizationId,
            String certificateXref) {
        String cleanedNamespace = cleanRequiredValue(namespace, "namespace");
        validateNamespaceName(cleanedNamespace);

        if (secretDomainMap == null || secretDomainMap.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment requires at least one TLS secret name");
        }

        Map<String, String> normalizedSecrets = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : secretDomainMap.entrySet()) {
            String secretName = cleanRequiredValue(entry.getKey(), "secretName");
            validateSecretName(secretName);
            String domain = trimToNull(entry.getValue());
            if (normalizedSecrets.putIfAbsent(secretName, domain) != null) {
                throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                        "Kubernetes deployment contains duplicate secret name: '" + secretName + "'");
            }
        }

        KubeApis.Core api = getOrCreateCoreV1Api(authConfigSupplier.get());
        String rolloutId = buildRolloutId();

        List<RolloutTarget> rolloutTargets = new ArrayList<>();
        for (Map.Entry<String, String> entry : normalizedSecrets.entrySet()) {
            String secretName = entry.getKey();
            String domain = entry.getValue();
            String stagedSecretName = buildStagedSecretName(secretName, rolloutId);
            rolloutTargets.add(new RolloutTarget(cleanedNamespace, secretName, stagedSecretName, domain));
        }

        // Preflight every staged and live write before mutating the cluster so RBAC/admission failures stop the
        // deployment with zero live-secret changes.
        api = preflightRolloutTargets(api,
            authConfigSupplier,
            authRefreshEnabled,
            bundle,
            rolloutTargets,
            organizationId,
            certificateXref,
            clusterName);

        List<NamespaceSecretRef> stagedSecrets = new ArrayList<>();
        List<String> deployedSecretRefs = new ArrayList<>();
        List<AppliedSecret> appliedSecrets = new ArrayList<>();
        try {
            api = stageRolloutTargets(api,
                    authConfigSupplier,
                    authRefreshEnabled,
                    bundle,
                    rolloutTargets,
                    organizationId,
                    certificateXref,
                    clusterName,
                    stagedSecrets);
            api = promoteRolloutTargets(api,
                    authConfigSupplier,
                    authRefreshEnabled,
                    bundle,
                    rolloutTargets,
                    organizationId,
                    certificateXref,
                    clusterName,
                    deployedSecretRefs,
                    appliedSecrets);
        } finally {
            cleanupStagedSecretsBestEffort(api, authConfigSupplier, authRefreshEnabled, stagedSecrets);
        }

        return new KubernetesDeploymentSummary(normalizedSecrets.size(), deployedSecretRefs, appliedSecrets);
    }

    KubeApis.Core getOrCreateCoreV1Api(KubernetesAuthConfig authConfig) {
        if (!authConfig.inCluster()) {
            return buildCoreV1Api(authConfig);
        }

        KubeApis.Core local = cachedCoreV1Api;
        if (local != null) {
            return local;
        }

        synchronized (this) {
            if (cachedCoreV1Api == null) {
                cachedCoreV1Api = buildCoreV1Api(authConfig);
            }
            return cachedCoreV1Api;
        }
    }

    /**
     * Builds a Kubernetes API client from the normalized auth config.
     *
     * <p>In-cluster mode follows the upstream Java client pattern:
     * https://github.com/kubernetes-client/java/blob/master/examples/examples-release-latest/src/main/java/io/kubernetes/client/examples/InClusterClientExample.java
     */
    KubeApis.Core buildCoreV1Api(KubernetesAuthConfig authConfig) {
        return apiClientFactory.buildCoreV1Api(authConfig);
    }

    Map<String, String> resolveNamespaceSecrets(KubeApis.Core api,
            Map<String, String> namespaceSecretOverrides,
            boolean allNamespaces) {
        try {
            return resolveNamespaceSecretsInternal(api, namespaceSecretOverrides, allNamespaces);
        } catch (ApiException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromK8s(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", "list-namespaces", e);
            }
            throw translateApiException("DEPLOY_K8S_NAMESPACE_LIST_FAILED",
                    "list Kubernetes namespaces",
                    null,
                    null,
                    e);
        }
    }

    private Map<String, String> resolveNamespaceSecretsInternal(KubeApis.Core api,
            Map<String, String> namespaceSecretOverrides,
            boolean allNamespaces) throws ApiException {
        if (!allNamespaces) {
            if (namespaceSecretOverrides == null || namespaceSecretOverrides.isEmpty()) {
                throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                        "Kubernetes deployment requires explicit namespace mappings when nsMaps is not all_namespaces mode");
            }
            Map<String, String> normalized = new LinkedHashMap<>();
            namespaceSecretOverrides.forEach((namespace, secretName) -> {
                String cleanedNamespace = cleanRequiredValue(namespace, "namespace");
                String cleanedSecretName = cleanRequiredValue(secretName, "secretName");
                validateNamespaceName(cleanedNamespace);
                validateSecretName(cleanedSecretName);
                if (normalized.putIfAbsent(cleanedNamespace, cleanedSecretName) != null) {
                    throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                            "Kubernetes deployment config contains duplicate namespace mapping for '" + cleanedNamespace
                                    + "' after normalization");
                }
            });
            return normalized;
        }

        String secretName = resolveAllNamespacesSecretName(namespaceSecretOverrides);
        V1NamespaceList namespaces = api.listNamespaces(null, null);
        Map<String, String> namespaceSecrets = new LinkedHashMap<>();
        if (namespaces != null && namespaces.getItems() != null) {
            for (V1Namespace item : namespaces.getItems()) {
                String namespace = item != null && item.getMetadata() != null
                        ? item.getMetadata().getName()
                        : null;
                if (namespace != null && !namespace.isBlank()) {
                    namespaceSecrets.put(namespace, secretName);
                }
            }
        }

        if (namespaceSecrets.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_NAMESPACE_NOT_FOUND",
                    "No namespaces were returned by the in-cluster Kubernetes API");
        }
        return namespaceSecrets;
    }

    private String resolveAllNamespacesSecretName(Map<String, String> namespaceSecretOverrides) {
        if (namespaceSecretOverrides == null || namespaceSecretOverrides.size() != 1
                || !namespaceSecretOverrides.containsKey(ALL_NAMESPACES_KEY)) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes all_namespaces deployment requires nsMaps {\"all_namespaces\":\"secret-name\"}");
        }

        String secretName = cleanRequiredValue(namespaceSecretOverrides.get(ALL_NAMESPACES_KEY), "secretName");
        validateSecretName(secretName);
        return secretName;
    }

        private KubeApis.Core preflightRolloutTargets(KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            CertificateBundle bundle,
            List<RolloutTarget> rolloutTargets,
            String organizationId,
            String certificateXref,
            String clusterName) {
        KubeApis.Core currentApi = api;
        for (RolloutTarget target : rolloutTargets) {
            String namespace = target.namespace();
            String stableSecretName = target.stableSecretName();
            String stagedSecretName = target.stagedSecretName();
            String domain = target.domain();

            ApiExecutionResult<Boolean> stagedPreflight = executeWithAuthRefreshRetry(
                currentApi,
                authConfigSupplier,
                authRefreshEnabled,
                "preflight staged Kubernetes TLS secret write",
                "DEPLOY_K8S_PREFLIGHT_FAILED",
                namespace,
                stagedSecretName,
                candidateApi -> {
                verifySecretWriteAccess(candidateApi,
                    namespace,
                    stagedSecretName,
                    buildTlsSecret(namespace,
                        stagedSecretName,
                        bundle,
                        organizationId,
                        certificateXref,
                        domain,
                        clusterName,
                        Map.of(
                            "certping.net/staged-rollout-id", extractRolloutId(stagedSecretName),
                            "certping.net/stable-secret-name", stableSecretName)));
                return true;
                });
            currentApi = stagedPreflight.api();

            ApiExecutionResult<Boolean> stablePreflight = executeWithAuthRefreshRetry(
                currentApi,
                authConfigSupplier,
                authRefreshEnabled,
                "preflight live Kubernetes TLS secret write",
                "DEPLOY_K8S_PREFLIGHT_FAILED",
                namespace,
                stableSecretName,
                candidateApi -> {
                verifySecretWriteAccess(candidateApi,
                    namespace,
                    stableSecretName,
                    buildTlsSecret(namespace,
                        stableSecretName,
                        bundle,
                        organizationId,
                        certificateXref,
                        domain,
                        clusterName));
                return true;
                });
            currentApi = stablePreflight.api();
        }
        return currentApi;
        }

        private KubeApis.Core stageRolloutTargets(KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            CertificateBundle bundle,
            List<RolloutTarget> rolloutTargets,
            String organizationId,
            String certificateXref,
            String clusterName,
            List<NamespaceSecretRef> stagedSecrets) {
        KubeApis.Core currentApi = api;
        for (RolloutTarget target : rolloutTargets) {
            String namespace = target.namespace();
            String stableSecretName = target.stableSecretName();
            String stagedSecretName = target.stagedSecretName();
            String domain = target.domain();

            ApiExecutionResult<Boolean> stageWrite = executeWithAuthRefreshRetry(
                currentApi,
                authConfigSupplier,
                authRefreshEnabled,
                "stage Kubernetes TLS secret",
                "DEPLOY_K8S_SECRET_STAGE_FAILED",
                namespace,
                stagedSecretName,
                candidateApi -> {
                upsertTlsSecret(candidateApi,
                    namespace,
                    stagedSecretName,
                    buildTlsSecret(namespace,
                        stagedSecretName,
                        bundle,
                        organizationId,
                        certificateXref,
                        domain,
                        clusterName,
                        Map.of(
                            "certping.net/staged-rollout-id", extractRolloutId(stagedSecretName),
                            "certping.net/stable-secret-name", stableSecretName)));
                return true;
                });
            currentApi = stageWrite.api();
            stagedSecrets.add(new NamespaceSecretRef(namespace, stagedSecretName));
        }
        return currentApi;
        }

        private KubeApis.Core promoteRolloutTargets(KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            CertificateBundle bundle,
            List<RolloutTarget> rolloutTargets,
            String organizationId,
            String certificateXref,
            String clusterName,
            List<String> deployedSecretRefs,
            List<AppliedSecret> appliedSecrets) {
        KubeApis.Core currentApi = api;
        for (RolloutTarget target : rolloutTargets) {
            String namespace = target.namespace();
            String stableSecretName = target.stableSecretName();
            String domain = target.domain();

            ApiExecutionResult<V1Secret> liveWrite = executeWithAuthRefreshRetry(
                currentApi,
                authConfigSupplier,
                authRefreshEnabled,
                "promote Kubernetes TLS secret",
                "DEPLOY_K8S_SECRET_UPSERT_FAILED",
                namespace,
                stableSecretName,
                candidateApi ->
                    upsertTlsSecret(candidateApi,
                        namespace,
                        stableSecretName,
                        buildTlsSecret(namespace,
                            stableSecretName,
                            bundle,
                            organizationId,
                            certificateXref,
                            domain,
                            clusterName)));
            currentApi = liveWrite.api();
            deployedSecretRefs.add(namespace + "/" + stableSecretName);

            V1Secret response = liveWrite.value();
            String resourceVersion = null;
            String uid = null;
            if (response != null && response.getMetadata() != null) {
                resourceVersion = response.getMetadata().getResourceVersion();
                uid = response.getMetadata().getUid();
            }
            appliedSecrets.add(new AppliedSecret(namespace, stableSecretName, resourceVersion, uid));
        }
        return currentApi;
        }

    private void cleanupStagedSecretsBestEffort(KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            List<NamespaceSecretRef> stagedSecrets) {
        KubeApis.Core currentApi = api;
        for (NamespaceSecretRef stagedSecret : stagedSecrets) {
            try {
                ApiExecutionResult<Boolean> cleanup = executeWithAuthRefreshRetry(
                        currentApi,
                        authConfigSupplier,
                        authRefreshEnabled,
                        "cleanup staged Kubernetes TLS secret",
                        "DEPLOY_K8S_STAGED_SECRET_CLEANUP_FAILED",
                        stagedSecret.namespace(),
                        stagedSecret.secretName(),
                        false,
                        candidateApi -> {
                            deleteSecretIfPresent(candidateApi, stagedSecret.namespace(), stagedSecret.secretName());
                            return true;
                        });
                currentApi = cleanup.api();
            } catch (RuntimeException cleanupFailure) {
                log.warn("Best-effort cleanup failed for staged Kubernetes secret namespace={} secretName={} reason={}",
                        stagedSecret.namespace(),
                        stagedSecret.secretName(),
                        cleanupFailure.getMessage());
            }
        }
    }

    private V1Secret upsertTlsSecret(KubeApis.Core api,
            String namespace,
            String secretName,
            V1Secret desiredSecret) throws ApiException {
        V1Secret existing;
        try {
            existing = api.readSecret(secretName, namespace);
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                try {
                    return createTlsSecret(api, namespace, desiredSecret);
                } catch (ApiException createFailure) {
                    if (isAuthFailure(createFailure)) {
                        throw createFailure;
                    }
                    throw translateApiException("DEPLOY_K8S_SECRET_CREATE_FAILED",
                            "create Kubernetes TLS secret",
                            namespace,
                            secretName,
                            createFailure);
                }
            }
            throw e;
        }

        V1Secret replacement = desiredSecret;
        if (existing != null && existing.getMetadata() != null) {
            replacement.getMetadata().setResourceVersion(existing.getMetadata().getResourceVersion());
        }
        // Carrying forward resourceVersion makes a renewal behave like an update to the same object instead of
        // colliding with Kubernetes optimistic concurrency checks.
        V1Secret response = api.replaceSecret(secretName, namespace, replacement, null, FIELD_MANAGER);
        log.info("Updated Kubernetes TLS secret namespace={} secretName={}", namespace, secretName);
        return response;
    }

    private V1Secret createTlsSecret(KubeApis.Core api, String namespace, V1Secret secret) throws ApiException {
        V1Secret response = api.createSecret(namespace, secret, null, FIELD_MANAGER);
        log.info("Created Kubernetes TLS secret namespace={} secretName={}", namespace, secret.getMetadata().getName());
        return response;
    }

    private void verifySecretWriteAccess(KubeApis.Core api,
            String namespace,
            String secretName,
            V1Secret desiredSecret) throws ApiException {
        try {
            V1Secret existing = api.readSecret(secretName, namespace);
            V1Secret dryRunReplacement = desiredSecret;
            if (existing != null && existing.getMetadata() != null) {
                dryRunReplacement.getMetadata().setResourceVersion(existing.getMetadata().getResourceVersion());
            }
            api.replaceSecret(secretName, namespace, dryRunReplacement, DRY_RUN_ALL, FIELD_MANAGER);
        } catch (ApiException e) {
            // A 404 means the secret does not exist yet. Dry-running the create path verifies that the namespace
            // accepts this exact object shape before we start the real rollout.
            if (e.getCode() == 404) {
                api.createSecret(namespace, desiredSecret, DRY_RUN_ALL, FIELD_MANAGER);
                return;
            }
            throw e;
        }
    }

    private void deleteSecretIfPresent(KubeApis.Core api, String namespace, String secretName) throws ApiException {
        try {
            api.deleteSecret(secretName, namespace);
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                return;
            }
            throw e;
        }
    }

    private <T> ApiExecutionResult<T> executeWithAuthRefreshRetry(
            KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            String operation,
            String errorCode,
            String namespace,
            String secretName,
            KubernetesApiCall<T> call) {
        return executeWithAuthRefreshRetry(
                api,
                authConfigSupplier,
                authRefreshEnabled,
                operation,
                errorCode,
                namespace,
                secretName,
                true,
                call);
    }

    private <T> ApiExecutionResult<T> executeWithAuthRefreshRetry(
            KubeApis.Core api,
            Supplier<KubernetesAuthConfig> authConfigSupplier,
            boolean authRefreshEnabled,
            String operation,
            String errorCode,
            String namespace,
            String secretName,
            boolean logStackTrace,
            KubernetesApiCall<T> call) {
        try {
            return new ApiExecutionResult<>(api, call.execute(api));
        } catch (ApiException firstFailure) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromK8s(firstFailure, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("k8s secret upsert", secretName, firstFailure);
            }
            if (!authRefreshEnabled || !isAuthFailure(firstFailure)) {
                throw translateApiException(errorCode, operation, namespace, secretName, firstFailure, logStackTrace);
            }

            log.info("Kubernetes {} failed with auth status={} — refreshing auth and retrying once", operation, firstFailure.getCode());
            KubeApis.Core refreshedApi = getOrCreateCoreV1Api(authConfigSupplier.get());
            try {
                return new ApiExecutionResult<>(refreshedApi, call.execute(refreshedApi));
            } catch (ApiException secondFailure) {
                Optional<RateLimitClassifier.RateLimitVerdict> rl2 =
                        RateLimitClassifier.fromK8s(secondFailure, "DEPLOY_PROVIDER_THROTTLED");
                if (rl2.isPresent()) {
                    throw rl2.get().toRetryable("k8s secret upsert", secretName, secondFailure);
                }
                throw translateApiException(errorCode, operation, namespace, secretName, secondFailure, logStackTrace);
            }
        }
    }

    private boolean isAuthFailure(ApiException e) {
        return e.getCode() == 401 || e.getCode() == 403;
    }

    private Map<String, String> buildStagedSecretNames(Map<String, String> namespaceSecrets, String rolloutId) {
        Map<String, String> stagedSecretNames = new LinkedHashMap<>();
        namespaceSecrets.forEach((namespace, secretName) ->
                stagedSecretNames.put(namespace, buildStagedSecretName(secretName, rolloutId)));
        return stagedSecretNames;
    }

    private String buildStagedSecretName(String stableSecretName, String rolloutId) {
        String suffix = STAGED_SECRET_SUFFIX + rolloutId;
        int maxBaseLength = MAX_DNS_SUBDOMAIN_LENGTH - suffix.length();
        // Kubernetes limits names to 253 chars, so staged names reserve space for the rollout suffix instead of
        // risking a write-time validation error after preflight has already passed.
        String stablePrefix = stableSecretName.length() > maxBaseLength
                ? stableSecretName.substring(0, maxBaseLength)
                : stableSecretName;
        String stagedSecretName = stablePrefix + suffix;
        validateSecretName(stagedSecretName);
        return stagedSecretName;
    }

    private String buildRolloutId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, ROLLOUT_ID_LENGTH);
    }

    private String extractRolloutId(String stagedSecretName) {
        int markerIndex = stagedSecretName.lastIndexOf(STAGED_SECRET_SUFFIX);
        return markerIndex >= 0
                ? stagedSecretName.substring(markerIndex + STAGED_SECRET_SUFFIX.length())
                : stagedSecretName;
    }

    private V1Secret buildTlsSecret(String namespace,
            String secretName,
            CertificateBundle bundle,
            String organizationId,
            String certificateXref,
            String domain,
            String clusterName) {
        return buildTlsSecret(namespace, secretName, bundle, organizationId, certificateXref, domain, clusterName, Map.of());
    }

    private V1Secret buildTlsSecret(String namespace,
            String secretName,
            CertificateBundle bundle,
            String organizationId,
            String certificateXref,
            String domain,
            String clusterName,
            Map<String, String> extraAnnotations) {
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("app.kubernetes.io/managed-by", FIELD_MANAGER);

        Map<String, String> annotations = new LinkedHashMap<>();
        if (organizationId != null && !organizationId.isBlank()) {
            annotations.put("certping.net/organization-id", organizationId);
        }
        if (certificateXref != null && !certificateXref.isBlank()) {
            annotations.put("certping.net/certificate-xref", certificateXref);
        }
        if (domain != null && !domain.isBlank()) {
            annotations.put("certping.net/domain", domain);
        }
        if (clusterName != null && !clusterName.isBlank()) {
            annotations.put("certping.net/cluster-name", clusterName);
        }
        annotations.putAll(extraAnnotations);

        return new V1Secret()
                .metadata(new V1ObjectMeta()
                        .namespace(namespace)
                        .name(secretName)
                        .labels(labels)
                        .annotations(annotations))
                .type(TLS_SECRET_TYPE)
                .stringData(Map.of(
                        "tls.crt", bundle.fullChain(),
                        "tls.key", bundle.privateKey()));
    }

    private String cleanRequiredValue(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment config contains a blank " + fieldName);
        }
        return value.trim();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private void validateSecretName(String secretName) {
        validateDnsSubdomain(secretName, "secret name");
    }

    private void validateNamespaceName(String namespace) {
        validateDnsSubdomain(namespace, "namespace");
    }

    public static void validateDnsSubdomain(String value, String fieldName) {
        if (value == null || !value.matches(DNS_SUBDOMAIN_PATTERN)) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes " + fieldName + " is invalid: '" + value + "'. Expected a DNS-1123 subdomain");
        }
        if (value.length() > MAX_DNS_SUBDOMAIN_LENGTH) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes " + fieldName + " exceeds " + MAX_DNS_SUBDOMAIN_LENGTH + " characters: '" + value + "'");
        }
    }

    private RuntimeException translateApiException(
            String errorCode,
            String operation,
            String namespace,
            String secretName,
            ApiException e) {
        return translateApiException(errorCode, operation, namespace, secretName, e, true);
    }

    private RuntimeException translateApiException(
            String errorCode,
            String operation,
            String namespace,
            String secretName,
            ApiException e,
            boolean logStackTrace) {
        String debugId = UUID.randomUUID().toString();
        String bodySnippet = redactAndBound(e.getResponseBody());
        if (logStackTrace) {
            log.warn("[K8S-API][{}] {} failed httpStatus={} namespace={} secretName={} upstream={}",
                    debugId,
                    operation,
                    e.getCode(),
                    namespace,
                    secretName,
                    bodySnippet,
                    e);
        } else {
            log.warn("[K8S-API][{}] {} failed httpStatus={} namespace={} secretName={} upstream={}",
                    debugId,
                    operation,
                    e.getCode(),
                    namespace,
                    secretName,
                    bodySnippet);
        }

        StringBuilder safeMessage = new StringBuilder(operation)
                .append(" failed");
        if (namespace != null) {
            safeMessage.append(" for namespace=").append(namespace);
        }
        if (secretName != null) {
            safeMessage.append(" secretName=").append(secretName);
        }
        safeMessage.append(" (HTTP ").append(e.getCode()).append(", debugId=").append(debugId).append(")");

        if (e.getCode() == 400 || e.getCode() == 401 || e.getCode() == 403 || e.getCode() == 404) {
            return new PermanentAgentException(errorCode, safeMessage.toString(), e);
        }
        // Permission and validation failures will not heal on retry, so classifying them as permanent prevents
        // the queue from replaying the same broken deployment indefinitely.
        return new TransientAgentException(errorCode, safeMessage.toString(), e);
    }

    private String redactAndBound(String upstreamBody) {
        return KubernetesErrorSanitizer.redactAndBound(upstreamBody);
    }

    private String requireDirectApiServer(String apiServer) {
        String normalized = apiServer == null ? null : apiServer.trim();
        if (normalized == null || normalized.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing apiServer");
        }

        try {
            URI uri = URI.create(normalized);
            if (uri.getScheme() == null || uri.getScheme().isBlank() || uri.getHost() == null || uri.getHost().isBlank()) {
                throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                        "Kubernetes direct-token auth apiServer must be an absolute URL");
            }
            return normalized;
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth apiServer is not a valid URL", e);
        }
    }

    private String requireDirectBearerToken(String bearerToken) {
        String normalized = bearerToken == null ? null : bearerToken.trim();
        if (normalized == null || normalized.isEmpty()) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing bearerToken");
        }
        return normalized;
    }

    private byte[] requireDirectClusterCa(byte[] clusterCaCertPem) {
        if (clusterCaCertPem == null || clusterCaCertPem.length == 0) {
            throw new PermanentAgentException("DEPLOY_K8S_CREDENTIAL_INVALID",
                    "Kubernetes direct-token auth is missing cluster CA certificate");
        }
        return clusterCaCertPem;
    }

    private String safeHost(String apiServer) {
        try {
            URI uri = URI.create(apiServer);
            String host = uri.getHost();
            return host == null || host.isBlank() ? "<unknown>" : host;
        } catch (IllegalArgumentException e) {
            return "<invalid>";
        }
    }

    /**
     * Per-secret post-write metadata captured from the Kubernetes API response.
     * resourceVersion / uid are populated when the live write succeeds; both can be {@code null}
     * for older code paths that don't capture them (forward-compat).
     */
    public record AppliedSecret(String namespace, String secretName, String resourceVersion, String uid) {
    }

    public record KubernetesDeploymentSummary(int namespaceCount,
                                              List<String> deployedSecretRefs,
                                              List<AppliedSecret> appliedSecrets) {
    }

    private record NamespaceSecretRef(String namespace, String secretName) {
    }

    private record ApiExecutionResult<T>(KubeApis.Core api, T value) {
    }

    private record RolloutTarget(String namespace, String stableSecretName, String stagedSecretName, String domain) {
    }

    @FunctionalInterface
    private interface KubernetesApiCall<T> {
        T execute(KubeApis.Core api) throws ApiException;
    }

    public record KubernetesAuthConfig(
            boolean inCluster,
            String apiServer,
            String bearerToken,
            byte[] clusterCaCertPem,
            String kubeConfigYaml) {
        public static KubernetesAuthConfig forInCluster() {
            return new KubernetesAuthConfig(true, null, null, null, null);
        }

        public static KubernetesAuthConfig serviceAccountToken(String apiServer, String bearerToken, byte[] clusterCaCertPem) {
            return new KubernetesAuthConfig(false, apiServer, bearerToken, clusterCaCertPem, null);
        }

        public static KubernetesAuthConfig kubeConfig(String kubeConfigYaml) {
            return new KubernetesAuthConfig(false, null, null, null, kubeConfigYaml);
        }
    }
}
