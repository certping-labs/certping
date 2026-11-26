// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.dto.credconfig.credjson.dns.CertPingDnsKeyConfig;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CredentialRejectedException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import com.certmanagement.service.deployment.config.DeploymentScopeValidatorRegistry;
import com.certmanagement.audit.CredentialFields;
import com.certmanagement.service.audit.CredentialAuditRecorder;
import com.certmanagement.service.audit.CredentialAuditRecorder.StoredIn;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Manages credential references — metadata + secret-handle pointers only.
 * Credential values are NEVER stored here.
 *
 * <p>Handles are provider-neutral opaque strings. The active {@link AgentSecretStore} driver
 * decides their shape (Azure KV URI / AWS SM ARN / GCP resource name). The server materializes
 * credJson through {@link AgentSecretWriter}; a customer can instead pre-load their own store and
 * register the handle here for the agent to dereference at cert-lifecycle time.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialReferenceService {

    private static final Set<String> CUSTOMER_KEY_CAS = Set.of(CaProvider.DIGICERT.name());

    private static final int SECRET_HANDLE_MAX_LEN = 500;

    private final CredentialReferenceRepository credentialRepo;
    private final DomainCredentialConfigRepository domainCredentialConfigRepo;
    private final CertDeploymentConfigRepository certDeploymentConfigRepo;
    private final OrganizationRepository organizationRepository;
    private final KubernetesDeploymentConfigValidator kubernetesConfigValidator;
    private final DeploymentScopeValidatorRegistry scopeValidatorRegistry;
    private final ObjectMapper objectMapper;
    private final CredJsonDispatcher credJsonDispatcher;
    private final AgentSecretWriter agentSecretWriter;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final FeatureLifecycleLock featureLifecycleLock;
    /** Writes credential.* rows in the change's transaction. */
    private final CredentialAuditRecorder credentialAudit;

    /**
     * Registers a DNS credential reference for the organization.
     * secretHandle is a handle into the agent's secret store; it is validated but not read.
     *
     * @param keyConfig a CertPing DNS key's non-secret details ({@link CertPingDnsKeyConfig}), or null
     */
    @Transactional
    public CredentialReferenceEntity registerDns(Long organizationId, String provider,
            String description, String secretHandle, JsonNode credJson, JsonNode keyConfig) {
        validateOrganizationExists(organizationId);
        if (DnsCredentialAvailability.isThirdParty(provider)) {
            featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.DNS_CREDENTIALS);
        }

        String credentialXref = "cred-" + System.nanoTime();
        String configJson = certPingKeyConfig(provider, keyConfig);
        String resolvedKvPath;
        // Namecheap takes either its whole credential as credJson (stored in the agent secret store), or its
        // non-secret account details as credJson next to a secretHandle that holds the API key.
        if (isNamecheapDnsProvider(provider) && hasCredJson(credJson)
                && secretHandle != null && !secretHandle.isBlank()) {
            resolvedKvPath = validateKvPathAndReturn(secretHandle);
            configJson = credJsonDispatcher.serializeNamecheapAccountConfig(credJson);
        } else {
            requireMutuallyExclusive(secretHandle, credJson);
            resolvedKvPath = hasCredJson(credJson)
                    ? materializeCredJsonToAgentKv(organizationId, credentialXref, provider, "DNS", credJson)
                    : validateKvPathAndReturn(secretHandle);
        }

        CredentialReferenceEntity entity = CredentialReferenceEntity.builder()
                .credentialXref(credentialXref)
                .organizationId(organizationId)
                .provider(provider)
                .type("DNS")
                .description(description)
                .status("ACTIVE")
                .secretHandle(resolvedKvPath)
                .configJson(configJson)
                .build();

        CredentialReferenceEntity saved = credentialRepo.save(entity);
        credentialAudit.credentialCreated(saved, hasCredJson(credJson) && configJson == null
                ? StoredIn.CERTPING : StoredIn.OWN_STORE, null);
        log.info("Registered DNS credential: xref={}, organizationId={}, provider={}, mode={}",
                saved.getCredentialXref(), organizationId, provider,
                credJson != null ? "credJson" : "secretHandle");
        return saved;
    }

    /**
     * A CertPing DNS key's details for its credential's config, or null when none were sent.
     *
     * @throws BadRequestException when details are sent for another provider
     */
    private String certPingKeyConfig(String provider, JsonNode keyConfig) {
        if (!hasCredJson(keyConfig)) {
            return null;
        }
        if (DnsCredentialAvailability.isThirdParty(provider)) {
            throw new BadRequestException("Configuration details are only accepted for CertPing DNS credentials.");
        }
        return credJsonDispatcher.serializeCertPingKeyConfig(keyConfig);
    }

    /**
     * Registers a deployment credential reference with an optional initial
     * {@code configJson}. For {@code KUBERNETES_SECRETS}, this is cluster scope
     * (authMethod, clusterName, namespaces). Per-certificate deployment metadata
     * (ARNs, Azure certificate names, k8s nsMaps) is stored in {@code cert_deployment_config}.
     */
    @Transactional
    public CredentialReferenceEntity registerDeployment(Long organizationId, String provider,
            String description, String secretHandle,
            String configJson, JsonNode credJson) {
        validateOrganizationExists(organizationId);
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CREDENTIALS_MANAGEMENT);

        if (provider != null && DISCOVERY_ONLY_PROVIDERS.contains(provider)) {
            throw new BadRequestException(provider + " is for discovery only. Add it as a discovery credential.");
        }
        // validate config payload if provider is k8s, else continue
        kubernetesConfigValidator.validateForProvider(provider, configJson);
        validateProviderScope(provider, configJson);
        rejectPerCertificateMapsInCredentialConfig(provider, configJson);

        String credentialXref = "cred-" + System.nanoTime();
        String resolvedKvPath;
        // For ambient-identity auth modes (WORKLOAD_IDENTITY / INSTANCE_PROFILE / SA_INCLUSTER),
        // the agent never reads a KV secret — auth comes from the pod's federated token or the
        // ambient IAM identity. So any secretHandle / credJson the caller provided is meaningless and
        // would just confuse later reads (the GET API would show a secretHandle that nothing actually
        // points at). Coerce to null up-front so the stored state matches reality.
        if (isAmbientAuthMode(provider, configJson)) {
            if (secretHandle != null && !secretHandle.isBlank()) {
                log.info("Ignoring submitted secretHandle for ambient-auth credential: provider={}, authMode={}",
                        provider, extractAuthMode(configJson));
            }
            if (credJson != null && !credJson.isNull() && !credJson.isMissingNode()) {
                log.info("Ignoring submitted credJson for ambient-auth credential: provider={}, authMode={}",
                        provider, extractAuthMode(configJson));
            }
            resolvedKvPath = null;
        } else if (credJson != null && !credJson.isNull() && !credJson.isMissingNode()) {
            requireMutuallyExclusive(secretHandle, credJson);
            resolvedKvPath = materializeCredJsonToAgentKv(organizationId, credentialXref, provider, "DEPLOYMENT", credJson);
        } else {
            validateKvPathForProvider(provider, secretHandle, configJson);
            resolvedKvPath = secretHandle;
        }

        CredentialReferenceEntity entity = CredentialReferenceEntity.builder()
                .credentialXref(credentialXref)
                .organizationId(organizationId)
                .provider(provider)
                .type("DEPLOYMENT")
                .description(description)
                .status("ACTIVE")
                .secretHandle(resolvedKvPath)
                .configJson(configJson)
                .build();

        CredentialReferenceEntity saved = credentialRepo.save(entity);
        credentialAudit.credentialCreated(saved, resolvedKvPath == null ? StoredIn.NOT_NEEDED
                : hasCredJson(credJson) ? StoredIn.CERTPING : StoredIn.OWN_STORE, extractAuthMode(configJson));
        log.info("Registered DEPLOYMENT credential: xref={}, organizationId={}, provider={}, mode={}",
                saved.getCredentialXref(), organizationId, provider,
                credJson != null ? "credJson" : "secretHandle");
        return saved;
    }

    /**
     * Registers a read-only DISCOVERY credential. Today only {@code AWS_ORGANIZATION}: the agent
     * uses it to list accounts and read ACM in each one. It can never be picked for deployment.
     */
    @Transactional
    public CredentialReferenceEntity registerDiscovery(Long organizationId, String provider,
            String description, String secretHandle,
            String configJson, JsonNode credJson) {
        validateOrganizationExists(organizationId);
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CREDENTIALS_MANAGEMENT);
        if (provider == null || !DISCOVERY_ONLY_PROVIDERS.contains(provider)) {
            throw new BadRequestException("Discovery credentials support: " + DISCOVERY_ONLY_PROVIDERS);
        }
        validateProviderScope(provider, configJson);

        String credentialXref = "cred-" + System.nanoTime();
        String resolvedKvPath;
        if (isAmbientAuthMode(provider, configJson)) {
            resolvedKvPath = null;
        } else if (credJson != null && !credJson.isNull() && !credJson.isMissingNode()) {
            requireMutuallyExclusive(secretHandle, credJson);
            resolvedKvPath = materializeCredJsonToAgentKv(organizationId, credentialXref, provider, "DISCOVERY", credJson);
        } else {
            validateKvPathForProvider(provider, secretHandle, configJson);
            resolvedKvPath = secretHandle;
        }

        CredentialReferenceEntity saved = credentialRepo.save(CredentialReferenceEntity.builder()
                .credentialXref(credentialXref)
                .organizationId(organizationId)
                .provider(provider)
                .type("DISCOVERY")
                .description(description)
                .status("ACTIVE")
                .secretHandle(resolvedKvPath)
                .configJson(configJson)
                .build());
        credentialAudit.credentialCreated(saved, resolvedKvPath == null ? StoredIn.NOT_NEEDED
                : hasCredJson(credJson) ? StoredIn.CERTPING : StoredIn.OWN_STORE, extractAuthMode(configJson));
        log.info("Registered DISCOVERY credential: xref={}, organizationId={}, provider={}",
                saved.getCredentialXref(), organizationId, provider);
        return saved;
    }

    /**
     * Registers a certificate authority credential: the customer's own account key for a CA that issues on it.
     * Only DigiCert does; Let's Encrypt needs no key.
     */
    @Transactional
    public CredentialReferenceEntity registerCa(Long organizationId, String provider,
            String description, String secretHandle, JsonNode credJson) {
        validateOrganizationExists(organizationId);
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CREDENTIALS_MANAGEMENT);
        String caProvider = provider == null ? "" : provider.trim().toUpperCase();
        if (!CUSTOMER_KEY_CAS.contains(caProvider)) {
            throw new BadRequestException("Only DigiCert takes your own certificate authority key, not: " + provider);
        }
        requireMutuallyExclusive(secretHandle, credJson);

        String credentialXref = "cred-" + System.nanoTime();
        String resolvedKvPath = hasCredJson(credJson)
                ? materializeCredJsonToAgentKv(organizationId, credentialXref, caProvider, "CA", credJson)
                : validateKvPathAndReturn(secretHandle);

        CredentialReferenceEntity saved = credentialRepo.save(CredentialReferenceEntity.builder()
                .credentialXref(credentialXref)
                .organizationId(organizationId)
                .provider(caProvider)
                .type("CA")
                .description(description)
                .status("ACTIVE")
                .secretHandle(resolvedKvPath)
                .build());
        credentialAudit.credentialCreated(saved, hasCredJson(credJson) ? StoredIn.CERTPING : StoredIn.OWN_STORE, null);
        log.info("Registered CA credential: xref={}, organizationId={}, provider={}",
                saved.getCredentialXref(), organizationId, caProvider);
        return saved;
    }

    /** The organization's active certificate authority credentials (DigiCert keys), newest change first. */
    @Transactional(readOnly = true)
    public List<CredentialReferenceEntity> listCa(Long organizationId) {
        return list(organizationId, "CA");
    }

    /**
     * Replaces the key of one of the organization's CA credentials, keeping its xref so certificates
     * and renewals that use it pick up the new key. Write-only: the key is never read back.
     */
    @Transactional
    public CredentialReferenceEntity replaceCaKey(Long organizationId, String credentialXref,
            String secretHandle, JsonNode credJson) {
        requireCa(organizationId, credentialXref);
        boolean hasHandle = secretHandle != null && !secretHandle.isBlank();
        if (!hasHandle && !hasCredJson(credJson)) {
            throw new BadRequestException("Send the new key as credJson {\"apiKey\"} or a secretHandle");
        }
        requireMutuallyExclusive(secretHandle, credJson);
        return updateCredential(organizationId, credentialXref, hasHandle ? secretHandle : null, null, credJson);
    }

    /** Deletes one of the organization's CA credentials; refused while a live certificate uses it. */
    @Transactional
    public CredentialReferenceEntity deleteCa(Long organizationId, String credentialXref) {
        requireCa(organizationId, credentialXref);
        return delete(organizationId, credentialXref);
    }

    /** 404 unless the xref names a CA credential of this organization. */
    private CredentialReferenceEntity requireCa(Long organizationId, String credentialXref) {
        CredentialReferenceEntity entity = getByXref(organizationId, credentialXref);
        if (!"CA".equals(entity.getType())) {
            throw new ResourceNotFoundException(
                    "CA credential '" + credentialXref + "' not found for organization");
        }
        return entity;
    }

    /** Retrieve a specific credential reference by xref and organizationId. */
    @Transactional(readOnly = true)
    public CredentialReferenceEntity getByXref(Long organizationId, String credentialXref) {
        return credentialRepo.findByCredentialXrefAndOrganizationId(credentialXref, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Credential '" + credentialXref + "' not found for organization"));
    }

    /**
     * Retrieve a specific credential reference (internal use — includes secretHandle).
     */
    @Transactional(readOnly = true)
    public CredentialReferenceEntity getByXrefInternal(String credentialXref) {
        return credentialRepo.findByCredentialXref(credentialXref)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Credential '" + credentialXref + "' not found"));
    }

    /** Missing xrefs are absent from the map — response-building callers treat a stale ref as null, not an error. */
    @Transactional(readOnly = true)
    public java.util.Map<String, CredentialReferenceEntity> getByXrefsInternal(java.util.Collection<String> credentialXrefs) {
        if (credentialXrefs == null || credentialXrefs.isEmpty()) {
            return java.util.Map.of();
        }
        return credentialRepo.findByCredentialXrefIn(credentialXrefs).stream()
                .collect(java.util.stream.Collectors.toMap(CredentialReferenceEntity::getCredentialXref, java.util.function.Function.identity()));
    }

    /**
     * List all ACTIVE credentials for a organization, optionally filtered by type.
     */
    @Transactional(readOnly = true)
    public List<CredentialReferenceEntity> list(Long organizationId, String type) {
        if (type != null && !type.isBlank()) {
            return credentialRepo.findByOrganizationIdAndTypeAndStatusOrderByUpdatedAtDesc(
                    organizationId, type.toUpperCase(), "ACTIVE");
        }
        return credentialRepo.findByOrganizationIdAndStatusOrderByUpdatedAtDesc(organizationId, "ACTIVE");
    }

    /**
     * Soft-delete a credential reference.
     * Rejected if any active certificates reference this credential.
     */
    @Transactional
    public CredentialReferenceEntity delete(Long organizationId, String credentialXref) {
        CredentialReferenceEntity entity = getByXref(organizationId, credentialXref);
        assertManageable(organizationId, entity);
        if ("DELETED".equals(entity.getStatus())) {
            throw new CredentialRejectedException(CredentialRejectedException.NOT_ACTIVE,
                    "Credential '" + credentialXref + "' is already deleted");
        }

        long activeCertCount = credentialRepo.countActiveCertsReferencingCredential(credentialXref);
        if (activeCertCount > 0) {
            throw new CredentialRejectedException(CredentialRejectedException.IN_USE,
                    "Credential '" + credentialXref + "' is referenced by " + activeCertCount +
                            " active certificate(s). Revoke or re-assign them first.");
        }

        entity.setStatus("DELETED");
        CredentialReferenceEntity saved = credentialRepo.save(entity);

        // remove the xref out of every live config that still mentions it. The earlier
        // active-cert guard only blocks delete while CERTS reference the cred — config
        // rows (DNS map, deployment targets list, per-cert deployment config) can hold
        // a stale xref for soft-deleted/future certs and would otherwise try to publish
        // a renewal against a DELETED credential.
        int dccremoved = domainCredentialConfigRepo.removeCredentialXref(credentialXref);
        int cdcremoved = certDeploymentConfigRepo.softDeleteByCredentialXref(credentialXref);
        credentialAudit.credentialDeleted(saved, dccremoved + cdcremoved);
        if (dccremoved > 0 || cdcremoved > 0) {
            log.info("removed credential xref={} from {} domain_credential_config and {} cert_deployment_config row(s)",
                    credentialXref, dccremoved, cdcremoved);
        }

        if (entity.getSecretHandle() != null) {
            try {
                agentSecretWriter.deleteIfOwned(entity.getSecretHandle());
            } catch (Exception ex) {
                log.warn("Failed to purge agent secret for xref={} handle={}: {}",
                        credentialXref, entity.getSecretHandle(), ex.getMessage());
            }
        }
        log.info("Soft-deleted credential: xref={}, organizationId={}", credentialXref, organizationId);
        return saved;
    }

    /**
     * Third-party DNS credentials are managed under DNS_CREDENTIALS, every other credential but CertPing DNS (always
     * available) under CREDENTIALS_MANAGEMENT.
     */
    private void assertManageable(long organizationId, CredentialReferenceEntity entity) {
        if (!"DNS".equals(entity.getType())) {
            featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.CREDENTIALS_MANAGEMENT);
        } else if (DnsCredentialAvailability.isThirdParty(entity.getProvider())) {
            featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.DNS_CREDENTIALS);
        }
    }

    /**
     * Updates the KV path URI for an existing credential reference.
     * Use case: client rotated their KV secret and the URI has changed.
     */
    @Transactional
    public CredentialReferenceEntity updateCredential(Long organizationId, String credentialXref,
            String newKvPath, String configJson, JsonNode credJson) {
        CredentialReferenceEntity entity = getByXref(organizationId, credentialXref);
        assertManageable(organizationId, entity);
        if ("DELETED".equals(entity.getStatus())) {
            throw new CredentialRejectedException(CredentialRejectedException.NOT_ACTIVE,
                    "Cannot update a deleted credential reference");
        }
        kubernetesConfigValidator.validateForProvider(entity.getProvider(), configJson);
        validateProviderScope(entity.getProvider(), configJson);
        rejectPerCertificateMapsInCredentialConfig(entity.getProvider(), configJson);

        boolean updatedConfigFromTypedInput = false;
        if (!DnsCredentialAvailability.isThirdParty(entity.getProvider())) {
            if (configJson != null && !configJson.isBlank()) {
                entity.setConfigJson(serializeCertPingKeyConfig(configJson));
                updatedConfigFromTypedInput = true;
            } else if (hasCredJson(credJson) || isNewKvPath(entity, newKvPath)) {
                // The stored details describe the replaced key; kept, its expiry would hold the new key's renewals.
                entity.setConfigJson(null);
                updatedConfigFromTypedInput = true;
            }
        }
        if (isNamecheapDnsCredential(entity)
                && !isCertPingStoredHandle(entity.getSecretHandle())) {
            if (hasCredJson(credJson) && configJson != null && !configJson.isBlank()) {
                throw new BadRequestException(
                        "Namecheap account details were provided twice. Send them in either credential details or configuration, not both.");
            }
            if (newKvPath != null && !newKvPath.isBlank()) {
                validateKvPathForProvider(entity.getProvider(), newKvPath, configJson);
                entity.setSecretHandle(newKvPath);
            }
            if (hasCredJson(credJson)) {
                entity.setConfigJson(credJsonDispatcher.serializeNamecheapAccountConfig(credJson));
                updatedConfigFromTypedInput = true;
            } else if (configJson != null && !configJson.isBlank()) {
                entity.setConfigJson(serializeNamecheapConfigJson(configJson));
                updatedConfigFromTypedInput = true;
            }
        } else if (credJson != null && !credJson.isNull() && !credJson.isMissingNode()) {
            // Rotate: overwrite the secret in place at the existing path. secretHandle is not changeable here.
            if (newKvPath != null && !newKvPath.isBlank() && !newKvPath.equals(entity.getSecretHandle())) {
                throw new BadRequestException("Cannot change secretHandle while rotating credJson — omit secretHandle or pass the existing value");
            }
            overwriteCredJsonAtExistingPath(entity, credJson);
        } else if (newKvPath != null && !newKvPath.isBlank()) {
            // Path change: user supplied a new secretHandle, swap it in.
            validateKvPathForProvider(entity.getProvider(), newKvPath, configJson);
            entity.setSecretHandle(newKvPath);
        }
        if (!updatedConfigFromTypedInput && configJson != null && !configJson.isBlank()) {
            entity.setConfigJson(configJson);
        }
        // After applying the configJson change, if the new authMode is ambient (WI / INSTANCE_PROFILE
        // / SA_INCLUSTER) make sure secretHandle is null. Otherwise a credential migrated SP→WI keeps a
        // stale secretHandle that nothing consumes — confusing in the GET response and a source of
        // misleading runtime hypothesis when debugging deploys. Uses entity.configJson so the
        // check reflects the just-applied state.
        if (isAmbientAuthMode(entity.getProvider(), entity.getConfigJson())
                && entity.getSecretHandle() != null) {
            log.info("Clearing secretHandle for ambient-auth credential after update: xref={}, provider={}",
                    credentialXref, entity.getProvider());
            entity.setSecretHandle(null);
        }
        // The refusal described the credential as it was; the next deployment tells whether the update fixed it.
        entity.setLastErrorMessage(null);
        CredentialReferenceEntity saved = credentialRepo.save(entity);
        credentialAudit.credentialUpdated(saved, suppliedFields(newKvPath, configJson, credJson),
                extractAuthMode(saved.getConfigJson()));
        int rearmedSchedules = "DNS".equals(saved.getType())
                ? renewalScheduleRepository.rearmParkedFailuresByDnsCredentialXref(credentialXref)
                : 0;
        log.info("Updated credential metadata: xref={}, organizationId={}, changes=[{}{}{}]",
                credentialXref, organizationId,
                credJson != null && !credJson.isNull() ? "credJson " : "",
                newKvPath != null && !newKvPath.isBlank() ? "secretHandle " : "",
                configJson != null && !configJson.isBlank() ? "configJson" : "");
        if (rearmedSchedules > 0) {
            log.info("Rearmed {} parked renewal schedule(s) after DNS credential update: xref={}",
                    rearmedSchedules, credentialXref);
        }
        return saved;
    }

    /** The credential fields a change supplied, by name only: what its audit row says changed. */
    private List<String> suppliedFields(String newKvPath, String configJson, JsonNode credJson) {
        List<String> fields = new ArrayList<>(3);
        if (hasCredJson(credJson)) {
            fields.add(CredentialFields.DETAILS);
        }
        if (newKvPath != null && !newKvPath.isBlank()) {
            fields.add(CredentialFields.SECRET_HANDLE);
        }
        if (configJson != null && !configJson.isBlank()) {
            fields.add(CredentialFields.CONFIGURATION);
        }
        return fields;
    }

    /**
     * Per-provider scope schema validation. Skips Kubernetes (handled by
     * {@code KubernetesDeploymentConfigValidator} above). Skips when a provider has no registered
     * scope validator — accepts any JSON, which is fine for providers we haven't covered.
     * Throws {@link BadRequestException} on bad scope so operators get an immediate 400 instead
     * of a deferred deploy-time failure.
     */
    private void validateProviderScope(String provider, String configJson) {
        if (provider == null || configJson == null || configJson.isBlank()) {
            return;
        }
        if ("KUBERNETES_SECRETS".equals(provider)) {
            return;
        }
        TargetType targetType;
        try {
            targetType = TargetType.valueOf(provider);
        } catch (IllegalArgumentException e) {
            // Provider isn't a known TargetType (DNS providers, etc.) — nothing to do here.
            return;
        }
        Optional<DeploymentScopeValidator> validator = scopeValidatorRegistry.find(targetType);
        if (validator.isEmpty()) {
            log.warn("No DeploymentScopeValidator registered for provider {} — skipping scope validation",
                    provider);
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            validator.get().validate(root);
        } catch (BadRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new BadRequestException("configJson must be valid JSON when provided", e);
        }
    }

    /**
     * Per-certificate deployment identifiers must not be stored on the deployment credential;
     * they belong in {@code cert_deployment_config} (or a manual deploy override).
     */
    private void rejectPerCertificateMapsInCredentialConfig(String provider, String configJson) {
        if (configJson == null || configJson.isBlank() || "KUBERNETES_SECRETS".equals(provider)) {
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            if (root != null && root.isObject()) {
                if (root.hasNonNull("domainCertificateArns") || root.hasNonNull("domainCertificateNames")) {
                    throw new BadRequestException(
                            "credential config must not contain domainCertificateArns or domainCertificateNames; "
                                    + "per-certificate deployment metadata is stored in cert_deployment_config.");
                }
            }
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("configJson must be valid JSON when provided", ex);
        }
    }

    // ------------------------------------------------------------------ //

    // Provider-neutral: handle shape depends on the org's active secret store; agent parses fully.
    public void validateKvPath(String secretHandle) {
        if (secretHandle == null || secretHandle.isBlank()) {
            throw new CredentialRejectedException(CredentialRejectedException.SECRET_HANDLE_INVALID,
                    "Secret handle is required.");
        }
        if (secretHandle.length() > SECRET_HANDLE_MAX_LEN) {
            throw new CredentialRejectedException(CredentialRejectedException.SECRET_HANDLE_INVALID,
                    "Secret handle too long (max " + SECRET_HANDLE_MAX_LEN + " chars).");
        }
        for (int i = 0; i < secretHandle.length(); i++) {
            char c = secretHandle.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                throw new CredentialRejectedException(CredentialRejectedException.SECRET_HANDLE_INVALID,
                        "Secret handle contains a control character.");
            }
        }
    }

    private static final java.util.Set<String> AWS_PROVIDERS = java.util.Set.of(
            "AWS_ACM", "AWS_ALB", "AWS_NLB", "AWS_API_GW_REST", "AWS_API_GW_HTTP", "AWS_CLOUDFRONT",
            "AWS_ORGANIZATION");

    /** Providers that can only scan. They are registered as DISCOVERY credentials, never DEPLOYMENT. */
    public static final java.util.Set<String> DISCOVERY_ONLY_PROVIDERS = java.util.Set.of("AWS_ORGANIZATION");

    private static final java.util.Set<String> AZURE_PROVIDERS = java.util.Set.of(
            "AZURE_KV", "AZURE_APP_GW", "AZURE_APP_GW_CONTAINERS", "AZURE_AFD");

    private static final java.util.Set<String> GCP_PROVIDERS = java.util.Set.of(
            "GCP_CERT_MANAGER", "GCP_ALB", "GCP_PROXY_NLB", "GCP_API_GW", "GCP_CLOUD_CDN");

    private void validateKvPathForProvider(String provider, String secretHandle, String configJson) {
        if (secretHandle != null && !secretHandle.isBlank()) {
            validateKvPath(secretHandle);
            return;
        }
        // KUBERNETES_SECRETS with SA_INCLUSTER — no KV secret needed (agent uses in-cluster SA token)
        if ("KUBERNETES_SECRETS".equals(provider) && "SA_INCLUSTER".equals(extractAuthMethod(configJson))) {
            return;
        }
        // AWS INSTANCE_PROFILE — no KV secret needed (agent uses ambient EC2/EKS identity)
        if (AWS_PROVIDERS.contains(provider) && "INSTANCE_PROFILE".equals(extractAuthMode(configJson))) {
            return;
        }
        // AWS ASSUME_ROLE — secretHandle is OPTIONAL. The agent's AwsAssumeRoleService falls back to
        // DefaultCredentialsProvider (IRSA / Pod Identity / instance profile / env vars) when no
        // static bootstrap keys are stored in KV, then chains STS AssumeRole onto that ambient
        // identity. Caller may still provide secretHandle if they want explicit bootstrap keys.
        if (AWS_PROVIDERS.contains(provider) && "ASSUME_ROLE".equals(extractAuthMode(configJson))) {
            return;
        }
        // Azure WORKLOAD_IDENTITY — no KV secret needed (agent uses federated token from environment)
        if (AZURE_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(extractAuthMode(configJson))) {
            return;
        }
        // GCP WORKLOAD_IDENTITY — no KV secret needed (agent uses Application Default Credentials
        // resolved from Workload Identity Federation; optional impersonateServiceAccount in scope
        // is a sub-option but still ambient).
        if (GCP_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(extractAuthMode(configJson))) {
            return;
        }
        throw new CredentialRejectedException(CredentialRejectedException.SECRET_HANDLE_INVALID,
                "secretHandle is required unless: KUBERNETES_SECRETS with authMethod=SA_INCLUSTER, " +
                "an AWS provider with authMode=INSTANCE_PROFILE or ASSUME_ROLE, " +
                "an Azure provider with authMode=WORKLOAD_IDENTITY, " +
                "or a GCP provider with authMode=WORKLOAD_IDENTITY");
    }

    /**
     * True when the provider + authMode combination means the agent will authenticate via an
     * ambient identity (federated token, EC2/EKS instance profile, in-cluster SA token) — and
     * therefore does NOT need any KV secret blob or secretHandle. Mirrors the cases that
     * {@link #validateKvPathForProvider} allows null secretHandle for. Centralised here so register +
     * update paths share one definition.
     */
    private boolean isAmbientAuthMode(String provider, String configJson) {
        if (provider == null || configJson == null || configJson.isBlank()) {
            return false;
        }
        if ("KUBERNETES_SECRETS".equals(provider) && "SA_INCLUSTER".equals(extractAuthMethod(configJson))) {
            return true;
        }
        String authMode = extractAuthMode(configJson);
        if (AWS_PROVIDERS.contains(provider) && "INSTANCE_PROFILE".equals(authMode)) {
            return true;
        }
        // NOTE: AWS ASSUME_ROLE is intentionally NOT treated as ambient here.
        // ASSUME_ROLE may carry bootstrap static keys in KV (optional), and the agent
        // (AwsAssumeRoleService.baseCredentialsProvider) uses them when present and
        // falls back to DefaultCredentialsProvider otherwise. If we flagged it ambient
        // we'd silently drop a caller's submitted secretHandle, which is a real use case for
        // cross-account chained roles. The secretHandle-null-OK semantics for ASSUME_ROLE
        // live only in validateKvPathForProvider above.
        if (AZURE_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(authMode)) {
            return true;
        }
        if (GCP_PROVIDERS.contains(provider) && "WORKLOAD_IDENTITY".equals(authMode)) {
            return true;
        }
        return false;
    }

    private String extractAuthMethod(String configJson) {
        return extractJsonTextField(configJson, "authMethod");
    }

    private String extractAuthMode(String configJson) {
        return extractJsonTextField(configJson, "authMode");
    }

    private String extractJsonTextField(String configJson, String fieldName) {
        if (configJson == null || configJson.isBlank()) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(configJson);
            if (root == null || !root.isObject()) {
                return null;
            }
            JsonNode node = root.get(fieldName);
            if (node == null || node.isNull() || !node.isString()) {
                return null;
            }
            String value = node.asString();
            return value == null || value.isBlank() ? null : value;
        } catch (Exception ex) {
            return null;
        }
    }

    private void validateOrganizationExists(Long organizationId) {
        if (!organizationRepository.existsById(organizationId)) {
            throw new ResourceNotFoundException("Organization not found: " + organizationId);
        }
    }

    // ──────────────────────── credJson helpers ────────────────────────

    /**
     * Validates credJson against the provider's typed DTO, then writes the resulting bytes
     * (JSON or — for Cloudflare DNS — bare string) to the agent KV. Returns the path that
     * should be persisted on the credential reference so the agent's existing reader path
     * works unchanged.
     */
    private String materializeCredJsonToAgentKv(Long organizationId, String credentialXref,
            String provider, String credentialType, JsonNode credJson) {
        if (!agentSecretWriter.isAvailable()) {
            throw new BadRequestException(
                    "credJson is not supported in this environment — agent secret store is not configured. "
                            + "Set certping.agent-secret-store.provider or pass secretHandle instead.");
        }
        agentSecretWriter.requireReadableByAgents(organizationId);
        String secretValue = credJsonDispatcher.serializeForKv(provider, credentialType, credJson);
        String secretName = agentSecretWriter.buildSecretName(organizationId, credentialXref);
        return agentSecretWriter.writeSecret(secretName, secretValue);
    }

    /**
     * Rotate path: overwrite the secret at the entity's existing secretHandle in place.
     * The path itself does not change so cert command emission / agent reads stay identical.
     */
    private void overwriteCredJsonAtExistingPath(CredentialReferenceEntity entity, JsonNode credJson) {
        if (!agentSecretWriter.isAvailable()) {
            throw new BadRequestException(
                    "credJson rotation is not supported in this environment — agent secret store is not configured.");
        }
        String existingHandle = entity.getSecretHandle();
        if (existingHandle == null || existingHandle.isBlank()) {
            throw new BadRequestException(
                    "Cannot rotate credJson — credential has no existing secretHandle. Re-register with credJson instead.");
        }
        agentSecretWriter.requireReadableByAgents(entity.getOrganizationId());
        String secretValue = credJsonDispatcher.serializeForKv(
                entity.getProvider(), entity.getType(), credJson);
        // Overwrite at the existing handle — provider-neutral, keeps the handle stable for the
        // agent's downstream read path. Versioned providers (AWS, GCP) return a refreshed handle;
        // Azure returns the same handle unchanged. We ignore the return value because the entity's
        // stored handle stays valid on Azure and is version-agnostic on AWS/GCP (secretsmanager
        // resolves partial ARNs and GCP's "/versions/latest" is always current).
        agentSecretWriter.overwriteAtHandle(existingHandle, secretValue);
    }

    private void requireMutuallyExclusive(String secretHandle, JsonNode credJson) {
        boolean hasKvPath = secretHandle != null && !secretHandle.isBlank();
        if (hasKvPath && hasCredJson(credJson)) {
            throw new BadRequestException("Supply either secretHandle or credJson, not both");
        }
    }

    private boolean hasCredJson(JsonNode credJson) {
        return credJson != null && !credJson.isNull() && !credJson.isMissingNode();
    }

    private boolean isNamecheapDnsProvider(String provider) {
        return provider != null && "NAMECHEAP".equalsIgnoreCase(provider);
    }

    private boolean isNamecheapDnsCredential(CredentialReferenceEntity entity) {
        return entity != null
                && isNamecheapDnsProvider(entity.getProvider())
                && "DNS".equalsIgnoreCase(entity.getType());
    }

    private static boolean isNewKvPath(CredentialReferenceEntity entity, String newKvPath) {
        return newKvPath != null && !newKvPath.isBlank() && !newKvPath.equals(entity.getSecretHandle());
    }

    private String serializeCertPingKeyConfig(String configJson) {
        try {
            return credJsonDispatcher.serializeCertPingKeyConfig(objectMapper.readTree(configJson));
        } catch (JacksonException ex) {
            throw new BadRequestException("configJson must be valid JSON when provided", ex);
        }
    }

    private String serializeNamecheapConfigJson(String configJson) {
        try {
            return credJsonDispatcher.serializeNamecheapAccountConfig(objectMapper.readTree(configJson));
        } catch (BadRequestException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BadRequestException("Namecheap account details must be valid JSON.", ex);
        }
    }

    /** Secrets CertPing stored for the agent from pasted values, as opposed to the customer's own vault. */
    static boolean isCertPingStoredHandle(String handle) {
        return handle != null && (handle.startsWith("local:") || handle.startsWith("sealed:"));
    }

    private String validateKvPathAndReturn(String secretHandle) {
        validateKvPath(secretHandle);
        return secretHandle;
    }

}
