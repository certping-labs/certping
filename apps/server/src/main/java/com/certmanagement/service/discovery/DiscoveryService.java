// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.transport.TransportProperties;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.discovery.DiscoveredCertDto;
import com.certmanagement.dto.discovery.DiscoveredCertDetailDto;
import com.certmanagement.dto.discovery.DiscoveryRunResponse;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryConfigStatus;
import com.certmanagement.entity.DiscoveryScanStatus;
import com.certmanagement.entity.DiscoveredCertEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertDiscoveryCommand;
import com.certmanagement.messaging.model.CertDiscoveryResponse;
import com.certmanagement.messaging.model.DiscoveredCertEntry;
import com.certmanagement.messaging.model.DiscoveryCompleteMessage;
import com.certmanagement.messaging.model.KubernetesDiscoveryData;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DiscoveryConfigRepository;
import com.certmanagement.repository.DiscoveredCertObservationRepository;
import com.certmanagement.repository.DiscoveredCertObservationRepository.DiscoveredCertCredentialView;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveredCertSpec;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.audit.DiscoveryAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.time.temporal.ChronoUnit.DAYS;

/**
 * Orchestrates certificate discovery:
 * <ul>
 *   <li>{@link #triggerDiscovery} resolves the deployment credential KV path and
 *       publishes a {@code CERT_DISCOVERY} command to the agent. Triggers persist the run in one
 *       short transaction and publish after it commits, so no row lock or connection is held
 *       across the queue send; a failed publish is recorded in a second short transaction.</li>
 *   <li>Feature work: every trigger re-checks {@code DISCOVERY} inside its transaction, and
 *       inbound results for an organization with it off are dropped and the scan CANCELLED.</li>
 *   <li>{@link #persistDiscoveryResults} persists inbound {@code CERT_DISCOVERY_RESPONSE}
 *       results, upserts discovered_cert rows, and evaluates managed status.</li>
 *   <li>Read methods for the discovery controller.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DiscoveryService {

    private static final String TARGET_KUBERNETES_SECRETS = "KUBERNETES_SECRETS";
    private static final String CREDENTIAL_TYPE_DEPLOYMENT = "DEPLOYMENT";
    private static final String CREDENTIAL_TYPE_DISCOVERY = "DISCOVERY";
    private static final String CREDENTIAL_STATUS_ACTIVE = "ACTIVE";
    private static final String UNKNOWN_TRACE_ID = "unknown";
    /** Slack past the command TTL before an undelivered scan is given up on (agent may be mid-scan). */
    private static final Duration UNDELIVERED_GRACE = Duration.ofMinutes(15);
    private static final String CANCELLED_MESSAGE =
            "Discovery was stopped because certificate discovery is turned off for this organization.";
    private static final String EXPIRED_MESSAGE =
            "Discovery did not start: no agent picked up the request in time. Check the agent is running and try again.";
    private final CertAgentPublisher           certAgentPublisher;
    private final OrgTypeResolver              orgTypeResolver;
    private final CredentialReferenceRepository credentialReferenceRepository;
    private final DiscoveryConfigRepository     discoveryConfigRepository;
    private final DiscoveredCertRepository     discoveredCertRepository;
    private final DiscoveredCertObservationRepository discoveredCertObservationRepository;
    private final CertificateRepository        certificateRepository;
    private final DiscoveryScanService          discoveryScanService;
    private final DiscoveryScopeKeyFactory      discoveryScopeKeyFactory;
    private final KubernetesDiscoveryDataValidator kubernetesDataValidator;
    private final DiscoveryCredentialPolicy     credentialPolicy;
    private final DiscoveredCertMapper           discoveredCertMapper;
    private final TransactionTemplate            transactionTemplate;
    private final FeatureFlagService             featureFlagService;
    private final TransportProperties            transportProperties;
    private final FeatureLifecycleLock           featureLifecycleLock;
    private final FeatureFlagResolver            featureFlagResolver;
    /** The member's discovery rows, written in the run's own transaction. */
    private final DiscoveryAuditRecorder         discoveryAudit;

    // ------------------------------------------------------------------ //
    //  Outbound trigger
    // ------------------------------------------------------------------ //

    /**
     * Resolves the deployment credential's KV path and publishes a {@code CERT_DISCOVERY}
     * command to the agent for the given organization and target type.
     *
     * @param organizationId numeric org ID
     * @param targetType     target type string matching agent's TargetType enum
     * @param credentialXref xref of the deployment credential to use for authentication
     * @return user-facing run status for the dispatched command
     * @throws com.certmanagement.exception.FeatureDisabledException when DISCOVERY is off for the org
     */
    public DiscoveryRunResponse triggerDiscovery(Long organizationId, String targetType, String credentialXref) {
        String normalizedTargetType = requireTargetType(targetType);
        // 400 before anything is stored for a target the agent cannot discover.
        DiscoveryCredentialPolicy.requireDiscoverableTargetStatic(normalizedTargetType);
        String normalizedCredentialXref = requireCredentialXref(credentialXref);
        DispatchPlan plan = inTransaction(() -> {
            assertDiscoveryEnabled(organizationId);
            CredentialReferenceEntity credential = loadActiveDeploymentCredential(
                    organizationId, normalizedCredentialXref);
            DiscoveryConfigEntity config = upsertDiscoveryConfig(
                    organizationId, normalizedTargetType, credential);
            return prepareDispatch(config, credential, DiscoveryAuditRecorder.Trigger.NEW);
        });
        return publish(plan);
    }

    /** Runs one saved configuration; a run already in flight is returned rather than duplicated. */
    public DiscoveryRunResponse triggerSavedDiscovery(Long organizationId, Long configId) {
        DispatchPlan plan = inTransaction(() -> {
            assertDiscoveryEnabled(organizationId);
            DiscoveryConfigEntity entity = loadDiscoveryConfigForUpdate(organizationId, configId);
            DiscoveryRunResponse runningRun = refreshRunningRun(entity);
            return runningRun != null ? DispatchPlan.settled(runningRun)
                    : prepareSavedConfig(entity, DiscoveryAuditRecorder.Trigger.SAVED);
        });
        return publish(plan);
    }

    /**
     * Runs every saved configuration of the organization. The row locks are held only while the
     * runs are recorded (one short transaction); the publishes happen after it commits.
     */
    public List<DiscoveryRunResponse> triggerAllSavedDiscovery(Long organizationId) {
        List<DispatchPlan> plans = inTransaction(() -> {
            assertDiscoveryEnabled(organizationId);
            // Bounded: at most one live configuration per target type (uq_discovery_config_org_target_active).
            return discoveryConfigRepository.findAllByOrganizationIdForUpdate(organizationId)
                    .stream()
                    .map(config -> {
                        DiscoveryRunResponse runningRun = refreshRunningRun(config);
                        // Bulk: each configuration that does not start records its own failure row.
                        return runningRun != null ? DispatchPlan.settled(runningRun)
                                : prepareSavedConfig(config, DiscoveryAuditRecorder.Trigger.ALL_SAVED);
                    })
                    .toList();
        });
        return plans.stream().map(this::publish).collect(Collectors.toList());
    }

    @Transactional
    public List<DiscoveryRunResponse> listDiscoveryConfigs(Long organizationId) {
        return discoveryConfigRepository
                .findAllByOrganizationIdAndIsDeletedFalseOrderByUpdatedAtDesc(organizationId)
                .stream()
                .map(this::toRefreshedRunResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    public DiscoveryRunResponse getDiscoveryConfigStatus(Long organizationId, Long configId) {
        DiscoveryConfigEntity config = discoveryConfigRepository
                .findByIdAndOrganizationIdAndIsDeletedFalse(configId, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("Discovery configuration not found"));
        return toRefreshedRunResponse(config);
    }

    @Transactional
    public void deleteDiscoveryConfig(Long organizationId, Long configId) {
        DiscoveryConfigEntity config = loadDiscoveryConfigForUpdate(organizationId, configId);
        boolean alreadyDeleted = Boolean.TRUE.equals(config.getIsDeleted());
        config.setIsDeleted(true);
        config.setStatusMessage("Discovery configuration was deleted.");
        discoveryConfigRepository.save(config);
        if (!alreadyDeleted) {
            discoveryAudit.configDeleted(config);
        }
    }

    /**
     * Runs a saved configuration. One whose credential is gone or no longer usable is not run: it says why on
     * the configuration, and its failure is recorded explicitly, since the request itself succeeds.
     */
    private DispatchPlan prepareSavedConfig(DiscoveryConfigEntity entity, DiscoveryAuditRecorder.Trigger trigger) {
        String unsupported = DiscoveryCredentialPolicy.unsupportedTargetReason(entity.getTargetType());
        if (unsupported != null) {
            // A configuration saved earlier for a target the agent cannot discover: not run.
            entity.setStatus(DiscoveryConfigStatus.CONFIG_REQUIRED);
            entity.setStatusMessage(unsupported.length() <= 300 ? unsupported : unsupported.substring(0, 300));
            discoveryConfigRepository.save(entity);
            discoveryAudit.scanNotStarted(entity, trigger, DiscoveryAuditRecorder.CREDENTIAL_INVALID);
            return DispatchPlan.settled(toRunResponse(entity));
        }
        CredentialReferenceEntity credential = loadConfiguredCredential(entity);
        if (credential == null) {
            discoveryConfigRepository.save(entity);
            discoveryAudit.scanNotStarted(entity, trigger, DiscoveryAuditRecorder.CREDENTIAL_NOT_ACTIVE);
            return DispatchPlan.settled(toRunResponse(entity));
        }
        reconcileSavedConfig(entity, credential);
        try {
            return prepareDispatch(entity, credential, trigger);
        } catch (BadRequestException exception) {
            entity.setStatus(DiscoveryConfigStatus.CREDENTIAL_INVALID);
            entity.setStatusMessage("The saved discovery credential is no longer usable. Update the credential and try again.");
            discoveryConfigRepository.save(entity);
            discoveryAudit.scanNotStarted(entity, trigger, DiscoveryAuditRecorder.CREDENTIAL_INVALID);
            log.warn("Saved discovery configuration is invalid: configId={}, organizationId={}, credentialXref={}, error={}",
                    entity.getId(), entity.getOrganizationId(), entity.getCredentialXref(), exception.getMessage());
            return DispatchPlan.settled(toRunResponse(entity));
        }
    }

    /**
     * Records the run (config STARTED, scan DISPATCHED) inside the caller's transaction and returns
     * the command to publish once that transaction commits.
     */
    private DispatchPlan prepareDispatch(
            DiscoveryConfigEntity config,
            CredentialReferenceEntity credential,
            DiscoveryAuditRecorder.Trigger trigger) {
        Long organizationId = config.getOrganizationId();
        String targetType = config.getTargetType();
        String credentialXref = credential.getCredentialXref();

        credentialPolicy.validateProvider(credential, targetType);
        String orgType = orgTypeResolver.resolve(organizationId);
        credentialPolicy.validateAuthentication(credential);

        DiscoveryTraceIds traceIds = createDiscoveryTraceIds();

        String discoveryScopeJson = credentialPolicy.toDiscoveryScopeJson(credential);
        CertDiscoveryCommand command = CertDiscoveryCommand.builder()
                .organizationId(organizationId.toString())
                .orgType(orgType)
                .requestId(traceIds.requestId())
                .correlationId(traceIds.correlationId())
                .targetType(targetType)
                .deploymentCredHandle(blankToNull(credential.getSecretHandle()))
                .credentialScopeJson(discoveryScopeJson)
                .build();

        String scopeKey = discoveryScopeKeyFactory.create(
                organizationId, targetType, credentialXref, discoveryScopeJson);
        OffsetDateTime requestedAt = OffsetDateTime.parse(command.getRequestedAt());
        config.setCredentialXref(credentialXref);
        config.setCredentialUpdatedAt(credential.getUpdatedAt());
        config.setScopeKey(scopeKey);
        config.setLastRequestId(traceIds.requestId());
        config.setStatus(DiscoveryConfigStatus.STARTED);
        config.setStatusMessage("Discovery has started. Results will appear shortly.");
        config.setLastStartedAt(requestedAt);
        config.setLastCompletedAt(null);
        DiscoveryConfigEntity saved = discoveryConfigRepository.save(config);

        discoveryScanService.createScan(
                traceIds.requestId(), organizationId, targetType, credentialXref, scopeKey, requestedAt);
        discoveryAudit.scanStarted(saved, credential, traceIds.requestId(), trigger);
        return DispatchPlan.toPublish(command, saved.getId(), toRunResponse(saved));
    }

    /**
     * Publishes a prepared run outside any transaction; a failure is recorded in its own short one.
     * DISCOVERY is re-read past the cache just before publishing, so a switch-off that committed after
     * the run was recorded cancels it instead (a check-then-publish window of one queue send
     * remains; a scan published in it is dropped and cancelled when its results arrive).
     */
    private DiscoveryRunResponse publish(DispatchPlan plan) {
        if (plan.command() == null) {
            return plan.response();
        }
        CertDiscoveryCommand command = plan.command();
        Long organizationId = parseOrganizationIdOrNull(command.getOrganizationId());
        if (organizationId != null && !featureFlagResolver.resolveUncached(FeatureFlags.DISCOVERY, organizationId)) {
            // Switched off after the run was recorded: never send the agent a scan for a disabled feature.
            log.info("DISCOVERY was turned off for organizationId={} before requestId={} was published — cancelled",
                    organizationId, command.getRequestId());
            return inTransaction(() -> cancelUnpublishedRun(plan, organizationId));
        }
        try {
            certAgentPublisher.publishDiscoveryCommand(command);
        } catch (RuntimeException exception) {
            log.warn("Failed to publish CERT_DISCOVERY: organizationId={}, targetType={}, requestId={}, errorType={}, error={}",
                    command.getOrganizationId(), command.getTargetType(), command.getRequestId(),
                    exception.getClass().getSimpleName(), exception.getMessage());
            return inTransaction(() -> recordDispatchFailure(plan));
        }
        log.info("Triggered CERT_DISCOVERY: organizationId={}, targetType={}, requestId={}",
                command.getOrganizationId(), command.getTargetType(), command.getRequestId());
        return plan.response();
    }

    /** Cancels a recorded run whose command was never published; returns what the caller sees. */
    private DiscoveryRunResponse cancelUnpublishedRun(DispatchPlan plan, Long organizationId) {
        cancelRun(plan.command().getRequestId(), organizationId);
        return findOwnConfig(plan.command().getRequestId(), organizationId)
                .map(this::toRunResponse)
                .orElseGet(() -> plan.response().toBuilder()
                        .status(DiscoveryConfigStatus.CANCELLED.name())
                        .message(CANCELLED_MESSAGE)
                        .build());
    }

    private DiscoveryRunResponse recordDispatchFailure(DispatchPlan plan) {
        discoveryScanService.markDispatchFailed(plan.command().getRequestId());
        Optional<DiscoveryConfigEntity> config = plan.configId() == null ? Optional.empty()
                : discoveryConfigRepository.findById(plan.configId())
                        .filter(c -> plan.command().getRequestId().equals(c.getLastRequestId()));
        if (config.isEmpty()) {
            return plan.response().toBuilder()
                    .status(DiscoveryConfigStatus.FAILED.name())
                    .message("Discovery could not be started. Please try again.")
                    .build();
        }
        DiscoveryConfigEntity entity = config.get();
        entity.setStatus(DiscoveryConfigStatus.FAILED);
        entity.setStatusMessage("Discovery could not be started. Please try again.");
        discoveryConfigRepository.save(entity);
        return toRunResponse(entity);
    }

    /**
     * Fails fast on the cached flag, then takes the (organization, DISCOVERY) lock and re-reads it, so a
     * run can never start after an org admin's switch-off found no scan running. Called inside the
     * run's transaction.
     */
    private void assertDiscoveryEnabled(Long organizationId) {
        featureFlagService.assertEnabled(FeatureFlags.DISCOVERY, organizationId);
        featureLifecycleLock.lockAndAssertEnabled(organizationId, FeatureFlags.DISCOVERY);
    }

    private <T> T inTransaction(Supplier<T> work) {
        return transactionTemplate.execute(status -> work.get());
    }

    private DiscoveryTraceIds createDiscoveryTraceIds() {
        String clientCorrelationId = firstNonBlank(
                GatewayRequestContext.getCorrelationId(),
                RequestContextInterceptor.getCurrentCorrelationId());
        if (isServerMintedHttpCorrelationId(clientCorrelationId)) {
            clientCorrelationId = null;
        }

        long correlationNonce = System.nanoTime();
        String correlationId = clientCorrelationId != null
                ? clientCorrelationId
                : "corr-" + correlationNonce;
        String requestId = "req-" + UUID.randomUUID();
        return new DiscoveryTraceIds(requestId, correlationId);
    }

    private boolean isServerMintedHttpCorrelationId(String correlationId) {
        return correlationId == null
                || UNKNOWN_TRACE_ID.equals(correlationId)
                || correlationId.startsWith("corr-http-");
    }

    private String firstNonBlank(String first, String second) {
        if (first != null && !first.isBlank() && !UNKNOWN_TRACE_ID.equals(first)) {
            return first.trim();
        }
        if (second != null && !second.isBlank() && !UNKNOWN_TRACE_ID.equals(second)) {
            return second.trim();
        }
        return null;
    }

    // ------------------------------------------------------------------ //
    //  Inbound persist results
    // ------------------------------------------------------------------ //

    /**
     * Persists the agent's discovery results, taking the organization from the response body.
     *
     * @deprecated The body's {@code organizationId} is attacker-controlled and can be omitted
     * entirely, which leaves the failure path with nothing to scope by. Callers on the agent
     * message path must use {@link #persistDiscoveryResults(CertDiscoveryResponse, Long)} and pass
     * the organization that was actually authenticated.
     */
    @Deprecated
    @Transactional
    public void persistDiscoveryResults(CertDiscoveryResponse response) {
        persistDiscoveryResults(response, null);
    }

    /**
     * Persists the agent's discovery results for an organization.
     *
     * <p>For each {@link DiscoveredCertEntry} in the response:
     * <ol>
     *   <li>Upsert into {@code discovered_cert}: insert on first discovery,
     *       update metadata on re-discovery.</li>
     *   <li>Set {@code managed=true} if the cert's serial number matches a CertPing-issued
     *       certificate for the same organization.</li>
     * </ol>
     *
     * @param verifiedOrganizationId the authenticated organization, or {@code null} for callers
     *                               outside the agent message path
     */
    @Transactional
    public void persistDiscoveryResults(CertDiscoveryResponse response, Long verifiedOrganizationId) {
        validateResponseRequestId(response.getRequestId());
        // The verified organization wins over the body's claim. The body can omit organizationId
        // entirely, and the caller's body/declared-org check passes when it does — so relying on
        // the body alone let a signed message name another tenant's requestId with nothing to
        // scope the failure path by. Falling back to the body only when nothing was verified keeps
        // the non-message callers working.
        Long claimedOrganizationId = verifiedOrganizationId != null
                ? verifiedOrganizationId
                : parseOrganizationIdOrNull(response.getOrganizationId());

        if (!"SUCCESS".equalsIgnoreCase(response.getStatus())) {
            if (cancelIfDiscoveryOff(response.getRequestId(), claimedOrganizationId)) {
                return;
            }
            log.warn("CERT_DISCOVERY_RESPONSE status={} for organizationId={}, targetType={}: errorCode={}, detail={}",
                    response.getStatus(), response.getOrganizationId(),
                    response.getTargetType(), response.getErrorCode(), response.getErrorDetail());
            discoveryScanService.markAgentFailed(response.getRequestId(), claimedOrganizationId,
                    response.getErrorCode());
            markConfigFailed(response.getRequestId(), claimedOrganizationId,
                    "Discovery failed. Check the credential permissions and try again.");
            return;
        }

        List<DiscoveredCertEntry> entries = response.getDiscoveredCerts() != null
                ? response.getDiscoveredCerts()
                : List.of();

        Long organizationId = claimedOrganizationId;
        if (organizationId == null) {
            log.warn("CERT_DISCOVERY_RESPONSE has invalid organizationId='{}', dropping batch (requestId={}, targetType={})",
                    response.getOrganizationId(), response.getRequestId(), response.getTargetType());
            return;
        }
        if (cancelIfDiscoveryOff(response.getRequestId(), organizationId)
                || discoveryScanService.findStatus(response.getRequestId())
                        .filter(status -> status == DiscoveryScanStatus.CANCELLED).isPresent()) {
            log.info("Dropping discovery batch requestId={}, batchIndex={}: the scan was cancelled",
                    response.getRequestId(), response.getBatchIndex());
            return;
        }
        OffsetDateTime now  = OffsetDateTime.now(ZoneOffset.UTC);
        DiscoveryBatchContext batchContext = discoveryScanService.beginBatch(response, organizationId);
        if (batchContext.duplicate()) {
            log.info("Ignoring duplicate discovery batch requestId={}, batchIndex={}",
                    response.getRequestId(), response.getBatchIndex());
            return;
        }

        validateEntries(response.getTargetType(), entries);

        List<String> incomingResourceIds = entries.stream()
                .map(DiscoveredCertEntry::getResourceId)
                .filter(id -> id != null && !id.isBlank())
                .collect(Collectors.toList());

        // Pre-fetch existing rows and managed serials in 2 queries instead of 2×N.
        Map<String, DiscoveredCertEntity> existingByResourceId = discoveredCertRepository
                .findAllByOrganizationIdAndResourceIdIn(organizationId, incomingResourceIds)
                .stream()
                .collect(Collectors.toMap(DiscoveredCertEntity::getResourceId, Function.identity()));

        // A discovered cert is "managed" when its serial matches a CertPing-issued cert
        // for the same org. Serials are normalized on both sides so the canonical form
        // stored at issuance (upper-case hex, no separators) matches the formats cloud
        // providers report (e.g. ACM's colon-separated lower-case hex).
        Set<String> managedSerials = managedSerialToXref(organizationId, entries.stream()
                .map(entry -> normalizeSerial(entry.getSerialNumber()))
                .filter(serial -> !serial.isEmpty())
                .collect(Collectors.toSet())).keySet();

        List<DiscoveredCertEntity> toSave = new ArrayList<>(entries.size());

        for (DiscoveredCertEntry entry : entries) {
            DiscoveredCertEntity entity = discoveredCertMapper.buildOrUpdate(
                    existingByResourceId.get(entry.getResourceId()),
                    organizationId, response.getRequestId(), response.getTargetType(),
                    entry, now, managedSerials);
            toSave.add(entity);
        }

        List<DiscoveredCertEntity> saved = toSave.isEmpty()
                ? List.of()
                : discoveredCertRepository.saveAll(toSave);
        discoveryScanService.recordObservations(
                batchContext, response.getRequestId(), organizationId, response.getTargetType(), saved, now);
        discoveryScanService.completeBatch(response, entries.size());
        refreshConfigAfterBatch(response.getRequestId(), organizationId);

        log.info("CERT_DISCOVERY_RESPONSE persisted: organizationId={}, targetType={}, batch={}/{}, persisted={}",
                organizationId, response.getTargetType(),
                response.getBatchIndex() + 1, response.getTotalBatches(),
                saved.size());
    }

    // ------------------------------------------------------------------ //
    //  Read
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public Page<DiscoveredCertDto> listDiscoveredCerts(
            Long organizationId,
            Boolean managed,
            String domain,
            String targetType,
            String keyAlgorithm,
            String certStatus,
            Integer expiresWithinDays,
            Pageable pageable) {

        OffsetDateTime nowUtc = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime expiresOnOrAfter = null;
        OffsetDateTime expiresOnOrBefore = null;
        if (expiresWithinDays != null && expiresWithinDays > 0) {
            expiresOnOrAfter = nowUtc;
            expiresOnOrBefore = nowUtc.plus(expiresWithinDays, DAYS);
        }

        Page<DiscoveredCertEntity> page = discoveredCertRepository
                .findAll(DiscoveredCertSpec.filter(
                        organizationId, managed, domain, targetType, keyAlgorithm, certStatus,
                        expiresOnOrAfter, expiresOnOrBefore),
                        pageable);

        // Resolve the matching CertPing certificate xref for managed rows so the UI can
        // deep-link them. Only query when the page actually contains managed rows.
        Map<String, String> managedSerialToXref = managedSerialToXref(organizationId, page.getContent().stream()
                .filter(entity -> Boolean.TRUE.equals(entity.getManaged()))
                .map(entity -> normalizeSerial(entity.getSerialNumber()))
                .filter(serial -> !serial.isEmpty())
                .collect(Collectors.toSet()));

        // Resolve the credential that discovered each cert so the UI can show/deep-link it
        // under the source. Sourced from discovered_cert_observation.
        List<Long> certIds = page.getContent().stream()
                .map(DiscoveredCertEntity::getId)
                .collect(Collectors.toList());
        Map<Long, String> certIdToCredentialXref = buildCertIdToCredentialXref(certIds);

        return page.map(entity ->
                DiscoveredCertDto.from(
                        entity,
                        resolveManagedXref(entity, managedSerialToXref),
                        certIdToCredentialXref.get(entity.getId())));
    }

    /**
     * Maps each discovered cert id to the credential xref that most recently observed it.
     * The query returns observations most-recent-first, so the first xref seen per cert wins.
     */
    private Map<Long, String> buildCertIdToCredentialXref(List<Long> certificateIds) {
        if (certificateIds.isEmpty()) {
            return Map.of();
        }
        return discoveredCertObservationRepository
                .findCredentialXrefsByDiscoveredCertIdIn(certificateIds).stream()
                .filter(view -> view.getCredentialXref() != null && !view.getCredentialXref().isBlank())
                .collect(Collectors.toMap(
                        DiscoveredCertCredentialView::getDiscoveredCertId,
                        DiscoveredCertCredentialView::getCredentialXref,
                        (existing, ignored) -> existing));
    }

    /**
     * Normalized serial → certificateXref for the org's CertPing certs whose serial is one of
     * {@code wanted}. The org's certs are scrolled, not loaded, so memory follows {@code wanted}.
     * Duplicate serials (not expected within an org) keep the first xref.
     */
    private Map<String, String> managedSerialToXref(Long organizationId, Set<String> wanted) {
        if (wanted.isEmpty()) {
            return Map.of();
        }
        Map<String, String> found = new HashMap<>();
        try (Stream<CertificateRepository.SerialXref> rows =
                     certificateRepository.streamSerialNumberAndXrefByOrganizationId(organizationId)) {
            rows.filter(row -> row.getCertificateXref() != null && !row.getCertificateXref().isBlank())
                    .forEach(row -> {
                        String serial = normalizeSerial(row.getSerialNumber());
                        if (wanted.contains(serial)) {
                            found.putIfAbsent(serial, row.getCertificateXref());
                        }
                    });
        }
        return found;
    }

    private String resolveManagedXref(DiscoveredCertEntity entity, Map<String, String> managedSerialToXref) {
        if (!Boolean.TRUE.equals(entity.getManaged())) {
            return null;
        }
        String normalizedSerial = normalizeSerial(entity.getSerialNumber());
        return normalizedSerial.isEmpty() ? null : managedSerialToXref.get(normalizedSerial);
    }

    public DiscoveredCertDetailDto getDiscoveredCertificate(Long organizationId, Long certificateId) {
        DiscoveredCertEntity entity = discoveredCertRepository.findByIdAndOrganizationId(certificateId, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("Discovered certificate not found"));
        KubernetesDiscoveryData providerData = null;
        if (TARGET_KUBERNETES_SECRETS.equals(entity.getTargetType()) && entity.getProviderData() != null) {
            providerData = kubernetesDataValidator.validateAndConvert(entity.getProviderData());
        }
        return discoveredCertMapper.toDetailDto(entity, providerData);
    }

    /**
     * Handles the {@code CERT_DISCOVERY_COMPLETE} signal from the agent.
     * All batches for this requestId have been sent; logs completion for observability.
     * When {@code DISCOVERY} is off for the organization the scan is CANCELLED instead.
     */
    @Transactional
    public void markDiscoveryComplete(DiscoveryCompleteMessage message) {
        validateResponseRequestId(message.getRequestId());
        Long organizationId;
        try {
            organizationId = Long.parseLong(message.getOrganizationId());
        } catch (NumberFormatException | NullPointerException exception) {
            throw new IllegalArgumentException("Discovery completion organizationId must be numeric", exception);
        }
        if (cancelIfDiscoveryOff(message.getRequestId(), organizationId)) {
            return;
        }
        discoveryScanService.recordCompletion(message, organizationId);
        refreshConfigAfterCompletion(message.getRequestId(), organizationId);
        log.info("Discovery complete: requestId={}, organizationId={}, targetType={}, totalCerts={}",
                message.getRequestId(), message.getOrganizationId(),
                message.getTargetType(), message.getTotalCerts());
    }

    /**
     * @deprecated A validly signed message can name another organization's requestId. Use
     * {@link #markDiscoveryAgentFailed(String, Long, String, String)} so the scan and config
     * lookups are scoped to the caller's authenticated organization.
     */
    @Deprecated
    @Transactional
    public void markDiscoveryAgentFailed(String requestId, String errorCode, String errorDetail) {
        markDiscoveryAgentFailed(requestId, null, errorCode, errorDetail);
    }

    @Transactional
    public void markDiscoveryAgentFailed(String requestId, Long organizationId, String errorCode, String errorDetail) {
        validateResponseRequestId(requestId);
        if (cancelIfDiscoveryOff(requestId, organizationId)) {
            return;
        }
        discoveryScanService.markAgentFailed(requestId, organizationId, errorCode);
        markConfigFailed(requestId, organizationId, userFacingDiscoveryFailureMessage(errorCode, errorDetail));
        log.warn("Discovery failed from AGENT_ERROR: requestId={}, errorCode={}", requestId, errorCode);
    }

    /**
     * Feature work: when {@code DISCOVERY} is off for the organization an inbound discovery message
     * is not processed. The scan is CANCELLED (so it never stays running) and the configuration says
     * why; the caller then acknowledges the message.
     *
     * @return {@code true} when the message must be dropped
     */
    private boolean cancelIfDiscoveryOff(String requestId, Long organizationId) {
        if (organizationId == null || featureFlagService.isEnabled(FeatureFlags.DISCOVERY, organizationId)) {
            return false;
        }
        cancelRun(requestId, organizationId);
        log.info("DISCOVERY is off for organizationId={} — dropped discovery message requestId={}",
                organizationId, requestId);
        return true;
    }

    /** Marks the scan CANCELLED and, if it was still running, says why on its configuration. */
    private void cancelRun(String requestId, Long organizationId) {
        if (discoveryScanService.markCancelled(requestId, organizationId)) {
            findOwnConfig(requestId, organizationId).ifPresent(config -> {
                config.setStatus(DiscoveryConfigStatus.CANCELLED);
                config.setStatusMessage(CANCELLED_MESSAGE);
                config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
                discoveryConfigRepository.save(config);
            });
        }
    }

    /**
     * A DISPATCHED scan older than the command's time-to-live (plus grace) can no longer be
     * answered: fail it and say so on the configuration, so the configuration can run again.
     */
    private boolean expireUndeliveredRun(DiscoveryConfigEntity config) {
        OffsetDateTime dispatchedBefore = OffsetDateTime.now(ZoneOffset.UTC)
                .minus(transportProperties.getDiscoveryCommandTtl())
                .minus(UNDELIVERED_GRACE);
        if (!discoveryScanService.expireIfUndelivered(config.getLastRequestId(), dispatchedBefore)) {
            return false;
        }
        config.setStatus(DiscoveryConfigStatus.FAILED);
        config.setStatusMessage(EXPIRED_MESSAGE);
        config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
        discoveryConfigRepository.save(config);
        return true;
    }

    /** Parses an organization id, returning {@code null} rather than throwing on a bad value. */
    private static Long parseOrganizationIdOrNull(String raw) {
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException | NullPointerException e) {
            return null;
        }
    }

    private DiscoveryConfigEntity upsertDiscoveryConfig(
            Long organizationId,
            String targetType,
            CredentialReferenceEntity credential) {
        DiscoveryConfigEntity config = discoveryConfigRepository
                .findByOrganizationIdAndTargetTypeAndCredentialXrefForUpdate(
                        organizationId, targetType, credential.getCredentialXref())
                .stream()
                .findFirst()
                .orElseGet(() -> DiscoveryConfigEntity.builder()
                        .organizationId(organizationId)
                        .targetType(targetType)
                        .credentialXref(credential.getCredentialXref())
                        .build());
        config.setCredentialXref(credential.getCredentialXref());
        config.setCredentialUpdatedAt(credential.getUpdatedAt());
        config.setStatus(DiscoveryConfigStatus.READY);
        config.setStatusMessage("Discovery configuration was saved.");
        return discoveryConfigRepository.save(config);
    }

    private DiscoveryConfigEntity loadDiscoveryConfigForUpdate(Long organizationId, Long configId) {
        if (configId == null) {
            throw new BadRequestException("configId is required for discovery");
        }
        return discoveryConfigRepository.findByIdAndOrganizationIdForUpdate(configId, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("Discovery configuration not found"));
    }

    private CredentialReferenceEntity loadActiveDeploymentCredential(
            Long organizationId, String credentialXref) {
        CredentialReferenceEntity credential = credentialReferenceRepository
                .findByCredentialXref(credentialXref)
                .filter(cred -> organizationId.equals(cred.getOrganizationId()))
                .orElseThrow(() -> new BadRequestException(
                        "We could not find that discovery credential for this organization."));
        if (!isDiscoveryCapable(credential)) {
            throw new BadRequestException("Choose a discovery or deployment credential for discovery.");
        }
        if (!CREDENTIAL_STATUS_ACTIVE.equalsIgnoreCase(credential.getStatus())) {
            throw new BadRequestException("This discovery credential is not active. Choose an active credential.");
        }
        return credential;
    }

    /** Read-only DISCOVERY credentials and DEPLOYMENT credentials can both run a scan. */
    private static boolean isDiscoveryCapable(CredentialReferenceEntity credential) {
        return CREDENTIAL_TYPE_DEPLOYMENT.equalsIgnoreCase(credential.getType())
                || CREDENTIAL_TYPE_DISCOVERY.equalsIgnoreCase(credential.getType());
    }

    private CredentialReferenceEntity loadConfiguredCredential(DiscoveryConfigEntity config) {
        CredentialReferenceEntity credential = credentialReferenceRepository
                .findByCredentialXref(config.getCredentialXref())
                .filter(cred -> config.getOrganizationId().equals(cred.getOrganizationId()))
                .orElse(null);
        if (credential == null
                || !isDiscoveryCapable(credential)
                || !CREDENTIAL_STATUS_ACTIVE.equalsIgnoreCase(credential.getStatus())) {
            config.setStatus(DiscoveryConfigStatus.CREDENTIAL_INVALID);
            config.setStatusMessage("The saved discovery credential is no longer active. Choose a credential again.");
            return null;
        }
        return credential;
    }

    private void reconcileSavedConfig(
            DiscoveryConfigEntity config,
            CredentialReferenceEntity credential) {
        if (credential.getUpdatedAt() == null
                || credential.getUpdatedAt().equals(config.getCredentialUpdatedAt())) {
            return;
        }
        config.setCredentialUpdatedAt(credential.getUpdatedAt());
        config.setStatus(DiscoveryConfigStatus.READY);
        config.setStatusMessage("Discovery settings were refreshed from the latest credential configuration.");
        discoveryConfigRepository.save(config);
    }

    private DiscoveryRunResponse refreshActiveRun(DiscoveryConfigEntity config) {
        if (config.getLastRequestId() == null || config.getLastRequestId().isBlank()) {
            return null;
        }
        Optional<DiscoveryScanStatus> scanStatus = discoveryScanService.findStatus(config.getLastRequestId());
        if (scanStatus.isEmpty()) {
            return null;
        }
        if (scanStatus.get() == DiscoveryScanStatus.DISPATCHED && expireUndeliveredRun(config)) {
            return toRunResponse(config);
        }
        if (scanStatus.get() == DiscoveryScanStatus.DISPATCHED
                || scanStatus.get() == DiscoveryScanStatus.RECEIVING) {
            config.setStatus(DiscoveryConfigStatus.IN_PROGRESS);
            config.setStatusMessage("Discovery is still running. Results will appear shortly.");
            discoveryConfigRepository.save(config);
            return toRunResponse(config);
        }
        if (scanStatus.get() == DiscoveryScanStatus.CANCELLED) {
            return toRunResponse(config);
        }
        if (scanStatus.get() == DiscoveryScanStatus.FAILED) {
            config.setStatus(DiscoveryConfigStatus.FAILED);
            if (config.getStatusMessage() == null || config.getStatusMessage().isBlank()
                    || "Discovery is still running. Results will appear shortly.".equals(config.getStatusMessage())
                    || "Discovery is running. Results will appear shortly.".equals(config.getStatusMessage())
                    || "Discovery has started. Results will appear shortly.".equals(config.getStatusMessage())) {
                config.setStatusMessage("Discovery failed. Check the credential permissions and try again.");
            }
            if (config.getLastCompletedAt() == null) {
                config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
            }
            discoveryConfigRepository.save(config);
            return toRunResponse(config);
        }
        setFinished(config, scanStatus.get());
        if (config.getLastCompletedAt() == null) {
            config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
        }
        discoveryConfigRepository.save(config);
        return toRunResponse(config);
    }

    static final String COMPLETE_MESSAGE = "Discovery is complete. The certificate inventory is up to date.";
    static final String PARTIAL_MESSAGE = "Discovery finished, but some accounts, regions, vaults or namespaces "
            + "could not be read. Certificates there were left unchanged. Check the credential permissions.";

    /** COMPLETE, or PARTIAL when the scan could not read some scopes. */
    private static void setFinished(DiscoveryConfigEntity config, DiscoveryScanStatus scanStatus) {
        if (scanStatus == DiscoveryScanStatus.PARTIAL) {
            config.setStatus(DiscoveryConfigStatus.PARTIAL);
            config.setStatusMessage(PARTIAL_MESSAGE);
        } else {
            config.setStatus(DiscoveryConfigStatus.COMPLETE);
            config.setStatusMessage(COMPLETE_MESSAGE);
        }
    }

    private DiscoveryRunResponse refreshRunningRun(DiscoveryConfigEntity config) {
        if (config.getLastRequestId() == null || config.getLastRequestId().isBlank()) {
            return null;
        }
        Optional<DiscoveryScanStatus> scanStatus = discoveryScanService.findStatus(config.getLastRequestId());
        if (scanStatus.isEmpty()) {
            return null;
        }
        if (scanStatus.get() != DiscoveryScanStatus.DISPATCHED
                && scanStatus.get() != DiscoveryScanStatus.RECEIVING) {
            return null;
        }
        if (scanStatus.get() == DiscoveryScanStatus.DISPATCHED && expireUndeliveredRun(config)) {
            return null;
        }
        config.setStatus(DiscoveryConfigStatus.IN_PROGRESS);
        config.setStatusMessage("Discovery is still running. Results will appear shortly.");
        discoveryConfigRepository.save(config);
        return toRunResponse(config);
    }

    /**
     * Resolves the discovery config that this requestId belongs to. The scan-level org check
     * ({@code validateBatchIdentity} / {@code recordCompletion}) confirms the requestId belongs to
     * the caller before this runs on the success path, but this method also reaches from the
     * failure path, which has no such upstream gate — so it re-checks here rather than trusting a
     * lookup that spans a different table, correlated only by the requestId string.
     */
    private Optional<DiscoveryConfigEntity> findOwnConfig(String requestId, Long organizationId) {
        return organizationId != null
                ? discoveryConfigRepository.findByLastRequestIdAndOrganizationIdAndIsDeletedFalse(
                        requestId, organizationId)
                : discoveryConfigRepository.findByLastRequestIdAndIsDeletedFalse(requestId);
    }

    private void refreshConfigAfterBatch(String requestId, Long organizationId) {
        findOwnConfig(requestId, organizationId).ifPresent(config -> {
            Optional<DiscoveryScanStatus> scanStatus = discoveryScanService.findStatus(requestId);
            if (scanStatus.isPresent() && DiscoveryScanService.isFinished(scanStatus.get())) {
                setFinished(config, scanStatus.get());
                config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
                discoveryConfigRepository.save(config);
            } else if (config.getStatus() == DiscoveryConfigStatus.STARTED) {
                config.setStatus(DiscoveryConfigStatus.IN_PROGRESS);
                config.setStatusMessage("Discovery is running. Results will appear shortly.");
                discoveryConfigRepository.save(config);
            }
        });
    }

    private void markConfigFailed(String requestId, Long organizationId, String message) {
        findOwnConfig(requestId, organizationId).ifPresent(config -> {
            config.setStatus(DiscoveryConfigStatus.FAILED);
            config.setStatusMessage(message);
            config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
            discoveryConfigRepository.save(config);
        });
    }

    private String userFacingDiscoveryFailureMessage(String errorCode, String errorDetail) {
        String code = errorCode == null ? "" : errorCode.trim().toUpperCase(Locale.ROOT);
        String detail = errorDetail == null ? "" : errorDetail.trim();
        String namespace = extractNamespace(detail);

        String message;
        if ("DISCOVERY_K8S_SECRET_LIST_FAILED".equals(code)) {
            String scope = namespace == null ? "the selected namespace" : "namespace " + namespace;
            if (detail.contains("HTTP 403")) {
                message = "Discovery failed because Kubernetes denied access to list Secrets in "
                        + scope + ". Check the service account RBAC and try again.";
            } else {
                message = "Discovery failed while listing Kubernetes Secrets in "
                        + scope + ". Check the service account permissions and try again.";
            }
        } else if (code.startsWith("DISCOVERY_K8S_")) {
            message = "Discovery failed while reading Kubernetes resources. Check the service account permissions and try again.";
        } else if (code.startsWith("DISCOVERY_")) {
            message = "Discovery failed. Check the selected credential permissions and try again.";
        } else {
            message = "Discovery failed. Please try again.";
        }
        return message.length() <= 300 ? message : message.substring(0, 300);
    }

    private String extractNamespace(String detail) {
        String marker = "namespace=";
        int start = detail.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int valueEnd = valueStart;
        while (valueEnd < detail.length() && !Character.isWhitespace(detail.charAt(valueEnd))) {
            valueEnd++;
        }
        return valueEnd > valueStart ? detail.substring(valueStart, valueEnd) : null;
    }

    private void refreshConfigAfterCompletion(String requestId, Long organizationId) {
        findOwnConfig(requestId, organizationId).ifPresent(config -> {
            Optional<DiscoveryScanStatus> scanStatus = discoveryScanService.findStatus(requestId);
            if (scanStatus.isPresent() && DiscoveryScanService.isFinished(scanStatus.get())) {
                setFinished(config, scanStatus.get());
                config.setLastCompletedAt(OffsetDateTime.now(ZoneOffset.UTC));
                discoveryConfigRepository.save(config);
            }
        });
    }

    private DiscoveryRunResponse toRefreshedRunResponse(DiscoveryConfigEntity config) {
        DiscoveryRunResponse activeRun = refreshActiveRun(config);
        return activeRun != null ? activeRun : toRunResponse(config);
    }

    private DiscoveryRunResponse toRunResponse(DiscoveryConfigEntity config) {
        return DiscoveryRunResponse.builder()
                .configId(config.getId())
                .status(config.getStatus().name())
                .message(config.getStatusMessage())
                .requestId(config.getLastRequestId())
                .targetType(config.getTargetType())
                .credentialXref(config.getCredentialXref())
                .startedAt(config.getLastStartedAt())
                .completedAt(config.getLastCompletedAt())
                .failedScopes(lastRunFailedScopes(config))
                .build();
    }

    /** What the configuration's last run could not read; empty for none. */
    private List<com.certmanagement.messaging.model.DiscoveryFailedScope> lastRunFailedScopes(
            DiscoveryConfigEntity config) {
        if (config.getLastRequestId() == null || config.getLastRequestId().isBlank()) {
            return List.of();
        }
        List<com.certmanagement.messaging.model.DiscoveryFailedScope> scopes =
                discoveryScanService.findFailedScopes(config.getLastRequestId());
        return scopes == null ? List.of() : scopes;
    }

    private void validateEntries(String targetType, List<DiscoveredCertEntry> entries) {
        for (DiscoveredCertEntry entry : entries) {
            if (entry.getResourceId() == null || entry.getResourceId().isBlank()) {
                throw new IllegalArgumentException("Discovered certificate resourceId must not be blank");
            }
            if (TARGET_KUBERNETES_SECRETS.equals(targetType)) {
                kubernetesDataValidator.validateAndConvert(entry.getKubernetesData());
            }
        }
    }

    private void validateResponseRequestId(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("Discovery requestId must not be blank");
        }
    }

    private String requireTargetType(String targetType) {
        if (targetType == null || targetType.isBlank()) {
            throw new BadRequestException("targetType is required for discovery");
        }
        return targetType.trim().toUpperCase(Locale.ROOT);
    }

    private String requireCredentialXref(String credentialXref) {
        if (credentialXref == null || credentialXref.isBlank()) {
            throw new BadRequestException("credentialXref is required for discovery");
        }
        return credentialXref.trim();
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /**
     * Canonicalizes a certificate serial number for cross-source comparison.
     *
     * <p>Serials are reported in different textual shapes depending on the source: the
     * issuance path stores upper-case hex with no separators (e.g. {@code 1A2B3C}), while
     * AWS ACM reports colon-separated lower-case hex (e.g. {@code 1a:2b:3c}). This strips
     * everything but hex digits, upper-cases, and drops leading zeros so equal serials
     * compare equal regardless of source formatting.
     *
     * @return the canonical form, or an empty string when the input is null/blank/non-hex
     */
    static String normalizeSerial(String serial) {
        if (serial == null) return "";
        String hex = serial.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
        int firstNonZero = 0;
        while (firstNonZero < hex.length() - 1 && hex.charAt(firstNonZero) == '0') {
            firstNonZero++;
        }
        return hex.isEmpty() ? "" : hex.substring(firstNonZero);
    }

    private record DiscoveryTraceIds(String requestId, String correlationId) {}

    /**
     * The outcome of the transactional half of a trigger: either a settled response (nothing to
     * publish) or a command to publish after commit together with the response to return.
     */
    private record DispatchPlan(CertDiscoveryCommand command, Long configId, DiscoveryRunResponse response) {
        static DispatchPlan settled(DiscoveryRunResponse response) {
            return new DispatchPlan(null, null, response);
        }

        static DispatchPlan toPublish(CertDiscoveryCommand command, Long configId, DiscoveryRunResponse response) {
            return new DispatchPlan(command, configId, response);
        }
    }
}
