// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.entity.IotDeviceSourceEvent;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.certificate.IotCertificateProfileCorrelationService;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceEventRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProfileResponseHandler {
    private static final int MAX_PROFILES_PER_BATCH = 25;
    private static final int MAX_TOTAL_PROFILES = 1_000_000;
    private static final int MAX_TOTAL_BATCHES = 100_000;
    private static final int MAX_CERTIFICATE_CORRELATIONS = 50;
    private static final int SHA_256_HEX_LENGTH = 64;
    private static final String AGENT_COMMAND_FAILED = "AGENT_COMMAND_FAILED";
    private static final Pattern BEARER_TOKEN = Pattern.compile(
            "(?i)\\bbearer\\s+[A-Za-z0-9._~+/=-]+");
    private static final Pattern SENSITIVE_ERROR_ASSIGNMENT = Pattern.compile(
            "(?i)\\b(client[_-]?secret|password|access[_-]?token|refresh[_-]?token|"
                    + "authorization|credential)\\b\\s*[:=]\\s*"
                    + "(?:bearer\\s+)?[^\\s,;]+");

    private final CertificateProfileRepository profileRepository;
    private final CertificateProfileConfigurationRepository configurationRepository;
    private final CertificateProfileProviderSnapshotRepository snapshotRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceEventRepository eventRepository;
    private final IotDeviceSourceEventService eventService;
    private final IotCertificateProfileCorrelationService certificateProfileCorrelationService;
    private final CertificateProfileJsonCodec jsonCodec;
    private final IotDeviceProperties properties;
    private final Clock clock;

    @Transactional
    public void handleOperation(CertificateProfileOperationResponse response) {
        Long organizationId = parseOrganizationIdOrNull(
                response.getOrganizationId(), "operation response");
        if (organizationId == null) {
            return;
        }
        IotDeviceSource source = findSourceOrNull(
                organizationId, response.getSourceXref(), "operation response");
        if (source == null) {
            return;
        }
        CertificateProfile profile = profileRepository
                .lockByProfileXrefAndOrganizationId(response.getProfileXref(), organizationId)
                .orElse(null);
        if (profile == null || !source.getId().equals(profile.getDeviceSourceId())) {
            log.warn("Ignoring profile operation response for unknown profile: org={} source={} profile={}",
                    organizationId, response.getSourceXref(), response.getProfileXref());
            return;
        }
        if (profile.getLatestOperationXref() == null
                || !Objects.equals(profile.getLatestOperationXref(), response.getOperationXref())
                || !Objects.equals(profile.getDesiredRevision(), response.getDesiredRevision())) {
            log.info("Ignoring stale profile operation response: profile={} operation={} revision={}",
                    profile.getProfileXref(), response.getOperationXref(), response.getDesiredRevision());
            return;
        }
        if (profile.getLatestOperationCompletedAt() != null) {
            log.info("Ignoring response for terminal profile operation: profile={} operation={}",
                    profile.getProfileXref(), response.getOperationXref());
            return;
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime respondedAt;
        try {
            respondedAt = requireAgentTime(response.getRespondedAt(), "respondedAt", now);
        } catch (IllegalArgumentException exception) {
            failInvalidOperationResponse(source, profile, response,
                    "PROFILE_RESPONSE_TIMESTAMP_INVALID", exception.getMessage(), now);
            return;
        }
        if (hasNewerSnapshot(profile, respondedAt)) {
            log.info("Ignoring profile operation response older than the latest observation: "
                            + "profile={} operation={} respondedAt={}",
                    profile.getProfileXref(), response.getOperationXref(), respondedAt);
            return;
        }
        if (!"SUCCEEDED".equalsIgnoreCase(response.getStatus()) || response.getProfile() == null) {
            profile.setLatestOperationCompletedAt(now);
            profile.setProviderSyncStatus(ProviderSyncStatus.FAILED);
            profile.setProviderSyncError(safeError(response.getErrorCode(), response.getErrorMessage()));
            profileRepository.save(profile);
            eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_FAILED, "FAILED",
                    operationDetail(profile, response.getOperationXref(), response.getErrorCode()),
                    respondedAt, response.getCorrelationId(),
                    response.getOperationXref() + ":failed");
            return;
        }

        ProfileObservedState observed = response.getProfile();
        OffsetDateTime observedAt;
        try {
            requireText(observed.getProviderProfileId(), "providerProfileId");
            requireText(observed.getProviderProfileType(), "providerProfileType");
            observedAt = requireAgentTime(observed.getObservedAt(), "observedAt", now);
        } catch (IllegalArgumentException exception) {
            failInvalidOperationResponse(source, profile, response,
                    "PROFILE_RESPONSE_METADATA_INVALID", exception.getMessage(), respondedAt);
            return;
        }
        if (hasNewerSnapshot(profile, observedAt)) {
            log.info("Ignoring profile operation response older than the latest observation: "
                            + "profile={} operation={} observedAt={}",
                    profile.getProfileXref(), response.getOperationXref(), observedAt);
            return;
        }
        if (!hasExpectedProviderIdentity(profile, observed)) {
            failOperationIdentityMismatch(source, profile, response, now, respondedAt);
            return;
        }
        applyProviderIdentity(profile, observed);
        saveSnapshotIfNewer(profile, observed, observedAt);
        profile.setLatestOperationCompletedAt(now);
        profile.setLastProviderSyncedAt(observedAt);
        if (!matchesSupportedConfiguration(profile, observed)) {
            profile.setProviderSyncStatus(ProviderSyncStatus.DRIFTED);
            profile.setProviderSyncError(
                    "Authoritative provider settings differ from desired state");
            profileRepository.save(profile);
            recordDrift(source, profile, observedAt, response.getOperationXref());
            return;
        }
        profile.setAppliedRevision(response.getDesiredRevision());
        profile.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
        profile.setProviderSyncError(null);
        profileRepository.save(profile);
        eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_SUCCEEDED, "IN_SYNC",
                operationDetail(profile, response.getOperationXref(), null),
                respondedAt, response.getCorrelationId(),
                response.getOperationXref() + ":succeeded");
    }

    @Transactional
    public void handlePart(CertificateProfileSyncResponsePart part) {
        Long organizationId = parseOrganizationIdOrNull(
                part.getOrganizationId(), "profile sync part");
        if (organizationId == null) {
            return;
        }
        IotDeviceSource source = findLockedSourceOrNull(
                organizationId, part.getSourceXref(), "profile sync part");
        if (source == null) {
            return;
        }
        String requestId = parseRequestIdOrNull(part.getRequestId(), source, "profile sync part");
        if (requestId == null) {
            return;
        }
        if (!isOpenRequestedSync(source, requestId)) {
            log.info("Ignoring profile sync part without an open CMS request: source={} request={}",
                    source.getSourceXref(), requestId);
            return;
        }
        List<ProfileObservedState> profiles = part.getProfiles() == null ? List.of() : part.getProfiles();
        if (part.getBatchIndex() == null || part.getBatchIndex() < 0
                || part.getBatchIndex() >= MAX_TOTAL_BATCHES
                || !isSha256(part.getBatchChecksum())
                || profiles.isEmpty() || profiles.size() > MAX_PROFILES_PER_BATCH) {
            failProfileSync(source, requestId, "PROFILE_SYNC_PART_INVALID",
                    "Profile sync part requires a valid batch index, checksum, and profile count",
                    OffsetDateTime.now(clock));
            return;
        }
        String computedChecksum = jsonCodec.sha256(profiles);
        if (!checksumsEqual(computedChecksum, part.getBatchChecksum())) {
            failProfileSync(source, requestId, "PROFILE_SYNC_CHECKSUM_MISMATCH",
                    OffsetDateTime.now(clock));
            return;
        }
        String dedupeKey = requestId + ":part:" + part.getBatchIndex();
        var existing = eventRepository.findByDeviceSourceIdAndDedupeKey(source.getId(), dedupeKey);
        if (existing.isPresent()) {
            String storedChecksum = jsonCodec.readObject(existing.get().getDetailJson())
                    .getOrDefault("batchChecksum", "").toString();
            if (!checksumsEqual(part.getBatchChecksum(), storedChecksum)) {
                failProfileSync(source, requestId, "PROFILE_SYNC_CHECKSUM_CONFLICT",
                        OffsetDateTime.now(clock));
            }
            return;
        }

        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        OffsetDateTime respondedAt;
        try {
            respondedAt = requireOptionalAgentTime(
                    part.getRespondedAt(), "respondedAt", receivedAt);
        } catch (IllegalArgumentException exception) {
            failProfileSync(source, requestId, "PROFILE_SYNC_TIMESTAMP_INVALID",
                    exception.getMessage(), receivedAt);
            return;
        }
        int acceptedProfiles = 0;
        int rejectedProfiles = 0;
        String firstRejectionReason = null;
        for (ProfileObservedState observed : profiles) {
            if (observed == null) {
                rejectedProfiles++;
                firstRejectionReason = firstRejectionReason == null
                        ? "Profile observation is null" : firstRejectionReason;
                log.warn("Rejecting null profile observation: source={} request={}",
                        source.getSourceXref(), requestId);
                continue;
            }
            try {
                upsertObserved(source, observed, requestId, receivedAt);
                acceptedProfiles++;
            } catch (IllegalArgumentException exception) {
                rejectedProfiles++;
                String reason = boundedRejectionReason(exception.getMessage());
                firstRejectionReason = firstRejectionReason == null
                        ? reason : firstRejectionReason;
                log.warn("Rejecting malformed profile observation: source={} request={} reason={}",
                        source.getSourceXref(), requestId, reason);
            } catch (ResponseStatusException exception) {
                rejectedProfiles++;
                String reason = boundedRejectionReason(exception.getReason());
                firstRejectionReason = firstRejectionReason == null
                        ? reason : firstRejectionReason;
                log.warn("Rejecting invalid profile observation: source={} request={} reason={}",
                        source.getSourceXref(), requestId, reason);
            }
        }
        Map<String, Object> partDetail = new LinkedHashMap<>();
        partDetail.put("requestXref", requestId);
        partDetail.put("batchIndex", part.getBatchIndex());
        partDetail.put("batchChecksum", part.getBatchChecksum());
        partDetail.put("profileCount", acceptedProfiles);
        partDetail.put("sentProfileCount", profiles.size());
        if (rejectedProfiles > 0) {
            partDetail.put("rejectedProfileCount", rejectedProfiles);
        }
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED, "RECEIVED",
                partDetail, respondedAt, requestId, dedupeKey);
        if (rejectedProfiles > 0) {
            failProfileSync(source, requestId, "INVALID_PROFILE_OBSERVATION",
                    firstRejectionReason, receivedAt);
            return;
        }
        finalizeIfComplete(source, requestId, receivedAt);
    }

    @Transactional
    public void handleComplete(CertificateProfileSyncResponseComplete complete) {
        Long organizationId = parseOrganizationIdOrNull(
                complete.getOrganizationId(), "profile sync completion");
        if (organizationId == null) {
            return;
        }
        IotDeviceSource source = findLockedSourceOrNull(
                organizationId, complete.getSourceXref(), "profile sync completion");
        if (source == null) {
            return;
        }
        String requestId = parseRequestIdOrNull(
                complete.getRequestId(), source, "profile sync completion");
        if (requestId == null) {
            return;
        }
        if (!isOpenRequestedSync(source, requestId)) {
            log.info("Ignoring profile sync completion without an open CMS request: source={} request={}",
                    source.getSourceXref(), requestId);
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        int totalProfiles;
        int totalBatches;
        String status;
        List<Map<String, Object>> certificateCorrelations;
        try {
            totalProfiles = boundedNonNegative(
                    complete.getTotalProfiles(), MAX_TOTAL_PROFILES, "totalProfiles");
            totalBatches = boundedNonNegative(
                    complete.getTotalBatches(), MAX_TOTAL_BATCHES, "totalBatches");
            status = normalizeCompletionStatus(complete.getStatus());
            certificateCorrelations = validateCertificateCorrelations(
                    complete.getCertificateCorrelations());
        } catch (IllegalArgumentException exception) {
            failProfileSync(source, requestId, "PROFILE_SYNC_COMPLETION_INVALID",
                    exception.getMessage(), now);
            return;
        }
        OffsetDateTime completedAt;
        try {
            completedAt = requireAgentTime(complete.getCompletedAt(), "completedAt", now);
        } catch (IllegalArgumentException exception) {
            failProfileSync(source, requestId, "PROFILE_SYNC_TIMESTAMP_INVALID",
                    exception.getMessage(), now);
            return;
        }
        if ("SUCCEEDED".equals(status)
                && ((totalProfiles == 0) != (totalBatches == 0))) {
            failProfileSync(source, requestId, "PROFILE_SYNC_TOTALS_INVALID", completedAt);
            return;
        }
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("requestXref", requestId);
        detail.put("totalProfiles", totalProfiles);
        detail.put("totalBatches", totalBatches);
        detail.put("status", status);
        if (complete.getErrorCode() != null) {
            detail.put("errorCode", complete.getErrorCode());
        }
        if (!certificateCorrelations.isEmpty()) {
            detail.put("certificateCorrelations", certificateCorrelations);
        }
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED, status,
                detail, completedAt, requestId, requestId + ":completion");
        if ("FAILED".equals(status)) {
            eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_FAILED, "FAILED",
                    detail, completedAt, requestId, requestId + ":failed");
            return;
        }
        finalizeIfComplete(source, requestId, now);
    }

    /** Applies an agent dead-letter to the exact still-pending profile operation. */
    @Transactional
    public void handleOperationAgentError(
            String sourceXref,
            Long organizationId,
            String operationXref,
            String errorCode,
            String errorDetail,
            String respondedAt) {
        if (organizationId == null) {
            log.warn("Ignoring profile operation AGENT_ERROR without a valid organizationId");
            return;
        }
        String validatedOperationXref;
        try {
            validatedOperationXref = requireXref(operationXref, "requestId");
        } catch (IllegalArgumentException exception) {
            log.warn("Ignoring profile operation AGENT_ERROR with invalid requestId: {}",
                    exception.getMessage());
            return;
        }
        IotDeviceSource source = findSourceOrNull(
                organizationId, sourceXref, "profile operation AGENT_ERROR");
        if (source == null) {
            return;
        }
        CertificateProfile profile = profileRepository.lockByLatestOperation(
                validatedOperationXref, organizationId, source.getId()).orElse(null);
        if (profile == null) {
            log.info("Ignoring stale profile operation AGENT_ERROR: org={} source={} operation={}",
                    organizationId, sourceXref, validatedOperationXref);
            return;
        }
        if (profile.getProviderSyncStatus() != ProviderSyncStatus.PENDING
                || profile.getLatestOperationCompletedAt() != null) {
            log.info("Ignoring profile operation AGENT_ERROR for terminal operation: "
                            + "profile={} operation={} status={}",
                    profile.getProfileXref(), validatedOperationXref,
                    profile.getProviderSyncStatus());
            return;
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime occurredAt = safeAgentErrorTime(respondedAt, now);
        String safeCode = safeAgentErrorCode(errorCode);
        String safeDetail = safeAgentErrorDetail(errorDetail);
        profile.setLatestOperationCompletedAt(now);
        profile.setProviderSyncStatus(ProviderSyncStatus.FAILED);
        profile.setProviderSyncError(safeError(safeCode, safeDetail));
        profileRepository.save(profile);

        Map<String, Object> detail = operationDetail(
                profile, validatedOperationXref, safeCode);
        detail.put("errorMessage", safeDetail);
        eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_FAILED, "FAILED",
                detail, occurredAt, validatedOperationXref,
                validatedOperationXref + ":failed");
    }

    /** Closes an exact server-issued profile discovery run after the agent dead-letters its command. */
    @Transactional
    public void handleSyncAgentError(
            String sourceXref,
            Long organizationId,
            String requestXref,
            String errorCode,
            String errorDetail,
            String respondedAt) {
        if (organizationId == null) {
            log.warn("Ignoring profile sync AGENT_ERROR without a valid organizationId");
            return;
        }
        IotDeviceSource source = findLockedSourceOrNull(
                organizationId, sourceXref, "profile sync AGENT_ERROR");
        if (source == null) {
            return;
        }
        String validatedRequestXref = parseRequestIdOrNull(
                requestXref, source, "profile sync AGENT_ERROR");
        if (validatedRequestXref == null || !isOpenRequestedSync(source, validatedRequestXref)) {
            log.info("Ignoring stale profile sync AGENT_ERROR: source={} request={}",
                    source.getSourceXref(), requestXref);
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        failProfileSync(source, validatedRequestXref, safeAgentErrorCode(errorCode),
                safeAgentErrorDetail(errorDetail), safeAgentErrorTime(respondedAt, now));
    }

    private void upsertObserved(
            IotDeviceSource source,
            ProfileObservedState observed,
            String syncXref,
            OffsetDateTime receivedAt) {
        requireText(observed.getProviderProfileId(), "providerProfileId");
        requireText(observed.getProviderProfileType(), "providerProfileType");
        OffsetDateTime observedAt = requireAgentTime(
                observed.getObservedAt(), "observedAt", receivedAt);
        validateObservedConfiguration(observed);
        CertificateProfile profile = profileRepository
                .findByDeviceSourceIdAndProviderProfileTypeAndProviderProfileId(
                        source.getId(), observed.getProviderProfileType(), observed.getProviderProfileId())
                .orElseGet(() -> findByMarker(source, observed));
        boolean discovered = profile == null;
        if (discovered) {
            profile = CertificateProfile.builder()
                    .profileXref(xref("profile_"))
                    .organizationId(source.getOrganizationId())
                    .deviceSourceId(source.getId())
                    .name(trim(observed.getName(), "Unnamed provider profile", 200))
                    .description(trim(observed.getDescription(), null, 1000))
                    .targetPlatform(normalize(observed.getTargetPlatform(), "UNKNOWN"))
                    .targetVariant(normalize(observed.getTargetVariant(), "STANDARD"))
                    .providerProfileType(trim(observed.getProviderProfileType(), "UNKNOWN", 150))
                    .providerProfileId(trim(observed.getProviderProfileId(), null, 500))
                    .providerCorrelationMarker(trim(observed.getProviderCorrelationMarker(), null, 200))
                    .lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                    .profileOrigin(ProfileOrigin.PROVIDER_DISCOVERED)
                    .controlMode(ProfileControlMode.OBSERVED_ONLY)
                    .profileKind(parseKind(observed.getProfileKind()))
                    .enrollmentMethod(normalize(observed.getEnrollmentMethod(), null))
                    .providerSyncStatus(ProviderSyncStatus.IN_SYNC)
                    .lastProviderSyncedAt(observedAt)
                    .lastProviderSyncXref(syncXref)
                    .build();
            profileRepository.saveAndFlush(profile);
            configurationRepository.save(configurationFromObserved(profile, observed, receivedAt));
        } else {
            CertificateProfileProviderSnapshot current = snapshotRepository
                    .findById(profile.getId()).orElse(null);
            profile.setLastProviderSyncXref(syncXref);
            if (current != null && current.getProviderObservedAt().isAfter(observedAt)) {
                profileRepository.save(profile);
                return;
            }
            applyProviderIdentity(profile, observed);
            if (profile.getControlMode() == ProfileControlMode.OBSERVED_ONLY) {
                profile.setName(trim(observed.getName(), profile.getName(), 200));
                profile.setDescription(trim(observed.getDescription(), null, 1000));
                configurationRepository.save(configurationFromObserved(profile, observed, receivedAt));
                profile.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
            } else if (profile.getProviderSyncStatus() == ProviderSyncStatus.PENDING
                    || profile.getProviderSyncStatus() == ProviderSyncStatus.FAILED) {
                reconcilePendingObservation(source, profile, observed, observedAt, receivedAt);
            } else if (!matchesSupportedConfiguration(profile, observed)) {
                profile.setProviderSyncStatus(ProviderSyncStatus.DRIFTED);
                profile.setProviderSyncError("Supported provider settings differ from desired state");
                recordDrift(source, profile, observedAt, null);
            } else {
                profile.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
                profile.setProviderSyncError(null);
            }
            profile.setLastProviderSyncedAt(observedAt);
            profileRepository.save(profile);
        }
        saveSnapshotIfNewer(profile, observed, observedAt);
        if (discovered) {
            eventService.record(source, DeviceSourceEventType.PROFILE_DISCOVERED, "OBSERVED_ONLY",
                    Map.of("profileXref", profile.getProfileXref(),
                            "providerProfileType", profile.getProviderProfileType()),
                    observedAt, null,
                    "profile-discovered:" + profile.getProviderProfileType() + ":"
                            + profile.getProviderProfileId());
        }
    }

    private CertificateProfile findByMarker(
            IotDeviceSource source, ProfileObservedState observed) {
        if (observed.getProviderCorrelationMarker() == null
                || observed.getProviderCorrelationMarker().isBlank()) {
            return null;
        }
        CertificateProfile candidate = profileRepository
                .findByDeviceSourceIdAndProviderCorrelationMarker(
                        source.getId(), observed.getProviderCorrelationMarker())
                .orElse(null);
        if (candidate == null) {
            return null;
        }
        boolean safeCreateRecovery = candidate.getControlMode() == ProfileControlMode.CMS_MANAGED
                && candidate.getLifecycleStatus() == ProfileLifecycleStatus.ACTIVE
                && candidate.getProviderProfileId() == null
                && (candidate.getProviderSyncStatus() == ProviderSyncStatus.PENDING
                    || candidate.getProviderSyncStatus() == ProviderSyncStatus.FAILED)
                && Objects.equals(candidate.getProviderProfileType(),
                    observed.getProviderProfileType())
                && Objects.equals(candidate.getTargetPlatform(),
                    normalize(observed.getTargetPlatform(), "UNKNOWN"))
                && Objects.equals(candidate.getEnrollmentMethod(),
                    normalize(observed.getEnrollmentMethod(), null));
        if (!safeCreateRecovery) {
            throw new IllegalArgumentException(
                    "Provider correlation marker conflicts with an incompatible CMS profile");
        }
        return candidate;
    }

    private void applyProviderIdentity(CertificateProfile profile, ProfileObservedState observed) {
        profile.setProviderProfileId(trim(observed.getProviderProfileId(),
                profile.getProviderProfileId(), 500));
        profile.setProviderProfileType(trim(observed.getProviderProfileType(),
                profile.getProviderProfileType(), 150));
        if (profile.getProviderCorrelationMarker() == null) {
            profile.setProviderCorrelationMarker(trim(
                    observed.getProviderCorrelationMarker(), null, 200));
        }
    }

    private CertificateProfileConfiguration configurationFromObserved(
            CertificateProfile profile, ProfileObservedState observed, OffsetDateTime now) {
        Map<String, Object> configuration = observed.getConfiguration() == null
                ? Map.of() : observed.getConfiguration();
        return CertificateProfileConfiguration.builder()
                .profileId(profile.getId())
                .organizationId(profile.getOrganizationId())
                .deviceSourceId(profile.getDeviceSourceId())
                .issuerXref(string(configuration.get("issuerXref")))
                .certificateScope(normalize(string(configuration.get("certificateScope")), null))
                .keyAlgorithm(normalize(string(configuration.get("keyAlgorithm")), null))
                .keySize(integer(configuration.get("keySize")))
                .curve(string(configuration.get("curve")))
                .signatureHash(normalize(string(configuration.get("signatureHash")), null))
                .subjectNameFormat(string(configuration.get("subjectNameFormat")))
                .subjectAltNameFormatsJson(jsonCodec.writeSafe(
                        listValue(configuration.get("subjectAltNameFormats"))))
                .extendedKeyUsagesJson(jsonCodec.writeSafe(
                        listValue(configuration.get("extendedKeyUsages"))))
                .keyUsagesJson(jsonCodec.writeSafe(
                        listValue(configuration.get("keyUsages"))))
                .validityValue(integer(configuration.get("validityValue")))
                .validityUnit(normalize(string(configuration.get("validityUnit")), null))
                .renewalWindowDays(integer(configuration.get("renewalWindowDays")))
                .keyExportable(bool(configuration.get("keyExportable")))
                .providerConfigJson(jsonCodec.writeSafe(
                        mapValue(configuration.get("providerConfig"))))
                .updatedAt(now)
                .build();
    }

    /**
     * Validate provider-controlled JSON before mutating an existing profile or inserting a
     * discovered one. This keeps a rejected observation from leaving a partial aggregate in the
     * same transaction while valid siblings in the batch can still be committed.
     */
    private void validateObservedConfiguration(ProfileObservedState observed) {
        Map<String, Object> configuration = observed.getConfiguration() == null
                ? Map.of() : observed.getConfiguration();
        jsonCodec.writeSafe(listValue(configuration.get("subjectAltNameFormats")));
        jsonCodec.writeSafe(listValue(configuration.get("extendedKeyUsages")));
        jsonCodec.writeSafe(listValue(configuration.get("keyUsages")));
        jsonCodec.writeSafe(mapValue(configuration.get("providerConfig")));
    }

    private boolean matchesSupportedConfiguration(
            CertificateProfile profile, ProfileObservedState observed) {
        CertificateProfileConfiguration desired = configurationRepository
                .findById(profile.getId()).orElse(null);
        if (desired == null || observed.getConfiguration() == null) {
            return false;
        }
        Map<String, Object> actual = observed.getConfiguration();
        return Objects.equals(normalizedValue(observed.getName()), normalizedValue(profile.getName()))
                && matches(actual, "certificateScope", desired.getCertificateScope())
                && matches(actual, "keyAlgorithm", desired.getKeyAlgorithm())
                && matches(actual, "keySize", desired.getKeySize())
                && matches(actual, "signatureHash", desired.getSignatureHash())
                && matches(actual, "subjectNameFormat", desired.getSubjectNameFormat())
                && matchesCanonicalList(actual, "subjectAltNameFormats",
                        canonicalSans(jsonCodec.readObjectList(
                                desired.getSubjectAltNameFormatsJson())))
                && matchesCanonicalList(actual, "extendedKeyUsages",
                        canonicalExtendedKeyUsages(jsonCodec.readObjectList(
                                desired.getExtendedKeyUsagesJson())))
                && matchesCanonicalList(actual, "keyUsages",
                        canonicalKeyUsages(jsonCodec.readStringList(
                                desired.getKeyUsagesJson())))
                && matches(actual, "validityValue", desired.getValidityValue())
                && matches(actual, "validityUnit", desired.getValidityUnit())
                && matchesProviderConfig(actual, desired);
    }

    private static boolean matches(Map<String, Object> actual, String key, Object desired) {
        if (!actual.containsKey(key)) {
            return desired == null;
        }
        return Objects.equals(normalizedValue(actual.get(key)), normalizedValue(desired));
    }

    private static boolean matchesCanonicalList(
            Map<String, Object> actual, String key, Object desired) {
        if (!actual.containsKey(key)) {
            return false;
        }
        Object actualValue = switch (key) {
            case "subjectAltNameFormats" -> canonicalSans(mapList(actual.get(key)));
            case "extendedKeyUsages" -> canonicalExtendedKeyUsages(mapList(actual.get(key)));
            case "keyUsages" -> canonicalKeyUsages(stringList(actual.get(key)));
            default -> actual.get(key);
        };
        return Objects.equals(actualValue, desired);
    }

    private boolean matchesProviderConfig(
            Map<String, Object> actual, CertificateProfileConfiguration desired) {
        Map<String, Object> observed = mapValue(actual.get("providerConfig"));
        Map<String, Object> configured = jsonCodec.readObject(desired.getProviderConfigJson());
        return matches(observed, "renewalThresholdPercentage",
                configured.get("renewalThresholdPercentage"))
                && matches(observed, "keyStorageProvider",
                configured.get("keyStorageProvider"));
    }

    private void saveSnapshotIfNewer(
            CertificateProfile profile, ProfileObservedState observed, OffsetDateTime observedAt) {
        CertificateProfileProviderSnapshot snapshot = snapshotRepository
                .findById(profile.getId()).orElse(null);
        if (snapshot != null && snapshot.getProviderObservedAt().isAfter(observedAt)) {
            return;
        }
        if (snapshot == null) {
            snapshot = new CertificateProfileProviderSnapshot();
            snapshot.setProfileId(profile.getId());
            snapshot.setOrganizationId(profile.getOrganizationId());
            snapshot.setDeviceSourceId(profile.getDeviceSourceId());
        }
        snapshot.setProviderResponseJson(
                jsonCodec.writeProviderSnapshot(observed.getProviderResponse()));
        snapshot.setResponseSchemaVersion(1);
        snapshot.setProviderVersion(trim(observed.getProviderVersion(), null, 100));
        snapshot.setProviderLastModifiedAt(parseNullableTime(observed.getProviderLastModifiedAt()));
        snapshot.setProviderObservedAt(observedAt);
        snapshot.setUpdatedAt(OffsetDateTime.now(clock));
        snapshotRepository.save(snapshot);
    }

    private boolean hasNewerSnapshot(
            CertificateProfile profile, OffsetDateTime responseObservedAt) {
        return snapshotRepository.findById(profile.getId())
                .map(snapshot -> snapshot.getProviderObservedAt().isAfter(responseObservedAt))
                .orElse(false);
    }

    private static boolean hasExpectedProviderIdentity(
            CertificateProfile profile, ProfileObservedState observed) {
        boolean nativeIdMatches = profile.getProviderProfileId() == null
                || Objects.equals(profile.getProviderProfileId(), observed.getProviderProfileId());
        boolean markerMatches = profile.getProviderCorrelationMarker() == null
                || Objects.equals(profile.getProviderCorrelationMarker(),
                    observed.getProviderCorrelationMarker());
        return nativeIdMatches && markerMatches
                && Objects.equals(profile.getProviderProfileType(), observed.getProviderProfileType());
    }

    private void failOperationIdentityMismatch(
            IotDeviceSource source,
            CertificateProfile profile,
            CertificateProfileOperationResponse response,
            OffsetDateTime completedAt,
            OffsetDateTime respondedAt) {
        profile.setLatestOperationCompletedAt(completedAt);
        profile.setProviderSyncStatus(ProviderSyncStatus.FAILED);
        profile.setProviderSyncError("Provider response identity did not match the requested profile");
        profileRepository.save(profile);
        eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_FAILED, "FAILED",
                operationDetail(profile, response.getOperationXref(),
                        "PROFILE_RESPONSE_IDENTITY_MISMATCH"),
                respondedAt, response.getCorrelationId(),
                response.getOperationXref() + ":failed");
    }

    private void failInvalidOperationResponse(
            IotDeviceSource source,
            CertificateProfile profile,
            CertificateProfileOperationResponse response,
            String errorCode,
            String errorMessage,
            OffsetDateTime occurredAt) {
        OffsetDateTime completedAt = OffsetDateTime.now(clock);
        profile.setLatestOperationCompletedAt(completedAt);
        profile.setProviderSyncStatus(ProviderSyncStatus.FAILED);
        profile.setProviderSyncError(safeError(errorCode, errorMessage));
        profileRepository.save(profile);
        Map<String, Object> detail = operationDetail(
                profile, response.getOperationXref(), errorCode);
        if (errorMessage != null && !errorMessage.isBlank()) {
            detail.put("errorMessage", trim(errorMessage, null, 500));
        }
        eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_FAILED, "FAILED",
                detail, occurredAt, response.getCorrelationId(),
                response.getOperationXref() + ":failed");
    }

    private void reconcilePendingObservation(
            IotDeviceSource source,
            CertificateProfile profile,
            ProfileObservedState observed,
            OffsetDateTime observedAt,
            OffsetDateTime receivedAt) {
        if (matchesSupportedConfiguration(profile, observed)) {
            profile.setAppliedRevision(profile.getDesiredRevision());
            profile.setProviderSyncStatus(ProviderSyncStatus.IN_SYNC);
            profile.setProviderSyncError(null);
            profile.setLatestOperationCompletedAt(receivedAt);
            String operationXref = Objects.toString(
                    profile.getLatestOperationXref(), profile.getProfileXref());
            eventService.record(source, DeviceSourceEventType.PROFILE_APPLY_SUCCEEDED, "IN_SYNC",
                    operationDetail(profile, operationXref, null), observedAt,
                    operationXref, operationXref + ":succeeded");
            return;
        }
        OffsetDateTime operationStartedAt = profile.getLatestOperationStartedAt();
        boolean stale = operationStartedAt == null
                || !receivedAt.isBefore(operationStartedAt.plus(
                    properties.getProfileResponseTimeout()));
        if (stale) {
            profile.setLatestOperationCompletedAt(receivedAt);
            profile.setProviderSyncStatus(ProviderSyncStatus.DRIFTED);
            profile.setProviderSyncError(
                    "Provider settings still differ after the profile response timeout");
            recordDrift(source, profile, observedAt, profile.getLatestOperationXref());
        }
    }

    private void recordDrift(
            IotDeviceSource source,
            CertificateProfile profile,
            OffsetDateTime observedAt,
            String correlationId) {
        eventService.record(source, DeviceSourceEventType.PROFILE_DRIFTED, "DRIFTED",
                Map.of("profileXref", profile.getProfileXref(),
                        "providerProfileType", profile.getProviderProfileType()),
                observedAt, correlationId,
                "profile-drifted:" + profile.getProfileXref() + ":"
                        + Objects.toString(profile.getDesiredRevision(), "observed"));
    }

    private void finalizeIfComplete(
            IotDeviceSource source, String requestXref, OffsetDateTime occurredAt) {
        List<IotDeviceSourceEvent> completionEvents = eventRepository
                .findByDeviceSourceIdAndCorrelationIdAndEventType(
                        source.getId(), requestXref,
                        DeviceSourceEventType.PROFILE_SYNC_COMPLETION_RECEIVED);
        if (completionEvents.isEmpty()) {
            return;
        }
        Map<String, Object> completion = jsonCodec.readObject(
                completionEvents.getFirst().getDetailJson());
        if (!"SUCCEEDED".equals(completion.get("status"))) {
            return;
        }
        int expectedBatches = integer(completion.get("totalBatches"), -1);
        int expectedProfiles = integer(completion.get("totalProfiles"), -1);
        List<IotDeviceSourceEvent> partEvents = eventRepository
                .findByDeviceSourceIdAndCorrelationIdAndEventType(
                        source.getId(), requestXref,
                        DeviceSourceEventType.PROFILE_SYNC_PART_RECEIVED);
        Set<Integer> receivedIndices = new HashSet<>();
        int receivedProfiles = 0;
        for (IotDeviceSourceEvent event : partEvents) {
            Map<String, Object> detail = jsonCodec.readObject(event.getDetailJson());
            Integer index = integer(detail.get("batchIndex"));
            if (index != null) {
                receivedIndices.add(index);
            }
            receivedProfiles += integer(detail.get("profileCount"), 0);
        }
        boolean completeIndexSet = expectedBatches >= 0
                && receivedIndices.size() == expectedBatches
                && receivedIndices.stream().allMatch(index -> index >= 0 && index < expectedBatches);
        if (!completeIndexSet) {
            return;
        }
        if (expectedProfiles < 0 || receivedProfiles != expectedProfiles) {
            failProfileSync(source, requestXref, "PROFILE_SYNC_COUNT_MISMATCH", occurredAt);
            return;
        }
        int missingProfiles = profileRepository.markMissingFromCompletedSync(
                source.getId(), requestXref,
                "Profile was not returned by the latest Intune sync", occurredAt);
        certificateProfileCorrelationService.reconcile(
                source, requestXref,
                readCertificateCorrelations(completion.get("certificateCorrelations")), occurredAt);
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_COMPLETED, "SUCCEEDED",
                Map.of("requestXref", requestXref,
                        "totalProfiles", expectedProfiles,
                        "totalBatches", expectedBatches,
                        "missingProfileCount", missingProfiles),
                occurredAt, requestXref, requestXref + ":completed");
        log.info("Certificate-profile sync completed: source={} request={} profiles={} batches={} "
                        + "markedMissing={}",
                source.getSourceXref(), requestXref, expectedProfiles, expectedBatches,
                missingProfiles);
    }

    private static List<Map<String, Object>> validateCertificateCorrelations(
            List<CertificateCorrelationResult> results) {
        if (results == null || results.isEmpty()) {
            return List.of();
        }
        if (results.size() > MAX_CERTIFICATE_CORRELATIONS) {
            throw new IllegalArgumentException("certificateCorrelations exceeds the limit");
        }
        Set<String> certificateXrefs = new HashSet<>();
        List<Map<String, Object>> validated = new ArrayList<>(results.size());
        for (CertificateCorrelationResult result : results) {
            if (result == null) {
                throw new IllegalArgumentException("certificate correlation is null");
            }
            String certificateXref = requirePattern(
                    result.certificateXref(), "certificateXref", "[A-Za-z0-9_-]{1,100}");
            if (!certificateXrefs.add(certificateXref)) {
                throw new IllegalArgumentException("certificate correlation xrefs must be unique");
            }
            String status = result.status() == null
                    ? null : result.status().trim().toUpperCase(Locale.ROOT);
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("certificateXref", certificateXref);
            value.put("status", status);
            if ("MATCHED".equals(status)) {
                value.put("providerProfileId", requirePattern(result.providerProfileId(),
                        "providerProfileId", "[A-Za-z0-9-]{1,100}"));
                value.put("providerProfileType", requireTextBounded(
                        result.providerProfileType(), "providerProfileType", 150));
                String method = result.matchMethod() == null
                        ? null : result.matchMethod().trim().toUpperCase(Locale.ROOT);
                if (!"SHA1".equals(method) && !"ISSUER_SERIAL".equals(method)) {
                    throw new IllegalArgumentException("matchMethod is invalid");
                }
                value.put("matchMethod", method);
            } else if (!"NOT_FOUND".equals(status) && !"AMBIGUOUS".equals(status)) {
                throw new IllegalArgumentException("certificate correlation status is invalid");
            }
            validated.add(Map.copyOf(value));
        }
        return List.copyOf(validated);
    }

    private static List<CertificateCorrelationResult> readCertificateCorrelations(Object raw) {
        if (!(raw instanceof List<?> values)) {
            return List.of();
        }
        List<CertificateCorrelationResult> results = new ArrayList<>(values.size());
        for (Object value : values) {
            if (value instanceof Map<?, ?> map) {
                results.add(new CertificateCorrelationResult(
                        string(map.get("certificateXref")), string(map.get("status")),
                        string(map.get("providerProfileId")), string(map.get("providerProfileType")),
                        string(map.get("matchMethod"))));
            }
        }
        return List.copyOf(results);
    }

    private static String requirePattern(String value, String name, String pattern) {
        String validated = requireTextBounded(value, name, 500);
        if (!validated.matches(pattern)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return validated;
    }

    private static String requireTextBounded(String value, String name, int maxLength) {
        if (value == null || value.isBlank() || value.length() > maxLength) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value.trim();
    }

    private boolean isOpenRequestedSync(IotDeviceSource source, String requestXref) {
        boolean requested = eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                source.getId(), requestXref, DeviceSourceEventType.PROFILE_SYNC_REQUESTED);
        if (!requested) {
            return false;
        }
        return !eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                source.getId(), requestXref, DeviceSourceEventType.PROFILE_SYNC_COMPLETED)
                && !eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                source.getId(), requestXref, DeviceSourceEventType.PROFILE_SYNC_FAILED);
    }

    private void failProfileSync(
            IotDeviceSource source,
            String requestXref,
            String errorCode,
            OffsetDateTime occurredAt) {
        failProfileSync(source, requestXref, errorCode, null, occurredAt);
    }

    private void failProfileSync(
            IotDeviceSource source,
            String requestXref,
            String errorCode,
            String errorMessage,
            OffsetDateTime occurredAt) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("requestXref", requestXref);
        detail.put("errorCode", errorCode);
        if (errorMessage != null && !errorMessage.isBlank()) {
            detail.put("errorMessage", trim(errorMessage, null, 500));
        }
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_FAILED, "FAILED",
                detail,
                occurredAt, requestXref, requestXref + ":failed");
    }

    private IotDeviceSource findSourceOrNull(
            Long organizationId, String sourceXref, String responseType) {
        IotDeviceSource source = sourceRepository
                .findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElse(null);
        if (source == null) {
            log.warn("Ignoring {} for unknown source: org={} source={}",
                    responseType, organizationId, sourceXref);
        }
        return source;
    }

    private IotDeviceSource findLockedSourceOrNull(
            Long organizationId, String sourceXref, String responseType) {
        IotDeviceSource source = sourceRepository
                .lockBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElse(null);
        if (source == null) {
            log.warn("Ignoring {} for unknown source: org={} source={}",
                    responseType, organizationId, sourceXref);
        }
        return source;
    }

    private static Map<String, Object> operationDetail(
            CertificateProfile profile, String operationXref, String errorCode) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("profileXref", profile.getProfileXref());
        detail.put("operationXref", operationXref);
        detail.put("desiredRevision", profile.getDesiredRevision());
        if (errorCode != null) {
            detail.put("errorCode", errorCode);
        }
        return detail;
    }

    private static ProfileKind parseKind(String value) {
        try {
            return value == null ? ProfileKind.CERTIFICATE_ENROLLMENT
                    : ProfileKind.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return ProfileKind.CERTIFICATE_ENROLLMENT;
        }
    }

    private static Long parseOrganizationIdOrNull(String value, String responseType) {
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException | NullPointerException exception) {
            log.warn("Ignoring {} with invalid organizationId", responseType);
            return null;
        }
    }

    private static String parseRequestIdOrNull(
            String value, IotDeviceSource source, String responseType) {
        try {
            return requireXref(value, "requestId");
        } catch (IllegalArgumentException exception) {
            log.warn("Ignoring {} with invalid requestId: source={} reason={}",
                    responseType, source.getSourceXref(), exception.getMessage());
            return null;
        }
    }

    private static int boundedNonNegative(Integer value, int maximum, String field) {
        if (value == null || value < 0 || value > maximum) {
            throw new IllegalArgumentException(
                    field + " must be between 0 and " + maximum);
        }
        return value;
    }

    private static String requireXref(String value, String field) {
        requireText(value, field);
        String normalized = value.trim();
        if (normalized.length() > 100
                || !normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
        return normalized;
    }

    private static boolean isSha256(String value) {
        return value != null && value.length() == SHA_256_HEX_LENGTH
                && value.matches("[0-9A-Fa-f]{64}");
    }

    private static boolean checksumsEqual(String first, String second) {
        if (!isSha256(first) || !isSha256(second)) {
            return false;
        }
        return MessageDigest.isEqual(
                first.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII),
                second.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }

    private static String normalizeCompletionStatus(String value) {
        String normalized = normalize(value, null);
        if (!Set.of("SUCCEEDED", "FAILED").contains(normalized)) {
            throw new IllegalArgumentException(
                    "status must be SUCCEEDED or FAILED");
        }
        return normalized;
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    private static String safeError(String code, String detail) {
        String value = (code == null ? "PROFILE_OPERATION_FAILED" : code)
                + (detail == null || detail.isBlank() ? "" : ": " + detail);
        return trim(value, "PROFILE_OPERATION_FAILED", 1000);
    }

    private static String safeAgentErrorCode(String value) {
        if (value == null || value.isBlank()) {
            return AGENT_COMMAND_FAILED;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return normalized.matches("[A-Z0-9][A-Z0-9_.:-]{0,99}")
                ? normalized : AGENT_COMMAND_FAILED;
    }

    private static String safeAgentErrorDetail(String value) {
        String normalized = value == null || value.isBlank()
                ? "Agent dead-lettered the command"
                : value.replaceAll("\\s+", " ").trim();
        normalized = SENSITIVE_ERROR_ASSIGNMENT.matcher(normalized)
                .replaceAll("$1=[REDACTED]");
        normalized = BEARER_TOKEN.matcher(normalized)
                .replaceAll("Bearer [REDACTED]");
        return trim(normalized, "Agent dead-lettered the command", 500);
    }

    private OffsetDateTime safeAgentErrorTime(String value, OffsetDateTime receivedAt) {
        try {
            return requireAgentTime(value, "respondedAt", receivedAt);
        } catch (IllegalArgumentException exception) {
            log.warn("Using CMS receive time for AGENT_ERROR with invalid respondedAt: {}",
                    exception.getMessage());
            return receivedAt;
        }
    }

    private static String boundedRejectionReason(String reason) {
        return trim(reason, "Profile observation is invalid", 500);
    }

    private static OffsetDateTime parseNullableTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException exception) {
            return null;
        }
    }

    private OffsetDateTime requireAgentTime(
            String value, String field, OffsetDateTime receivedAt) {
        OffsetDateTime parsed = parseNullableTime(value);
        if (parsed == null) {
            throw new IllegalArgumentException(field + " must be an ISO-8601 timestamp");
        }
        if (parsed.isAfter(receivedAt.plus(properties.getMaxAgentClockSkew()))) {
            throw new IllegalArgumentException(
                    field + " exceeds the allowed agent clock skew");
        }
        return parsed;
    }

    private OffsetDateTime requireOptionalAgentTime(
            String value, String field, OffsetDateTime receivedAt) {
        return value == null || value.isBlank()
                ? receivedAt : requireAgentTime(value, field, receivedAt);
    }

    private static String normalize(String value, String fallback) {
        return value == null || value.isBlank()
                ? fallback : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String trim(String value, String fallback, int maxLength) {
        String result = value == null || value.isBlank() ? fallback : value.trim();
        return result == null || result.length() <= maxLength
                ? result : result.substring(0, maxLength);
    }

    private static String string(Object value) {
        return value == null ? null : value.toString();
    }

    private static Integer integer(Object value) {
        return integer(value, null);
    }

    private static Integer integer(Object value, Integer fallback) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return value == null ? fallback : Integer.valueOf(value.toString());
        } catch (NumberFormatException exception) {
            return fallback;
        }
    }

    private static Boolean bool(Object value) {
        return value instanceof Boolean bool ? bool
                : value == null ? null : Boolean.valueOf(value.toString());
    }

    private static Object listValue(Object value) {
        return value instanceof List<?> ? value : List.of();
    }

    private static Map<String, Object> mapValue(Object value) {
        if (!(value instanceof Map<?, ?> raw)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        raw.forEach((key, nested) -> {
            if (key != null) {
                result.put(key.toString(), nested);
            }
        });
        return result;
    }

    private static Object normalizedValue(Object value) {
        if (value instanceof Number number) {
            return new java.math.BigDecimal(number.toString()).stripTrailingZeros();
        }
        return value == null ? null : value.toString().trim().toUpperCase(Locale.ROOT);
    }

    private static List<Map<String, Object>> canonicalSans(List<Map<String, Object>> values) {
        return values.stream().map(value -> Map.<String, Object>of(
                        "type", normalizeSanType(Objects.toString(value.get("type"), "")),
                        "format", Objects.toString(value.get("format"), "").trim()))
                .sorted(Comparator.comparing(
                                (Map<String, Object> value) -> value.get("type").toString())
                        .thenComparing(value -> value.get("format").toString()))
                .toList();
    }

    private static List<Map<String, Object>> canonicalExtendedKeyUsages(
            List<Map<String, Object>> values) {
        List<Map<String, Object>> canonical = new ArrayList<>();
        for (Map<String, Object> value : values) {
            Map<String, Object> usage = new LinkedHashMap<>();
            usage.put("objectIdentifier",
                    Objects.toString(value.get("objectIdentifier"), "").trim());
            if (value.get("name") != null) {
                usage.put("name", value.get("name").toString().trim());
            }
            canonical.add(usage);
        }
        canonical.sort(Comparator.comparing(
                        (Map<String, Object> value) -> value.get("objectIdentifier").toString())
                .thenComparing(value -> Objects.toString(value.get("name"), ""),
                        String.CASE_INSENSITIVE_ORDER));
        return List.copyOf(canonical);
    }

    private static List<String> canonicalKeyUsages(List<String> values) {
        return values.stream()
                .map(value -> value == null ? "" : value.trim().toUpperCase(Locale.ROOT))
                .sorted()
                .toList();
    }

    private static List<Map<String, Object>> mapList(Object value) {
        if (!(value instanceof List<?> values)) {
            return List.of();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : values) {
            if (item instanceof Map<?, ?>) {
                result.add(mapValue(item));
            }
        }
        return result;
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> values)) {
            return List.of();
        }
        return values.stream().map(Objects::toString).toList();
    }

    private static String normalizeSanType(String value) {
        return switch (value.trim().toUpperCase(Locale.ROOT)) {
            case "EMAIL", "EMAIL_ADDRESS", "EMAILADDRESS" -> "EMAIL";
            case "UPN", "USER_PRINCIPAL_NAME", "USERPRINCIPALNAME" -> "UPN";
            case "DNS", "DNS_NAME", "DNSNAME", "DOMAINNAMESERVICE" -> "DNS";
            case "URI", "UNIFORM_RESOURCE_IDENTIFIER", "UNIFORMRESOURCEIDENTIFIER",
                    "UNIVERSALRESOURCEIDENTIFIER" -> "URI";
            default -> value.trim().toUpperCase(Locale.ROOT);
        };
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }
}
