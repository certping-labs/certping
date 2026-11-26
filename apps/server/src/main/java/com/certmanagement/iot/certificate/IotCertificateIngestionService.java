// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.profile.CertificateProfile;
import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileConfigurationRepository;
import com.certmanagement.iot.profile.CertificateProfileRepository;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Source-first ingestion of agent SCEP telemetry. The device source resolved from
 * {@code connectionProfileRef} is the routing identity; a certificate profile is an optional,
 * later-reconciled link, so an issued certificate is never dropped just because its Intune
 * profile (or device) has not been synchronized yet.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateIngestionService {
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SHA1 = Pattern.compile("[0-9a-f]{40}");

    static final String PROFILE_MATCHED = "MATCHED";
    static final String PROFILE_PENDING_SYNC = "PENDING_SYNC";
    static final String PROFILE_AMBIGUOUS = "AMBIGUOUS";

    private final OrganizationRepository organizationRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final CertificateProfileRepository profileRepository;
    private final CertificateProfileConfigurationRepository configurationRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceRepository deviceRepository;
    private final IotCertificateSupersessionService supersessionService;
    private final IotDeviceEventService eventService;
    private final IotCertificateDeviceLinkService deviceLinkService;
    private final IotAlertPublisher alertPublisher;
    private final FeatureFlagService featureFlagService;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final IotAuditRecorder iotAudit;

    /** Invalid or cross-tenant metadata is acknowledged and dropped; database failures still retry. */
    @Transactional
    public void handle(ScepCertificateIssuedMessage message) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null)) {
            return;
        }
        try {
            ingest(message);
        } catch (IllegalArgumentException exception) {
            // Invalid messages are acknowledged and dropped, but they must never leave behind a
            // partially-created enrollment if validation failed after a repository write.
            rollbackOnly();
            log.warn("Dropping invalid SCEP_CERT_ISSUED metadata: {}", exception.getMessage());
        }
    }

    /** Audit that an enrollment was received (pre-validation). Creates the enrollment shell if absent. */
    @Transactional
    public void handleRequested(ScepCertRequestedMessage message) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null)) {
            return;
        }
        try {
            ingestRequested(message);
        } catch (IllegalArgumentException exception) {
            rollbackOnly();
            log.warn("Dropping invalid SCEP_CERT_REQUESTED metadata: {}", exception.getMessage());
        }
    }

    /** Record a terminal REJECTED/FAILED outcome. Creates the enrollment shell if the result arrives first. */
    @Transactional
    public void handleResult(ScepCertResultMessage message) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null)) {
            return;
        }
        try {
            ingestResult(message);
        } catch (IllegalArgumentException exception) {
            rollbackOnly();
            log.warn("Dropping invalid SCEP_CERT_RESULT metadata: {}", exception.getMessage());
        }
    }

    private void ingestRequested(ScepCertRequestedMessage message) {
        if (message == null || !Integer.valueOf(2).equals(message.getMessageVersion())) {
            throw new IllegalArgumentException("unsupported messageVersion");
        }
        Long organizationId = positiveLong(message.getOrganizationId(), "organizationId");
        if (organizationUnavailable(organizationId, "SCEP_CERT_REQUESTED")) {
            return;
        }
        IotDeviceSource source = resolveSource(organizationId,
                message.getConnectionProfileRef(), message.getEndpointId(), null);
        String transactionId = required(message.getIntuneTransactionId(), 255, "intuneTransactionId");
        String csrFingerprint = optionalSha256(message.getCsrFingerprintSha256(), "csrFingerprintSha256");
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        OffsetDateTime requestedAt = timestamp(message.getRequestedAt(), "requestedAt");

        enrollmentRepository.lockTransaction(source.getId(), transactionId);
        IotCertificateEnrollment enrollment = findOrCreateShell(
                source, organizationId, transactionId, csrFingerprint,
                "RECEIVED", requestedAt, receivedAt, false);
        eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_REQUESTED, "RECEIVED",
                "Enrollment request received", Map.of(), message.getCorrelationId(),
                "scep-requested:" + enrollment.getEnrollmentXref(), requestedAt);
    }

    private void ingestResult(ScepCertResultMessage message) {
        if (message == null || !Integer.valueOf(2).equals(message.getMessageVersion())) {
            throw new IllegalArgumentException("unsupported messageVersion");
        }
        String status = required(message.getStatus(), 40, "status").toUpperCase(Locale.ROOT);
        if (!"REJECTED".equals(status) && !"FAILED".equals(status)) {
            throw new IllegalArgumentException("status must be REJECTED or FAILED");
        }
        Long organizationId = positiveLong(message.getOrganizationId(), "organizationId");
        if (organizationUnavailable(organizationId, "SCEP_CERT_RESULT")) {
            return;
        }
        String profileRef = trimToNull(firstNonBlank(message.getConnectionProfileRef(), message.getEndpointId()));
        Optional<IotDeviceSource> registered = profileRef == null ? Optional.empty()
                : sourceRepository.findByOrganizationIdAndConnectionProfileRef(organizationId, profileRef);
        if (registered.isEmpty()) {
            // No enrollment can be kept without a source, but the outcome still belongs in the organization's trail.
            log.warn("SCEP enrollment ended without a certificate for an unregistered connection profile: "
                            + "organizationId={} profile={} status={} errorCode={}",
                    organizationId, profileRef, status, message.getErrorCode());
            iotAudit.enrollmentFailed(organizationId, null, truncate(profileRef, 100), null, message.getStage(),
                    message.isRetryable(), message.getErrorCode());
            return;
        }
        IotDeviceSource source = registered.get();
        String transactionId = required(message.getIntuneTransactionId(), 255, "intuneTransactionId");
        String csrFingerprint = optionalSha256(message.getCsrFingerprintSha256(), "csrFingerprintSha256");
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        OffsetDateTime occurredAt = timestamp(message.getOccurredAt(), "occurredAt");

        enrollmentRepository.lockTransaction(source.getId(), transactionId);
        IotCertificateEnrollment enrollment = findOrCreateShell(
                source, organizationId, transactionId, csrFingerprint,
                status, occurredAt, receivedAt, message.isRetryable());
        // A late failure must never overwrite a certificate that was already issued for this transaction.
        if (!"ISSUED".equals(enrollment.getStatus())) {
            enrollment.setStatus(status);
            enrollment.setFailureStage(truncate(message.getStage(), 50));
            enrollment.setErrorCode(truncate(message.getErrorCode(), 100));
            enrollment.setErrorMessage(truncate(message.getErrorMessage(), 1000));
            enrollment.setRetryable(message.isRetryable());
            enrollment.setCompletedAt(occurredAt);
            enrollment.setUpdatedAt(receivedAt);
            enrollmentRepository.save(enrollment);
        }
        DeviceEventType eventType = "REJECTED".equals(status)
                ? DeviceEventType.CHALLENGE_REJECTED : DeviceEventType.CERTIFICATE_ENROLLMENT_FAILED;
        eventService.recordEnrollment(enrollment, eventType, status, truncate(message.getErrorMessage(), 1000),
                Map.of("stage", firstNonBlank(message.getStage(), "")), message.getCorrelationId(),
                "scep-result:" + status + ":" + enrollment.getEnrollmentXref(), occurredAt);
        // A terminal enrollment failure left no trace in the logs at all. errorMessage is
        // agent-supplied text that can echo CSR subject content, so it stays in the event row.
        log.info("SCEP enrollment ended without a certificate: source={} txn={} enrollment={} "
                        + "status={} stage={} errorCode={} retryable={}",
                source.getSourceXref(), transactionId, enrollment.getEnrollmentXref(), status,
                message.getStage(), message.getErrorCode(), message.isRetryable());
        iotAudit.enrollmentFailed(organizationId, source, null, enrollment.getEnrollmentXref(), message.getStage(),
                message.isRetryable(), message.getErrorCode());
        alertIssuanceDependencyDown(organizationId, source, message);
    }

    /**
     * A CA or Intune that cannot answer blocks enrollment for every device behind the connection, so
     * it is reported immediately rather than waiting for the digest. A per-device rejection
     * (CHALLENGE_REJECTED) is deliberately excluded: it is one device's problem, not the platform's.
     * The hour bucket collapses the resulting storm into one alert per connection per hour.
     */
    private void alertIssuanceDependencyDown(Long organizationId, IotDeviceSource source,
                                             ScepCertResultMessage message) {
        String scenario = switch (firstNonBlank(message.getErrorCode(), "")) {
            case "CA_UNAVAILABLE" -> "CA_UNREACHABLE";
            case "CA_REJECTED" -> "CA_REJECTING_ISSUANCE";
            case "INTUNE_UNAVAILABLE" -> "INTUNE_UNREACHABLE";
            default -> null;
        };
        if (scenario == null) {
            return;
        }
        boolean ca = scenario.startsWith("CA_");
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("sourceXref", source.getSourceXref());
        facts.put("stage", message.getStage());
        facts.put("errorCode", message.getErrorCode());
        facts.put("errorMessage", truncate(message.getErrorMessage(), 500));
        facts.put("retryable", message.isRetryable());
        alertPublisher.critical(organizationId, scenario,
                ca ? "Certificate authority is not issuing device certificates"
                        : "Intune is not validating device enrollments",
                ca ? "Device enrollments are failing at CA signing, so no device behind this "
                        + "connection can obtain or renew a certificate until the CA recovers."
                   : "Device enrollments are failing at Intune challenge validation, so no device "
                        + "behind this connection can obtain or renew a certificate until Intune "
                        + "responds again.",
                source.getSourceXref() + ":" + IotAlertPublisher.hourBucket(), null, facts);
    }

    private void ingest(ScepCertificateIssuedMessage message) {
        // Pre-release: the agent and the server ship together, so exactly one version is
        // accepted per message type — no compatibility window.
        if (message == null || !Integer.valueOf(3).equals(message.getMessageVersion())) {
            throw new IllegalArgumentException("unsupported messageVersion");
        }
        if (!"ISSUED".equals(required(message.getStatus(), 40, "status").toUpperCase(Locale.ROOT))) {
            throw new IllegalArgumentException("status must be ISSUED");
        }
        Long organizationId = positiveLong(message.getOrganizationId(), "organizationId");
        if (organizationUnavailable(organizationId, "SCEP_CERT_ISSUED")) {
            return;
        }
        IotDeviceSource source = resolveSource(organizationId,
                message.getConnectionProfileRef(), message.getEndpointId(), message.getSourceXref());
        String transactionId = required(message.getIntuneTransactionId(), 255, "intuneTransactionId");
        enrollmentRepository.lockTransaction(source.getId(), transactionId);
        String csrFingerprint = optionalSha256(message.getCsrFingerprintSha256(), "csrFingerprintSha256");
        String certificateFingerprintSha1 = sha1(message.getFingerprintSha1(), "fingerprintSha1");
        String certificateFingerprint = sha256(message.getFingerprintSha256(), "fingerprintSha256");
        if (message.getKeySize() != null && message.getKeySize() <= 0) {
            throw new IllegalArgumentException("keySize must be positive");
        }
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        OffsetDateTime requestedAt = timestamp(message.getRequestedAt(), "requestedAt");
        OffsetDateTime validatedAt = timestamp(message.getValidatedAt(), "validatedAt");
        OffsetDateTime issuedAt = timestamp(message.getIssuedAt(), "issuedAt");
        OffsetDateTime completedAt = timestamp(message.getCompletedAt(), "completedAt");
        OffsetDateTime respondedAt = timestamp(message.getRespondedAt(), "respondedAt");
        validateTimeline(requestedAt, validatedAt, issuedAt, completedAt, respondedAt);
        validateCertificateMetadata(message);

        // The profile is a hint to verify, never a routing key: an unknown profile keeps the
        // certificate, a hint that belongs to another source rejects the whole message.
        ProfileResolution profileResolution = resolveProfileHint(
                message.getProfileXref(), message.getProviderProfileId(), source);

        // Resolved before the enrollment row is locked, because resolving an initial enrollment
        // takes a shared lock on the device. The sync's orphan batch locks stale devices and then
        // their enrollments; acquiring in the other order here would let an issuance and the sync
        // that is orphaning its device deadlock against each other. A duplicate delivery pays one
        // extra device read for that ordering, which is cheap next to a deadlock on the SCEP path.
        IotCertificateDeviceLinkService.DeviceLink deviceLink =
                deviceLinkService.resolve(source, message);

        Optional<IotCertificateEnrollment> existing = enrollmentRepository
                .findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                        organizationId, source.getId(), transactionId);
        boolean preExisting = existing.isPresent();
        IotCertificateEnrollment enrollment;
        if (preExisting) {
            enrollment = existing.get();
            // A conflict is two PRESENT fingerprints that differ. A shell that carried none must
            // not discard the issued certificate: an unknown detail never drops it.
            if (csrFingerprint != null && enrollment.getCsrFingerprintSha256() != null
                    && !csrFingerprint.equals(enrollment.getCsrFingerprintSha256())) {
                throw new IllegalArgumentException(
                        "transaction was already recorded with another CSR fingerprint");
            }
            if (enrollment.getCsrFingerprintSha256() == null && csrFingerprint != null) {
                enrollment.setCsrFingerprintSha256(csrFingerprint);
            }
        } else {
            enrollment = createEnrollment(message, source, profileResolution, organizationId,
                    transactionId, csrFingerprint, requestedAt, validatedAt, issuedAt, completedAt,
                    receivedAt, deviceLink);
        }
        Optional<IotDeviceCertificate> existingCertificate =
                certificateRepository.findByEnrollmentId(enrollment.getId());
        if (existingCertificate.isPresent()) {
            verifyDuplicateCertificate(existingCertificate.get(), message,
                    certificateFingerprintSha1, certificateFingerprint);
            return;
        }
        if (preExisting) {
            // A prior SCEP_CERT_REQUESTED created the shell without device or profile evidence.
            // The ISSUED message is where identity becomes known, so apply both links now (only on
            // first real processing — the duplicate check above already returned otherwise).
            applyDeviceLink(enrollment, deviceLink);
            applyProfileResolution(enrollment, profileResolution);
            deviceLinkService.record(enrollment, message, deviceLink, validatedAt);
        }

        CertificateProfileConfiguration configuration = profileResolution.profile() == null ? null
                : configurationRepository.findById(profileResolution.profile().getId()).orElse(null);
        IotDeviceCertificate certificate = toCertificate(
                message, enrollment, configuration, certificateFingerprintSha1,
                certificateFingerprint, issuedAt, receivedAt);
        IotDeviceCertificate savedCertificate = certificateRepository.save(certificate);
        returnArchivedDeviceToInventory(enrollment, message.getCorrelationId());
        // txn= is what joins this to the agent's own SCEP line and to the REQUESTED/RESULT
        // messages for the same enrollment; identifier type travels, the value never does.
        log.info("SCEP certificate inventory persisted: source={} txn={} enrollment={} "
                        + "certificate={} serial={} deviceMatch={} deviceId={} identifierType={} "
                        + "profileResolution={}",
                source.getSourceXref(), transactionId, enrollment.getEnrollmentXref(),
                savedCertificate.getCertificateXref(), savedCertificate.getSerialNumber(),
                enrollment.getDeviceMatchStatus(), enrollment.getDeviceId(),
                enrollment.getSourceIdentifierType(), enrollment.getProfileResolutionStatus());
        supersessionService.reconcileGroup(savedCertificate.getOrganizationId(),
                savedCertificate.getDeviceId(), savedCertificate.getProfileId(),
                message.getCorrelationId());

        enrollment.setStatus("ISSUED");
        // validatedAt is set here too, not only in createEnrollment: when a prior SCEP_CERT_REQUESTED
        // already created the shell, this update path owns filling in the validation timestamp.
        enrollment.setValidatedAt(validatedAt);
        enrollment.setIssuedAt(issuedAt);
        enrollment.setCompletedAt(completedAt);
        enrollment.setUpdatedAt(receivedAt);
        // A retryable failure recorded before the retry succeeded is no longer the outcome.
        enrollment.setFailureStage(null);
        enrollment.setErrorCode(null);
        enrollment.setErrorMessage(null);
        enrollment.setRetryable(false);
        enrollmentRepository.save(enrollment);
        // A successful issuance implies the intermediate transitions all happened. The agent already
        // sends their timestamps, so reconstruct the audit trail here rather than adding queue traffic.
        String enrollmentXref = enrollment.getEnrollmentXref();
        eventService.recordEnrollment(enrollment, DeviceEventType.CHALLENGE_VALIDATED, "VALIDATING",
                "Intune validated the challenge", Map.of(),
                message.getCorrelationId(), "scep-validated:" + enrollmentXref, validatedAt);
        eventService.recordEnrollment(enrollment, DeviceEventType.CA_ISSUANCE_STARTED, "SIGNING",
                "CA issuance started", Map.of("caProvider", certificate.getCaProvider()),
                message.getCorrelationId(), "scep-ca-started:" + enrollmentXref, validatedAt);
        eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_ISSUED, "ISSUED",
                "Certificate issued successfully",
                Map.of("certificateXref", certificate.getCertificateXref(),
                        "caProvider", certificate.getCaProvider(),
                        "serialNumber", certificate.getSerialNumber()),
                message.getCorrelationId(), "scep-issued:" + certificateFingerprint, issuedAt);
        eventService.recordEnrollment(enrollment, DeviceEventType.INTUNE_NOTIFICATION_SUCCEEDED, "ISSUED",
                "Intune notified of issuance", Map.of(),
                message.getCorrelationId(), "scep-notified:" + enrollmentXref, respondedAt);
        recordProfileResolution(enrollment, profileResolution, message.getCorrelationId(), issuedAt);
    }

    /**
     * Resolves the device source that owns the SCEP route. Version 3 names it in
     * {@code connectionProfileRef}; version 2 producers carried the same value as {@code endpointId}.
     */
    private IotDeviceSource resolveSource(Long organizationId, String connectionProfileRef,
                                          String endpointId, String sourceXref) {
        String sourceRef = required(firstNonBlank(connectionProfileRef, endpointId),
                100, "connectionProfileRef");
        IotDeviceSource source = sourceRepository
                .findByOrganizationIdAndConnectionProfileRef(organizationId, sourceRef)
                .orElseThrow(() -> new IllegalArgumentException(
                        "no device source is registered for this connection profile"));
        if (sourceXref != null && !sourceXref.isBlank()
                && !sourceXref.trim().equals(source.getSourceXref())) {
            throw new IllegalArgumentException(
                    "sourceXref does not corroborate the resolved device source");
        }
        return source;
    }

    /**
     * A missing or not-yet-synchronized profile hint keeps the certificate storable
     * ({@code PENDING_SYNC}); only a hint that provably belongs to another source or organization
     * rejects the message. {@code MATCHED} requires exactly one proven profile.
     */
    private ProfileResolution resolveProfileHint(String profileXref, String providerProfileId,
                                                 IotDeviceSource source) {
        String xref = trimToNull(profileXref);
        if (xref != null) {
            if (xref.length() > 100) {
                throw new IllegalArgumentException("profileXref exceeds 100 characters");
            }
            Optional<CertificateProfile> profile = profileRepository
                    .lockByProfileXrefAndOrganizationId(xref, source.getOrganizationId());
            if (profile.isEmpty()) {
                return new ProfileResolution(null, PROFILE_PENDING_SYNC);
            }
            if (!source.getId().equals(profile.get().getDeviceSourceId())) {
                throw new IllegalArgumentException("profile hint belongs to another device source");
            }
            return new ProfileResolution(profile.get(), PROFILE_MATCHED);
        }
        String providerId = trimToNull(providerProfileId);
        if (providerId != null) {
            if (providerId.length() > 500) {
                throw new IllegalArgumentException("providerProfileId exceeds 500 characters");
            }
            List<CertificateProfile> candidates =
                    profileRepository.findAllByDeviceSourceIdAndProviderProfileId(
                            source.getId(), providerId);
            if (candidates.size() == 1) {
                return new ProfileResolution(candidates.get(0), PROFILE_MATCHED);
            }
            return new ProfileResolution(null,
                    candidates.isEmpty() ? PROFILE_PENDING_SYNC : PROFILE_AMBIGUOUS);
        }
        return new ProfileResolution(null, PROFILE_PENDING_SYNC);
    }

    private static void applyDeviceLink(IotCertificateEnrollment enrollment,
                                        IotCertificateDeviceLinkService.DeviceLink deviceLink) {
        enrollment.setAssertedSourceDeviceId(deviceLink.identifierValue());
        enrollment.setSourceIdentifierType(deviceLink.identifierType());
        enrollment.setSourceIdentifierAssurance(deviceLink.identifierAssurance());
        enrollment.setDeviceId(deviceLink.deviceId());
        enrollment.setDeviceMatchStatus(deviceLink.status());
        enrollment.setEnrollmentType(deviceLink.enrollmentType());
        enrollment.setPriorCertificateIssuerDn(deviceLink.priorCertificateIssuerDn());
        enrollment.setPriorCertificateSerialNumber(deviceLink.priorCertificateSerialNumber());
    }

    private static void applyProfileResolution(IotCertificateEnrollment enrollment,
                                               ProfileResolution resolution) {
        enrollment.setProfileId(resolution.profileId());
        enrollment.setProfileResolutionStatus(resolution.status());
    }

    private void recordProfileResolution(IotCertificateEnrollment enrollment,
                                         ProfileResolution resolution,
                                         String correlationId,
                                         OffsetDateTime occurredAt) {
        boolean matched = PROFILE_MATCHED.equals(resolution.status());
        eventService.recordEnrollment(enrollment,
                matched ? DeviceEventType.CERTIFICATE_PROFILE_MATCHED
                        : DeviceEventType.CERTIFICATE_PROFILE_UNMATCHED,
                resolution.status(),
                matched ? "Certificate profile proven by a source-scoped hint"
                        : "Certificate stored without a profile link; reconciliation is pending",
                matched ? Map.of("profileXref", resolution.profile().getProfileXref()) : Map.of(),
                correlationId, "scep-profile-match:" + enrollment.getEnrollmentXref(), occurredAt);
    }

    private boolean organizationUnavailable(Long organizationId, String messageType) {
        if (!organizationRepository.existsById(organizationId)
                || !featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId)) {
            log.warn("Dropping {} for unavailable organizationId={}", messageType, organizationId);
            return true;
        }
        return false;
    }

    private IotCertificateEnrollment findOrCreateShell(IotDeviceSource source,
                                                       Long organizationId, String transactionId,
                                                       String csrFingerprint, String status,
                                                       OffsetDateTime requestedAt, OffsetDateTime receivedAt,
                                                       boolean retryable) {
        Optional<IotCertificateEnrollment> existing = enrollmentRepository
                .findByOrganizationIdAndDeviceSourceIdAndTransactionId(
                        organizationId, source.getId(), transactionId);
        if (existing.isPresent()) {
            IotCertificateEnrollment enrollment = existing.get();
            if (csrFingerprint != null && enrollment.getCsrFingerprintSha256() != null
                    && !csrFingerprint.equals(enrollment.getCsrFingerprintSha256())) {
                throw new IllegalArgumentException(
                        "transaction was already recorded with another CSR fingerprint");
            }
            return enrollment;
        }
        return enrollmentRepository.save(IotCertificateEnrollment.builder()
                .enrollmentXref("enr_" + UUID.randomUUID())
                .organizationId(organizationId)
                .deviceSourceId(source.getId())
                .profileId(null)
                .profileResolutionStatus(PROFILE_PENDING_SYNC)
                .deviceId(null)
                .endpointId(required(source.getConnectionProfileRef(), 100, "connectionProfileRef"))
                .transactionId(transactionId)
                .csrFingerprintSha256(csrFingerprint)
                .enrollmentType("INITIAL")
                .deviceMatchStatus("NOT_ASSERTED")
                .status(status)
                .retryable(retryable)
                .requestedAt(requestedAt)
                .createdAt(receivedAt)
                .updatedAt(receivedAt)
                .build());
    }

    private static void rollbackOnly() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }

    private IotCertificateEnrollment createEnrollment(ScepCertificateIssuedMessage message,
                                                      IotDeviceSource source,
                                                      ProfileResolution profileResolution,
                                                      Long organizationId,
                                                      String transactionId,
                                                      String csrFingerprint,
                                                      OffsetDateTime requestedAt,
                                                      OffsetDateTime validatedAt,
                                                      OffsetDateTime issuedAt,
                                                      OffsetDateTime completedAt,
                                                      OffsetDateTime receivedAt,
                                                      IotCertificateDeviceLinkService.DeviceLink deviceLink) {
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .enrollmentXref("enr_" + UUID.randomUUID())
                .organizationId(organizationId)
                .deviceSourceId(source.getId())
                .profileId(profileResolution.profileId())
                .profileResolutionStatus(profileResolution.status())
                .deviceId(deviceLink.deviceId())
                .endpointId(required(source.getConnectionProfileRef(),
                        100, "connectionProfileRef"))
                .transactionId(transactionId)
                .csrFingerprintSha256(csrFingerprint)
                .assertedSourceDeviceId(deviceLink.identifierValue())
                .sourceIdentifierType(deviceLink.identifierType())
                .sourceIdentifierAssurance(deviceLink.identifierAssurance())
                .enrollmentType(deviceLink.enrollmentType())
                .priorCertificateIssuerDn(deviceLink.priorCertificateIssuerDn())
                .priorCertificateSerialNumber(deviceLink.priorCertificateSerialNumber())
                .deviceMatchStatus(deviceLink.status())
                .status("ISSUED")
                .retryable(false)
                .requestedAt(requestedAt)
                .validatedAt(validatedAt)
                .issuedAt(issuedAt)
                .completedAt(completedAt)
                .createdAt(receivedAt)
                .updatedAt(receivedAt)
                .build();
        IotCertificateEnrollment saved = enrollmentRepository.save(enrollment);
        deviceLinkService.record(saved, message, deviceLink, validatedAt);
        return saved;
    }

    /**
     * Passive renewal confirmation: a fresh certificate for the same device and profile is our own
     * proof that any earlier, still-monitored certificate has renewed. Flip those priors to
     * {@code RENEWED} (terminal) and append the event. No Intune round-trip. Requires both a linked
     * device and a resolved profile — without both, "same device + profile" cannot be asserted.
     */
    /**
     * A device that has just been issued a certificate is in use, so it cannot stay hidden.
     *
     * <p>Archiving checks that nothing usable is issued against the device, but a renewal inherits
     * its device from the prior certificate and never consults {@code iot_device}, so a live
     * certificate can still land on an archived row afterwards. Undoing the archive here keeps the
     * credential visible; the statement matches no row unless the device really was archived.
     */
    private void returnArchivedDeviceToInventory(
            IotCertificateEnrollment enrollment, String correlationId) {
        Long deviceId = enrollment.getDeviceId();
        if (deviceId == null || deviceRepository.restoreArchivedDevice(deviceId) == 0) {
            return;
        }
        log.info("Archived device returned to the inventory by a new certificate: enrollment={} "
                + "deviceId={} correlation={}", enrollment.getEnrollmentXref(), deviceId,
                correlationId);
    }

    private IotDeviceCertificate toCertificate(ScepCertificateIssuedMessage message,
                                               IotCertificateEnrollment enrollment,
                                               CertificateProfileConfiguration configuration,
                                               String fingerprintSha1,
                                               String fingerprint,
                                               OffsetDateTime issuedAt,
                                               OffsetDateTime receivedAt) {
        OffsetDateTime validFrom = timestamp(message.getValidFrom(), "validFrom");
        OffsetDateTime validTo = timestamp(message.getValidTo(), "validTo");
        if (!validTo.isAfter(validFrom)) {
            throw new IllegalArgumentException("validTo must be after validFrom");
        }
        return IotDeviceCertificate.builder()
                .certificateXref("crt_" + UUID.randomUUID())
                .enrollmentId(enrollment.getId())
                .organizationId(enrollment.getOrganizationId())
                .deviceSourceId(enrollment.getDeviceSourceId())
                .profileId(enrollment.getProfileId())
                .deviceId(enrollment.getDeviceId())
                .caProvider(required(message.getCaProvider(), 50, "caProvider").toUpperCase(Locale.ROOT))
                .issuerXref(truncate(
                        configuration == null ? null : configuration.getIssuerXref(), 100))
                .caName(truncate(message.getCaName(), 255))
                .caEndEntityName(truncate(message.getEndEntityName(), 255))
                .caProvisionerName(truncate(message.getCaProvisionerName(), 255))
                .issuerDn(required(message.getIssuer(), 2000, "issuer"))
                .serialNumber(canonicalSerial(message.getSerialNumber()))
                .subjectDn(required(message.getSubjectDn(), 2000, "subjectDn"))
                .commonName(truncate(message.getCommonName(), 500))
                .subjectAltNamesJson(json(boundedSubjectAlternativeNames(message.getSubjectAltNames())))
                .certificateScope(configuration == null ? null : configuration.getCertificateScope())
                .fingerprintSha1(fingerprintSha1)
                .fingerprintSha256(fingerprint)
                .validFrom(validFrom)
                .validTo(validTo)
                .signatureAlgorithm(truncate(message.getSignatureAlgorithm(), 100))
                .signatureAlgorithmOid(truncate(message.getSignatureAlgorithmOid(), 100))
                .publicKeyAlgorithm(truncate(message.getPublicKeyAlgorithm(), 30))
                .keySize(message.getKeySize())
                .publicKeyCurve(truncate(message.getPublicKeyCurve(), 100))
                .keyUsageJson(json(csv(message.getKeyUsage())))
                .extendedKeyUsageOidsJson(json(csv(message.getExtendedKeyUsage())))
                .certificatePolicyOidsJson(json(boundedList(message.getCertificatePolicyOids(), 50, 100)))
                .subjectKeyIdentifier(truncate(message.getSubjectKeyIdentifier(), 255))
                .authorityKeyIdentifier(truncate(message.getAuthorityKeyIdentifier(), 255))
                .certificateAuthority(Boolean.TRUE.equals(message.getCertificateAuthority()))
                .status("ISSUED")
                .renewalState("NONE")
                .nudgeAttempts(0)
                .issuedAt(issuedAt)
                .createdAt(receivedAt)
                .updatedAt(receivedAt)
                .build();
    }

    private static void verifyDuplicateCertificate(IotDeviceCertificate existing,
                                                   ScepCertificateIssuedMessage message,
                                                   String fingerprintSha1,
                                                   String fingerprint) {
        String issuer = required(message.getIssuer(), 2000, "issuer");
        String serial = canonicalSerial(message.getSerialNumber());
        if (!fingerprintSha1.equals(existing.getFingerprintSha1())
                || !fingerprint.equals(existing.getFingerprintSha256())
                || !issuer.equals(existing.getIssuerDn())
                || !serial.equals(existing.getSerialNumber())) {
            throw new IllegalArgumentException(
                    "transaction was already recorded with another issued certificate");
        }
    }

    /** Validate every agent-controlled field before the first enrollment write. */
    private static void validateCertificateMetadata(ScepCertificateIssuedMessage message) {
        required(firstNonBlank(message.getEndpointId(), message.getConnectionProfileRef()),
                100, "endpointId");
        required(message.getCaProvider(), 50, "caProvider");
        required(message.getIssuer(), 2000, "issuer");
        canonicalSerial(message.getSerialNumber());
        required(message.getSubjectDn(), 2000, "subjectDn");
        OffsetDateTime validFrom = timestamp(message.getValidFrom(), "validFrom");
        OffsetDateTime validTo = timestamp(message.getValidTo(), "validTo");
        if (!validTo.isAfter(validFrom)) {
            throw new IllegalArgumentException("validTo must be after validFrom");
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("certificate metadata is not valid JSON", exception);
        }
    }

    private static List<String> csv(String value) {
        if (value == null || value.isBlank()) return List.of();
        return Arrays.stream(value.split(","))
                .map(String::trim).filter(part -> !part.isEmpty()).limit(100).toList();
    }

    private static List<String> boundedList(List<String> values, int maxItems, int maxLength) {
        if (values == null) return List.of();
        return values.stream().filter(value -> value != null && !value.isBlank())
                .map(value -> truncate(value, maxLength)).limit(maxItems).toList();
    }

    private static List<ScepCertificateIssuedMessage.SubjectAlternativeName> boundedSubjectAlternativeNames(
            List<ScepCertificateIssuedMessage.SubjectAlternativeName> values) {
        if (values == null) return List.of();
        return values.stream()
                .filter(value -> value != null && value.type() != null && value.value() != null)
                .map(value -> new ScepCertificateIssuedMessage.SubjectAlternativeName(
                        truncate(value.type(), 50), truncate(value.oid(), 100),
                        truncate(value.value(), 2000)))
                .filter(value -> !value.type().isBlank() && !value.value().isBlank())
                .limit(100)
                .toList();
    }

    private static void validateTimeline(OffsetDateTime requestedAt,
                                         OffsetDateTime validatedAt,
                                         OffsetDateTime issuedAt,
                                         OffsetDateTime completedAt,
                                         OffsetDateTime respondedAt) {
        if (validatedAt.isBefore(requestedAt)
                || issuedAt.isBefore(validatedAt)
                || completedAt.isBefore(issuedAt)
                || respondedAt.isBefore(completedAt)) {
            throw new IllegalArgumentException("enrollment timestamps are out of order");
        }
    }

    private static String canonicalSerial(String value) {
        String serial = required(value, 160, "serialNumber").replace(":", "").toUpperCase(Locale.ROOT);
        if (!serial.matches("[0-9A-F]+")) throw new IllegalArgumentException("serialNumber must be hexadecimal");
        return serial;
    }

    private static String sha256(String value, String field) {
        String normalized = required(value, 95, field).replace(":", "").toLowerCase(Locale.ROOT);
        if (!SHA256.matcher(normalized).matches()) throw new IllegalArgumentException(field + " must be SHA-256 hex");
        return normalized;
    }

    private static String sha1(String value, String field) {
        String normalized = required(value, 59, field).replace(":", "").toLowerCase(Locale.ROOT);
        if (!SHA1.matcher(normalized).matches()) {
            throw new IllegalArgumentException(field + " must be SHA-1 hex");
        }
        return normalized;
    }

    private static String optionalSha256(String value, String field) {
        return value == null || value.isBlank() ? null : sha256(value, field);
    }

    private static OffsetDateTime timestamp(String value, String field) {
        try { return OffsetDateTime.parse(required(value, 50, field)); }
        catch (RuntimeException exception) { throw new IllegalArgumentException(field + " must be ISO-8601"); }
    }

    private static Long positiveLong(String value, String field) {
        try {
            long parsed = Long.parseLong(required(value, 30, field));
            if (parsed <= 0) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(field + " must be a positive integer");
        }
    }

    private static String required(String value, int max, String field) {
        String normalized = value == null ? null : value.trim();
        if (normalized == null || normalized.isEmpty()) throw new IllegalArgumentException(field + " is required");
        if (normalized.length() > max) throw new IllegalArgumentException(field + " exceeds " + max + " characters");
        return normalized;
    }

    private static String truncate(String value, int max) {
        if (value == null) return null;
        String normalized = value.trim();
        return normalized.length() <= max ? normalized : normalized.substring(0, max);
    }

    private static String trimToNull(String value) {
        if (value == null || value.isBlank()) return null;
        return value.trim();
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private static boolean sameNullable(String left, String right) {
        return Objects.equals(left, right);
    }

    /** Outcome of the optional profile hint: a proven profile, or a null link with its reason. */
    record ProfileResolution(CertificateProfile profile, String status) {
        Long profileId() {
            return profile == null ? null : profile.getId();
        }
    }
}
