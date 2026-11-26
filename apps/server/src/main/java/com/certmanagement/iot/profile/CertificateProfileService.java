// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.text.Normalizer;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProfileService {
    private static final String INTUNE_WINDOWS_SCEP =
            "#microsoft.graph.windows81SCEPCertificateProfile";
    private static final Set<String> WINDOWS_KSP_VALUES = Set.of(
            "useTpmKspOtherwiseUseSoftwareKsp", "useTpmKspOtherwiseFail",
            "usePassportForWorkKspOtherwiseFail", "useSoftwareKsp");
    private static final Set<String> WINDOWS_KEY_USAGES = Set.of(
            "digitalSignature", "keyEncipherment");
    private static final Set<String> WINDOWS_PROVIDER_CONFIG_KEYS = Set.of(
            "renewalThresholdPercentage", "keyStorageProvider", "assignmentGroupIds");
    private static final int MAX_ASSIGNMENT_GROUPS = 20;
    private static final Pattern GUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Set<String> WINDOWS_SAN_TYPES = Set.of(
            "EMAIL", "UPN", "DNS", "URI");
    private static final Set<String> WINDOWS_SAN_KEYS = Set.of("type", "format");
    private static final Set<String> WINDOWS_EKU_KEYS = Set.of("name", "objectIdentifier");
    private static final int MAX_PROFILE_PAGE_SIZE = 100;
    private static final char LIKE_ESCAPE = '\\';
    private static final Pattern RESERVED_CORRELATION_MARKER = Pattern.compile(
            "\\[\\s*certping\\s*:",
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.UNICODE_CHARACTER_CLASS);

    private final CertificateProfileRepository profileRepository;
    private final CertificateProfileConfigurationRepository configurationRepository;
    private final CertificateProfileProviderSnapshotRepository snapshotRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceEventService eventService;
    private final CertificateProfileMessageDispatcher dispatcher;
    private final CertificateProfileJsonCodec jsonCodec;
    private final FeatureFlagService featureFlagService;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    @Transactional(readOnly = true)
    public Page<CertificateProfileResponse> list(
            Long organizationId,
            String sourceXref,
            ProfileLifecycleStatus lifecycleStatus,
            ProfileControlMode controlMode,
            ProviderSyncStatus providerSyncStatus,
            String targetPlatform,
            String search,
            Pageable pageable) {
        assertCommonFeatureFlags(organizationId);
        Long sourceId = sourceXref == null ? null
                : requireSourceForRead(organizationId, sourceXref).getId();
        Pageable boundedPageable = pageable.getPageSize() <= MAX_PROFILE_PAGE_SIZE
                ? pageable
                : PageRequest.of(pageable.getPageNumber(), MAX_PROFILE_PAGE_SIZE, pageable.getSort());
        Specification<CertificateProfile> specification =
                (root, query, criteria) -> criteria.equal(root.get("organizationId"), organizationId);
        if (sourceId != null) {
            specification = specification.and((root, query, criteria) ->
                    criteria.equal(root.get("deviceSourceId"), sourceId));
        }
        if (lifecycleStatus != null) {
            specification = specification.and((root, query, criteria) ->
                    criteria.equal(root.get("lifecycleStatus"), lifecycleStatus));
        } else {
            specification = specification.and((root, query, criteria) ->
                    criteria.notEqual(root.get("lifecycleStatus"),
                            ProfileLifecycleStatus.ARCHIVED));
        }
        if (controlMode != null) {
            specification = specification.and((root, query, criteria) ->
                    criteria.equal(root.get("controlMode"), controlMode));
        }
        if (providerSyncStatus != null) {
            specification = specification.and((root, query, criteria) ->
                    criteria.equal(root.get("providerSyncStatus"), providerSyncStatus));
        }
        if (targetPlatform != null && !targetPlatform.isBlank()) {
            String normalizedPlatform = normalize(targetPlatform);
            specification = specification.and((root, query, criteria) ->
                    criteria.equal(root.get("targetPlatform"), normalizedPlatform));
        }
        if (search != null && !search.isBlank()) {
            String pattern = "%" + escapeLikeLiteral(
                    search.trim().toLowerCase(Locale.ROOT)) + "%";
            specification = specification.and((root, query, criteria) ->
                    criteria.or(
                            criteria.like(criteria.lower(root.get("name")), pattern, LIKE_ESCAPE),
                            criteria.like(criteria.lower(root.get("description")), pattern, LIKE_ESCAPE)));
        }
        Page<CertificateProfile> profiles = profileRepository.findAll(specification, boundedPageable);
        if (profiles.isEmpty()) {
            return Page.empty(boundedPageable);
        }
        Map<Long, IotDeviceSource> sources = sourceRepository.findAllById(
                        profiles.stream().map(CertificateProfile::getDeviceSourceId).collect(Collectors.toSet()))
                .stream().collect(Collectors.toMap(IotDeviceSource::getId, Function.identity()));
        Map<Long, CertificateProfileConfiguration> configurations = configurationRepository
                .findAllById(profiles.stream().map(CertificateProfile::getId).toList())
                .stream().collect(Collectors.toMap(
                        CertificateProfileConfiguration::getProfileId, Function.identity()));
        return profiles.map(profile -> toResponse(
                profile,
                sources.get(profile.getDeviceSourceId()),
                configurations.get(profile.getId()),
                null));
    }

    @Transactional(readOnly = true)
    public CertificateProfileResponse get(Long organizationId, String profileXref) {
        assertCommonFeatureFlags(organizationId);
        CertificateProfile profile = requireProfile(organizationId, profileXref);
        return toResponse(profile);
    }

    @Transactional(readOnly = true)
    public CertificateProfile requireProfile(Long organizationId, String profileXref) {
        assertCommonFeatureFlags(organizationId);
        return profileRepository.findByProfileXrefAndOrganizationId(profileXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Certificate profile not found"));
    }

    @Transactional
    public CertificateProfileResponse create(
            Long organizationId, Long actorUserId, CreateCertificateProfileRequest request) {
        if (request.lifecycleStatus() == ProfileLifecycleStatus.ARCHIVED) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "A certificate profile cannot be created as ARCHIVED");
        }
        IotDeviceSource source = requireSource(organizationId, request.sourceXref());
        String targetPlatform = normalize(request.targetPlatform());
        String targetVariant = request.targetVariant() == null
                ? "STANDARD" : normalize(request.targetVariant());
        String description = validatedDescription(request.description());
        validateRequest(source, request.lifecycleStatus(), targetPlatform,
                request.profileKind(), request.enrollmentMethod(), request.configuration());

        OffsetDateTime now = OffsetDateTime.now(clock);
        String profileXref = xref("profile_");
        boolean activate = request.lifecycleStatus() == ProfileLifecycleStatus.ACTIVE;
        String operationXref = activate ? xref("profile_op_") : null;
        CertificateProfile profile = CertificateProfile.builder()
                .profileXref(profileXref)
                .organizationId(organizationId)
                .deviceSourceId(source.getId())
                .name(request.name().trim())
                .description(description)
                .targetPlatform(targetPlatform)
                .targetVariant(targetVariant)
                .providerProfileType(resolveProviderType(source, targetPlatform,
                        request.enrollmentMethod()))
                .providerCorrelationMarker("certping:" + profileXref)
                .lifecycleStatus(request.lifecycleStatus())
                .profileOrigin(ProfileOrigin.CMS_CREATED)
                .controlMode(ProfileControlMode.CMS_MANAGED)
                .profileKind(request.profileKind())
                .enrollmentMethod(normalizeNullable(request.enrollmentMethod()))
                .desiredRevision(1L)
                .latestOperationXref(operationXref)
                .latestOperationStartedAt(activate ? now : null)
                .providerSyncStatus(activate ? ProviderSyncStatus.PENDING : ProviderSyncStatus.NEVER)
                .createdByUserId(actorUserId)
                .updatedByUserId(actorUserId)
                .build();
        profileRepository.saveAndFlush(profile);
        configurationRepository.save(toConfiguration(profile, request.configuration(), now));
        iotAudit.profileCreated(profile, source.getSourceXref());

        eventService.record(source, DeviceSourceEventType.PROFILE_CREATED,
                activate ? ProviderSyncStatus.PENDING.name() : ProfileLifecycleStatus.DRAFT.name(),
                detail(profile, operationXref, actorUserId, List.of()), now, operationXref,
                profileXref + ":created");
        if (activate) {
            publishAfterCommit(profile.getId(), operationXref, "CREATE");
        }
        return toResponse(profile);
    }

    @Transactional
    public CertificateProfileResponse update(
            Long organizationId,
            Long actorUserId,
            String profileXref,
            UpdateCertificateProfileRequest request) {
        assertCommonFeatureFlags(organizationId);
        CertificateProfile profile = profileRepository
                .lockByProfileXrefAndOrganizationId(profileXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Certificate profile not found"));
        if (profile.getControlMode() != ProfileControlMode.CMS_MANAGED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Provider-discovered profiles are read-only");
        }
        if (!Objects.equals(profile.getRowVersion(), request.expectedVersion())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Certificate profile changed; reload it before updating");
        }
        IotDeviceSource source = requireSourceById(profile.getDeviceSourceId());
        assertProviderFeatureFlag(source);
        validateRequest(source, request.lifecycleStatus(), profile.getTargetPlatform(),
                profile.getProfileKind(), profile.getEnrollmentMethod(), request.configuration());
        String description = validatedDescription(request.description());

        CertificateProfileConfiguration oldConfiguration = configurationRepository
                .findById(profile.getId()).orElseThrow();
        List<String> changedFields = changedFields(
                profile, oldConfiguration, request, description);
        boolean nativeUpdate = request.lifecycleStatus() == ProfileLifecycleStatus.ACTIVE
                && profile.getProviderProfileId() != null;
        if (nativeUpdate && !changedFields.isEmpty() && !request.confirmReissuance()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "confirmReissuance=true is required because Intune can revoke affected certificates");
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        ProfileLifecycleStatus statusBefore = profile.getLifecycleStatus();
        profile.setName(request.name().trim());
        profile.setDescription(description);
        profile.setLifecycleStatus(request.lifecycleStatus());
        profile.setUpdatedByUserId(actorUserId);
        configurationRepository.save(toConfiguration(profile, request.configuration(), now));

        boolean send = request.lifecycleStatus() == ProfileLifecycleStatus.ACTIVE
                && (!changedFields.isEmpty() || profile.getProviderProfileId() == null);
        if (send) {
            String operationXref = xref("profile_op_");
            profile.setDesiredRevision(profile.getDesiredRevision() + 1);
            profile.setLatestOperationXref(operationXref);
            profile.setLatestOperationStartedAt(now);
            profile.setLatestOperationCompletedAt(null);
            profile.setProviderSyncStatus(ProviderSyncStatus.PENDING);
            profile.setProviderSyncError(null);
            profileRepository.saveAndFlush(profile);
            DeviceSourceEventType type = nativeUpdate
                    ? DeviceSourceEventType.PROFILE_UPDATE_CONFIRMED
                    : DeviceSourceEventType.PROFILE_UPDATE_REQUESTED;
            eventService.record(source, type, ProviderSyncStatus.PENDING.name(),
                    detail(profile, operationXref, actorUserId, changedFields), now, operationXref,
                    operationXref + ":requested");
            publishAfterCommit(profile.getId(), operationXref,
                    profile.getProviderProfileId() == null ? "CREATE" : "UPDATE");
        } else {
            profileRepository.saveAndFlush(profile);
        }
        iotAudit.profileUpdated(profile, changedFields, statusBefore, send);
        return toResponse(profile);
    }

    private void validateRequest(
            IotDeviceSource source,
            ProfileLifecycleStatus lifecycleStatus,
            String targetPlatform,
            ProfileKind profileKind,
            String enrollmentMethod,
            CertificateProfileConfigurationInput configuration) {
        if ((configuration.validityValue() == null) != (configuration.validityUnit() == null)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "validityValue and validityUnit must be supplied together");
        }
        if (lifecycleStatus != ProfileLifecycleStatus.ACTIVE) {
            return;
        }
        if (source.getProvider() != DeviceSourceProvider.INTUNE
                || !"WINDOWS".equals(targetPlatform)
                || profileKind != ProfileKind.CERTIFICATE_ENROLLMENT
                || !"SCEP".equals(normalizeNullable(enrollmentMethod))) {
            throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
                    "The first native profile implementation supports Intune Windows SCEP only");
        }
        if (!"RSA".equals(normalizeNullable(configuration.keyAlgorithm()))
                || (configuration.keySize() == null
                || (configuration.keySize() != 2048 && configuration.keySize() != 4096))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Intune Windows SCEP requires RSA 2048 or 4096");
        }
        if (configuration.certificateScope() == null
                || configuration.certificateScope().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "certificateScope is required for active SCEP profiles");
        }
        if (configuration.validityValue() == null || configuration.validityUnit() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "validityValue and validityUnit are required for active SCEP profiles");
        }
        if (!Set.of("SHA2", "SHA256").contains(
                normalizeNullable(configuration.signatureHash()))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Intune Windows SCEP requires signatureHash SHA2");
        }
        if (configuration.subjectNameFormat() == null
                || configuration.subjectNameFormat().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "subjectNameFormat is required for active SCEP profiles");
        }
        Map<String, Object> providerConfig = configuration.providerConfig() == null
                ? Map.of() : configuration.providerConfig();
        if (!WINDOWS_PROVIDER_CONFIG_KEYS.containsAll(providerConfig.keySet())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "providerConfig contains a field unsupported by Intune Windows SCEP");
        }
        Integer threshold = exactInteger(providerConfig.get("renewalThresholdPercentage"));
        if (threshold == null || threshold < 1 || threshold > 99) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "providerConfig.renewalThresholdPercentage must be between 1 and 99");
        }
        Object ksp = providerConfig.get("keyStorageProvider");
        if (!(ksp instanceof String value) || !WINDOWS_KSP_VALUES.contains(value)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "providerConfig.keyStorageProvider is invalid for Windows SCEP");
        }
        if (configuration.keySize() == 4096 && !"useSoftwareKsp".equals(ksp)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "RSA 4096 requires the Windows software KSP");
        }
        validateAssignmentGroupIds(providerConfig.get("assignmentGroupIds"));
        if (configuration.keyUsages() == null || configuration.keyUsages().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "keyUsages must contain at least one Intune Windows SCEP usage");
        }
        if (!WINDOWS_KEY_USAGES.containsAll(configuration.keyUsages())
                || configuration.keyUsages().stream().distinct().count()
                != configuration.keyUsages().size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "keyUsages contains a duplicate or value unsupported by Intune Windows SCEP");
        }
        validateSubjectAlternativeNames(configuration.subjectAltNameFormats());
        validateExtendedKeyUsages(configuration.extendedKeyUsages());
    }

    private CertificateProfileConfiguration toConfiguration(
            CertificateProfile profile,
            CertificateProfileConfigurationInput input,
            OffsetDateTime now) {
        return CertificateProfileConfiguration.builder()
                .profileId(profile.getId())
                .organizationId(profile.getOrganizationId())
                .deviceSourceId(profile.getDeviceSourceId())
                .issuerXref(trimToNull(input.issuerXref()))
                .certificateScope(normalizeNullable(input.certificateScope()))
                .keyAlgorithm(normalizeNullable(input.keyAlgorithm()))
                .keySize(input.keySize())
                .curve(trimToNull(input.curve()))
                .signatureHash(normalizeSignatureHash(input.signatureHash()))
                .subjectNameFormat(trimToNull(input.subjectNameFormat()))
                .subjectAltNameFormatsJson(jsonCodec.writeRequest(input.subjectAltNameFormats()))
                .extendedKeyUsagesJson(jsonCodec.writeRequest(input.extendedKeyUsages()))
                .keyUsagesJson(jsonCodec.writeRequest(input.keyUsages()))
                .validityValue(input.validityValue())
                .validityUnit(normalizeNullable(input.validityUnit()))
                .renewalWindowDays(input.renewalWindowDays())
                .keyExportable(input.keyExportable())
                .providerConfigJson(jsonCodec.writeRequest(input.providerConfig()))
                .updatedAt(now)
                .build();
    }

    private CertificateProfileResponse toResponse(CertificateProfile profile) {
        IotDeviceSource source = requireSourceById(profile.getDeviceSourceId());
        CertificateProfileConfiguration configuration = configurationRepository
                .findById(profile.getId()).orElse(null);
        CertificateProfileProviderSnapshot snapshot = snapshotRepository
                .findById(profile.getId()).orElse(null);
        return toResponse(profile, source, configuration, snapshot);
    }

    private CertificateProfileResponse toResponse(
            CertificateProfile profile,
            IotDeviceSource source,
            CertificateProfileConfiguration configuration,
            CertificateProfileProviderSnapshot snapshot) {
        if (source == null) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Device source is no longer available");
        }
        return new CertificateProfileResponse(
                profile.getProfileXref(), source.getSourceXref(), source.getDisplayName(),
                source.getProvider(), profile.getName(), profile.getDescription(),
                profile.getTargetPlatform(), profile.getTargetVariant(),
                profile.getProviderProfileType(), profile.getProviderProfileId(),
                profile.getLifecycleStatus(), profile.getProfileOrigin(), profile.getControlMode(),
                profile.getProfileKind(), profile.getEnrollmentMethod(), profile.getDesiredRevision(),
                profile.getAppliedRevision(), profile.getLatestOperationXref(),
                profile.getLatestOperationStartedAt(), profile.getLatestOperationCompletedAt(),
                profile.getProviderSyncStatus(), profile.getProviderSyncError(),
                profile.getLastProviderSyncedAt(), response(configuration), response(snapshot),
                profile.getCreatedAt(), profile.getUpdatedAt(), profile.getRowVersion());
    }

    private CertificateProfileResponse.Configuration response(
            CertificateProfileConfiguration configuration) {
        if (configuration == null) {
            return null;
        }
        return new CertificateProfileResponse.Configuration(
                configuration.getIssuerXref(), configuration.getCertificateScope(),
                configuration.getKeyAlgorithm(), configuration.getKeySize(), configuration.getCurve(),
                configuration.getSignatureHash(), configuration.getSubjectNameFormat(),
                jsonCodec.readObjectList(configuration.getSubjectAltNameFormatsJson()),
                jsonCodec.readObjectList(configuration.getExtendedKeyUsagesJson()),
                jsonCodec.readStringList(configuration.getKeyUsagesJson()),
                configuration.getValidityValue(), configuration.getValidityUnit(),
                configuration.getRenewalWindowDays(), configuration.getKeyExportable(),
                jsonCodec.readObject(configuration.getProviderConfigJson()));
    }

    private CertificateProfileResponse.ProviderSnapshot response(
            CertificateProfileProviderSnapshot snapshot) {
        if (snapshot == null) {
            return null;
        }
        return new CertificateProfileResponse.ProviderSnapshot(
                jsonCodec.readObject(snapshot.getProviderResponseJson()),
                snapshot.getResponseSchemaVersion(), snapshot.getProviderVersion(),
                snapshot.getProviderLastModifiedAt(), snapshot.getProviderObservedAt());
    }

    private List<String> changedFields(
            CertificateProfile profile,
            CertificateProfileConfiguration configuration,
            UpdateCertificateProfileRequest request,
            String description) {
        List<String> changed = new ArrayList<>();
        changed(changed, "name", profile.getName(), request.name().trim());
        changed(changed, "description", profile.getDescription(), description);
        changed(changed, "lifecycleStatus", profile.getLifecycleStatus(), request.lifecycleStatus());
        CertificateProfileConfigurationInput input = request.configuration();
        changed(changed, "issuerXref", configuration.getIssuerXref(), trimToNull(input.issuerXref()));
        changed(changed, "certificateScope", configuration.getCertificateScope(),
                normalizeNullable(input.certificateScope()));
        changed(changed, "keyAlgorithm", configuration.getKeyAlgorithm(),
                normalizeNullable(input.keyAlgorithm()));
        changed(changed, "keySize", configuration.getKeySize(), input.keySize());
        changed(changed, "curve", configuration.getCurve(), trimToNull(input.curve()));
        changed(changed, "signatureHash", configuration.getSignatureHash(),
                normalizeSignatureHash(input.signatureHash()));
        changed(changed, "subjectNameFormat", configuration.getSubjectNameFormat(),
                trimToNull(input.subjectNameFormat()));
        changed(changed, "subjectAltNameFormats",
                jsonCodec.readObjectList(configuration.getSubjectAltNameFormatsJson()),
                jsonCodec.readObjectList(jsonCodec.writeRequest(input.subjectAltNameFormats())));
        changed(changed, "extendedKeyUsages",
                jsonCodec.readObjectList(configuration.getExtendedKeyUsagesJson()),
                jsonCodec.readObjectList(jsonCodec.writeRequest(input.extendedKeyUsages())));
        changed(changed, "keyUsages",
                jsonCodec.readStringList(configuration.getKeyUsagesJson()),
                jsonCodec.readStringList(jsonCodec.writeRequest(input.keyUsages())));
        changed(changed, "validityValue", configuration.getValidityValue(), input.validityValue());
        changed(changed, "validityUnit", configuration.getValidityUnit(),
                normalizeNullable(input.validityUnit()));
        changed(changed, "renewalWindowDays", configuration.getRenewalWindowDays(),
                input.renewalWindowDays());
        changed(changed, "keyExportable", configuration.getKeyExportable(), input.keyExportable());
        changed(changed, "providerConfig",
                jsonCodec.readObject(configuration.getProviderConfigJson()),
                jsonCodec.readObject(jsonCodec.writeRequest(input.providerConfig())));
        return changed;
    }

    private static String validatedDescription(String value) {
        String description = trimToNull(value);
        String markerCandidate = description == null ? null
                : Normalizer.normalize(description, Normalizer.Form.NFKC);
        if (markerCandidate != null
                && RESERVED_CORRELATION_MARKER.matcher(markerCandidate).find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "description must not contain the reserved [certping:...] correlation marker");
        }
        return description;
    }

    private static void changed(List<String> fields, String field, Object oldValue, Object newValue) {
        if (!Objects.equals(oldValue, newValue)) {
            fields.add(field);
        }
    }

    private Map<String, Object> detail(
            CertificateProfile profile,
            String operationXref,
            Long actorUserId,
            List<String> changedFields) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("profileXref", profile.getProfileXref());
        if (operationXref != null) {
            detail.put("operationXref", operationXref);
        }
        if (actorUserId != null) {
            detail.put("actorUserId", actorUserId);
        }
        if (!changedFields.isEmpty()) {
            detail.put("changedFields", changedFields);
        }
        return detail;
    }

    private void publishAfterCommit(Long profileId, String operationXref, String operation) {
        Runnable publish = () -> {
            try {
                dispatcher.publishOperation(profileId, operationXref, operation);
            } catch (Exception exception) {
                log.warn("Profile operation remains pending after publish failure: profileId={} reason={}",
                        profileId, exception.getMessage());
            }
        };
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            publish.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                publish.run();
            }
        });
    }

    private IotDeviceSource requireSource(Long organizationId, String sourceXref) {
        assertCommonFeatureFlags(organizationId);
        IotDeviceSource source = requireSourceForRead(organizationId, sourceXref);
        assertProviderFeatureFlag(source);
        return source;
    }

    private IotDeviceSource requireSourceForRead(Long organizationId, String sourceXref) {
        return sourceRepository
                .findBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device source not found"));
    }

    private IotDeviceSource requireSourceById(Long sourceId) {
        return sourceRepository.findById(sourceId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.CONFLICT, "Device source is no longer available"));
    }

    private void assertCommonFeatureFlags(Long organizationId) {
        featureFlagService.assertEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId);
        featureFlagService.assertEnabled(
                FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, organizationId);
    }

    private void assertProviderFeatureFlag(IotDeviceSource source) {
        if (source.getProvider() == DeviceSourceProvider.INTUNE) {
            featureFlagService.assertEnabled(
                    FeatureFlags.IOT_PROVIDER_INTUNE, source.getOrganizationId());
        }
    }

    private static String resolveProviderType(
            IotDeviceSource source, String targetPlatform, String enrollmentMethod) {
        if (source.getProvider() == DeviceSourceProvider.INTUNE
                && "WINDOWS".equals(targetPlatform)
                && "SCEP".equals(normalizeNullable(enrollmentMethod))) {
            return INTUNE_WINDOWS_SCEP;
        }
        return source.getProvider().name() + ":" + targetPlatform + ":"
                + Objects.toString(normalizeNullable(enrollmentMethod), "NONE");
    }

    private static Integer exactInteger(Object value) {
        if (value instanceof Byte || value instanceof Short || value instanceof Integer) {
            return ((Number) value).intValue();
        }
        if (value instanceof Long number) {
            return number >= Integer.MIN_VALUE && number <= Integer.MAX_VALUE
                    ? number.intValue() : null;
        }
        if (value instanceof Number number) {
            double candidate = number.doubleValue();
            return Double.isFinite(candidate) && candidate == Math.rint(candidate)
                    && candidate >= Integer.MIN_VALUE && candidate <= Integer.MAX_VALUE
                    ? (int) candidate : null;
        }
        try {
            return value == null ? null : Integer.valueOf(value.toString());
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static void validateAssignmentGroupIds(Object value) {
        if (value == null) {
            return;
        }
        if (!(value instanceof List<?> groupIds) || groupIds.size() > MAX_ASSIGNMENT_GROUPS
                || !groupIds.stream().allMatch(groupId -> groupId instanceof String text
                        && GUID.matcher(text).matches())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "providerConfig.assignmentGroupIds must list at most "
                            + MAX_ASSIGNMENT_GROUPS + " Entra group object IDs");
        }
    }

    private static void validateSubjectAlternativeNames(List<Map<String, Object>> values) {
        if (values == null) {
            return;
        }
        for (Map<String, Object> value : values) {
            if (value == null || !WINDOWS_SAN_KEYS.containsAll(value.keySet())
                    || !value.keySet().containsAll(WINDOWS_SAN_KEYS)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Each subjectAltNameFormats entry must contain only type and format");
            }
            Object type = value.get("type");
            Object format = value.get("format");
            if (!(type instanceof String typeValue)
                    || !WINDOWS_SAN_TYPES.contains(normalize(typeValue))
                    || !(format instanceof String formatValue)
                    || formatValue.isBlank() || formatValue.length() > 1000) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Each subjectAltNameFormats entry requires a supported type and non-empty format");
            }
        }
    }

    private static void validateExtendedKeyUsages(List<Map<String, Object>> values) {
        if (values == null) {
            return;
        }
        for (Map<String, Object> value : values) {
            if (value == null || !WINDOWS_EKU_KEYS.containsAll(value.keySet())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Each extendedKeyUsages entry contains an unsupported field");
            }
            Object oid = value.get("objectIdentifier");
            Object name = value.get("name");
            if (!(oid instanceof String oidValue)
                    || !oidValue.matches("[0-2](\\.[0-9]+)+")
                    || (name != null && (!(name instanceof String nameValue)
                    || nameValue.isBlank() || nameValue.length() > 255))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Each extendedKeyUsages entry requires a valid objectIdentifier and optional name");
            }
        }
    }

    private static String normalize(String value) {
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private static String escapeLikeLiteral(String value) {
        return value.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }

    private static String normalizeNullable(String value) {
        return value == null || value.isBlank() ? null : normalize(value);
    }

    private static String normalizeSignatureHash(String value) {
        String normalized = normalizeNullable(value);
        return "SHA256".equals(normalized) ? "SHA2" : normalized;
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }
}
