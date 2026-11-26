// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.service.OrgTypeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import org.springframework.data.domain.PageRequest;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProfileMessageDispatcher {
    private static final int MAX_CORRELATION_CANDIDATES = 50;

    private final CertificateProfileRepository profileRepository;
    private final CertificateProfileConfigurationRepository configurationRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceSourceEventService eventService;
    private final CertificateProfileJsonCodec jsonCodec;
    private final OrgTypeResolver orgTypeResolver;
    private final CertAgentPublisher publisher;
    private final Clock clock;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void publishOperation(Long profileId, String expectedOperationXref, String operation) {
        CertificateProfile profile = profileRepository.findById(profileId).orElse(null);
        if (profile == null
                || profile.getProviderSyncStatus() != ProviderSyncStatus.PENDING
                || !expectedOperationXref.equals(profile.getLatestOperationXref())) {
            return;
        }
        CertificateProfileConfiguration configuration = configurationRepository
                .findById(profileId).orElseThrow();
        IotDeviceSource source = sourceRepository.findById(profile.getDeviceSourceId()).orElseThrow();
        CertificateProfileCommand command = CertificateProfileCommand.builder()
                .requestId(expectedOperationXref)
                .correlationId(expectedOperationXref)
                .organizationId(String.valueOf(profile.getOrganizationId()))
                .orgType(orgTypeResolver.resolve(profile.getOrganizationId()))
                .sourceXref(source.getSourceXref())
                .connectionProfileRef(source.getConnectionProfileRef())
                .provider(source.getProvider().name())
                .profileXref(profile.getProfileXref())
                .operationXref(expectedOperationXref)
                .operation(operation)
                .desiredRevision(profile.getDesiredRevision())
                .providerProfileId(profile.getProviderProfileId())
                .providerProfileType(profile.getProviderProfileType())
                .providerCorrelationMarker(profile.getProviderCorrelationMarker())
                .name(profile.getName())
                .description(profile.getDescription())
                .targetPlatform(profile.getTargetPlatform())
                .targetVariant(profile.getTargetVariant())
                .profileKind(profile.getProfileKind().name())
                .enrollmentMethod(profile.getEnrollmentMethod())
                .configuration(configurationMap(configuration))
                .requestedAt(OffsetDateTime.now(clock).toString())
                .build();
        publisher.publishCertificateProfileCommand(command);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void publishDiscovery(Long sourceId, String requestXref) {
        IotDeviceSource source = sourceRepository.findById(sourceId).orElse(null);
        if (source == null) {
            return;
        }
        CertificateProfileSyncCommand command = CertificateProfileSyncCommand.builder()
                .requestId(requestXref)
                .correlationId(requestXref)
                .organizationId(String.valueOf(source.getOrganizationId()))
                .orgType(orgTypeResolver.resolve(source.getOrganizationId()))
                .sourceXref(source.getSourceXref())
                .connectionProfileRef(source.getConnectionProfileRef())
                .provider(source.getProvider().name())
                .certificateCorrelationCandidates(correlationCandidates(source.getId()))
                .requestedAt(OffsetDateTime.now(clock).toString())
                .build();
        publisher.publishCertificateProfileSyncCommand(command);
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_STARTED, "RUNNING",
                Map.of("requestXref", requestXref), OffsetDateTime.now(clock), requestXref,
                requestXref + ":started");
    }

    private List<CertificateCorrelationCandidate> correlationCandidates(Long deviceSourceId) {
        return certificateRepository.findProfileCorrelationCandidates(
                        deviceSourceId, PageRequest.of(0, MAX_CORRELATION_CANDIDATES))
                .stream()
                .map(candidate -> new CertificateCorrelationCandidate(
                        candidate.getCertificateXref(), candidate.getFingerprintSha1(),
                        candidate.getIssuerDn(), candidate.getSerialNumber()))
                .toList();
    }

    private Map<String, Object> configurationMap(CertificateProfileConfiguration configuration) {
        Map<String, Object> result = new LinkedHashMap<>();
        put(result, "issuerXref", configuration.getIssuerXref());
        put(result, "certificateScope", configuration.getCertificateScope());
        put(result, "keyAlgorithm", configuration.getKeyAlgorithm());
        put(result, "keySize", configuration.getKeySize());
        put(result, "curve", configuration.getCurve());
        put(result, "signatureHash", configuration.getSignatureHash());
        put(result, "subjectNameFormat", configuration.getSubjectNameFormat());
        result.put("subjectAltNameFormats",
                jsonCodec.readObjectList(configuration.getSubjectAltNameFormatsJson()));
        result.put("extendedKeyUsages",
                jsonCodec.readObjectList(configuration.getExtendedKeyUsagesJson()));
        result.put("keyUsages", jsonCodec.readStringList(configuration.getKeyUsagesJson()));
        put(result, "validityValue", configuration.getValidityValue());
        put(result, "validityUnit", configuration.getValidityUnit());
        put(result, "renewalWindowDays", configuration.getRenewalWindowDays());
        put(result, "keyExportable", configuration.getKeyExportable());
        result.put("providerConfig", jsonCodec.readObject(configuration.getProviderConfigJson()));
        return result;
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
