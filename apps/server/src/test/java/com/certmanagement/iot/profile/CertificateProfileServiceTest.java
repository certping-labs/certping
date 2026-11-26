// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateProfileServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);
    @Mock private CertificateProfileRepository profileRepository;
    @Mock private CertificateProfileConfigurationRepository configurationRepository;
    @Mock private CertificateProfileProviderSnapshotRepository snapshotRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceSourceEventService eventService;
    @Mock private CertificateProfileMessageDispatcher dispatcher;
    @Mock private FeatureFlagService featureFlagService;

    private CertificateProfileService service;
    private final AtomicReference<CertificateProfileConfiguration> storedConfiguration =
            new AtomicReference<>();

    @BeforeEach
    void setUp() {
        service = new CertificateProfileService(
                profileRepository, configurationRepository, snapshotRepository,
                sourceRepository, eventService, dispatcher,
                new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build()),
                featureFlagService,
                Clock.fixed(Instant.parse("2026-08-25T00:00:00Z"), ZoneOffset.UTC), iotAudit);
    }

    @Test
    void activeWindowsScepCreatePersistsPendingStateAndDispatchesWithoutSecrets() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source()));
        when(profileRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            CertificateProfile profile = invocation.getArgument(0);
            profile.setId(100L);
            profile.setRowVersion(0L);
            return profile;
        });
        when(configurationRepository.save(any())).thenAnswer(invocation -> {
            CertificateProfileConfiguration value = invocation.getArgument(0);
            storedConfiguration.set(value);
            return value;
        });
        when(configurationRepository.findById(100L))
                .thenAnswer(invocation -> Optional.ofNullable(storedConfiguration.get()));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());

        CertificateProfileResponse response = service.create(42L, 7L,
                new CreateCertificateProfileRequest(
                        "Corporate Windows", "Device authentication", "source-1",
                        ProfileLifecycleStatus.ACTIVE, "windows", null,
                        ProfileKind.CERTIFICATE_ENROLLMENT, "SCEP", configuration()));

        assertThat(response.providerSyncStatus()).isEqualTo(ProviderSyncStatus.PENDING);
        assertThat(response.targetPlatform()).isEqualTo("WINDOWS");
        assertThat(response.providerProfileType())
                .isEqualTo("#microsoft.graph.windows81SCEPCertificateProfile");
        assertThat(response.configuration().providerConfig())
                .containsEntry("renewalThresholdPercentage", 20)
                .containsEntry("assignmentGroupIds", List.of(GROUP_ID));
        verify(dispatcher).publishOperation(100L, response.latestOperationXref(), "CREATE");
        verify(iotAudit).profileCreated(any(CertificateProfile.class), org.mockito.ArgumentMatchers.eq("source-1"));
    }

    @Test
    void updateOfNativeActiveProfileRequiresExplicitReissuanceConfirmation() {
        CertificateProfile profile = activeProfile();
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source()));
        storedConfiguration.set(storedConfiguration(profile));
        when(configurationRepository.findById(100L))
                .thenAnswer(invocation -> Optional.ofNullable(storedConfiguration.get()));

        UpdateCertificateProfileRequest request = new UpdateCertificateProfileRequest(
                "Renamed profile", "Device authentication", ProfileLifecycleStatus.ACTIVE,
                4L, false, configuration());

        assertThatThrownBy(() -> service.update(42L, 7L, "profile-1", request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("confirmReissuance=true");
        verify(dispatcher, never()).publishOperation(any(), any(), any());
        org.mockito.Mockito.verifyNoInteractions(iotAudit);
    }

    @Test
    void createRejectsReservedCorrelationMarkerWithCaseAndUnicodeWhitespace() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        CreateCertificateProfileRequest request = new CreateCertificateProfileRequest(
                "Corporate Windows", "User text ［\u00a0CeRtPiNg \n ： forged]", "source-1",
                ProfileLifecycleStatus.ACTIVE, "WINDOWS", "STANDARD",
                ProfileKind.CERTIFICATE_ENROLLMENT, "SCEP", configuration());

        assertThatThrownBy(() -> service.create(42L, 7L, request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("reserved [certping:...] correlation marker");
        verify(profileRepository, never()).saveAndFlush(any());
        verify(dispatcher, never()).publishOperation(any(), any(), any());
    }

    @Test
    void updateRejectsReservedCorrelationMarkerBeforeChangingProfile() {
        CertificateProfile profile = activeProfile();
        when(profileRepository.lockByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source()));
        UpdateCertificateProfileRequest request = new UpdateCertificateProfileRequest(
                "Corporate Windows", "[ CERTPING : forged]", ProfileLifecycleStatus.ACTIVE,
                4L, true, configuration());

        assertThatThrownBy(() -> service.update(42L, 7L, "profile-1", request))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("reserved [certping:...] correlation marker");
        assertThat(profile.getDescription()).isEqualTo("Device authentication");
        verify(profileRepository, never()).saveAndFlush(any());
        verify(dispatcher, never()).publishOperation(any(), any(), any());
    }

    @Test
    void activeProfileRequiresCertificateScopeAndValidity() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        CertificateProfileConfigurationInput missingScope = new CertificateProfileConfigurationInput(
                null, null, "RSA", 2048, null, "SHA2",
                "CN={{AAD_Device_ID}}", List.of(), List.of(), List.of("digitalSignature"),
                12, "MONTHS", 30, null,
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));

        assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(missingScope)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("certificateScope");

        CertificateProfileConfigurationInput missingValidity = new CertificateProfileConfigurationInput(
                null, "DEVICE", "RSA", 2048, null, "SHA2",
                "CN={{AAD_Device_ID}}", List.of(), List.of(), List.of("digitalSignature"),
                null, null, 30, null,
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));
        assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(missingValidity)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("validityValue and validityUnit are required");
    }

    @Test
    void sha256AliasIsPersistedAsCanonicalSha2() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source()));
        when(profileRepository.saveAndFlush(any())).thenAnswer(invocation -> {
            CertificateProfile profile = invocation.getArgument(0);
            profile.setId(100L);
            profile.setRowVersion(0L);
            return profile;
        });
        when(configurationRepository.save(any())).thenAnswer(invocation -> {
            CertificateProfileConfiguration value = invocation.getArgument(0);
            storedConfiguration.set(value);
            return value;
        });
        when(configurationRepository.findById(100L))
                .thenAnswer(invocation -> Optional.ofNullable(storedConfiguration.get()));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());
        CertificateProfileConfigurationInput alias = new CertificateProfileConfigurationInput(
                null, "DEVICE", "RSA", 2048, null, "SHA256",
                "CN={{AAD_Device_ID}}", List.of(), List.of(), List.of("digitalSignature"),
                12, "MONTHS", 30, null,
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));

        CertificateProfileResponse response = service.create(42L, 7L, activeRequest(alias));

        assertThat(response.configuration().signatureHash()).isEqualTo("SHA2");
        assertThat(storedConfiguration.get().getSignatureHash()).isEqualTo("SHA2");
    }

    @Test
    void activeIntuneProfileRejectsUnknownProviderFieldsAndMalformedNestedSettings() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        CertificateProfileConfigurationInput unknownProviderField = withNestedSettings(
                List.of(),
                List.of(Map.of("objectIdentifier", "1.3.6.1.5.5.7.3.2")),
                List.of("digitalSignature"),
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp",
                        "tenantId", "must-not-be-accepted"));

        assertThatThrownBy(() -> service.create(
                42L, 7L, activeRequest(unknownProviderField)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("providerConfig contains a field unsupported");

        CertificateProfileConfigurationInput malformedSan = withNestedSettings(
                List.of(Map.of("type", "DNS")),
                List.of(Map.of("objectIdentifier", "1.3.6.1.5.5.7.3.2")),
                List.of("digitalSignature"),
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));
        assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(malformedSan)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("type and format");
    }

    @Test
    void assignmentGroupIdsAcceptOnlyUpToTwentyEntraObjectIds() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        List<Map<String, Object>> ekus = List.of(Map.of("objectIdentifier", "1.3.6.1.5.5.7.3.2"));

        for (Object invalid : List.of(
                List.of("All devices"),
                GROUP_ID,
                java.util.Collections.nCopies(21, GROUP_ID))) {
            CertificateProfileConfigurationInput configuration = withNestedSettings(
                    List.of(), ekus, List.of("digitalSignature"),
                    Map.of("renewalThresholdPercentage", 20,
                            "keyStorageProvider", "useSoftwareKsp",
                            "assignmentGroupIds", invalid));
            assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(configuration)))
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("assignmentGroupIds");
        }
    }

    @Test
    void activeIntuneProfileRequiresValidEkuAndAtLeastOneKeyUsage() {
        when(sourceRepository.findBySourceXrefAndOrganizationId("source-1", 42L))
                .thenReturn(Optional.of(source()));
        CertificateProfileConfigurationInput emptyKeyUsage = withNestedSettings(
                List.of(), List.of(), List.of(),
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));

        assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(emptyKeyUsage)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("keyUsages must contain at least one");

        CertificateProfileConfigurationInput malformedEku = withNestedSettings(
                List.of(), List.of(Map.of("objectIdentifier", "not-an-oid")),
                List.of("digitalSignature"),
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp"));
        assertThatThrownBy(() -> service.create(42L, 7L, activeRequest(malformedEku)))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("valid objectIdentifier");
    }

    @Test
    void listCapsOnlyProfilePageSizeAndHistoricalGetDoesNotRequireProviderFlag() {
        when(profileRepository.findAll(
                any(org.springframework.data.jpa.domain.Specification.class), any(Pageable.class)))
                .thenReturn(Page.empty());

        service.list(42L, null, null, null, null, null, null,
                PageRequest.of(2, 500));

        org.mockito.ArgumentCaptor<Pageable> pageable =
                org.mockito.ArgumentCaptor.forClass(Pageable.class);
        verify(profileRepository).findAll(
                any(org.springframework.data.jpa.domain.Specification.class), pageable.capture());
        assertThat(pageable.getValue().getPageNumber()).isEqualTo(2);
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);

        CertificateProfile profile = activeProfile();
        when(profileRepository.findByProfileXrefAndOrganizationId("profile-1", 42L))
                .thenReturn(Optional.of(profile));
        when(sourceRepository.findById(10L)).thenReturn(Optional.of(source()));
        when(configurationRepository.findById(100L))
                .thenReturn(Optional.of(storedConfiguration(profile)));
        when(snapshotRepository.findById(100L)).thenReturn(Optional.empty());

        service.get(42L, "profile-1");

        verify(featureFlagService, never()).assertEnabled(
                eq(FeatureFlags.IOT_PROVIDER_INTUNE), eq(42L));
    }

    @Test
    @SuppressWarnings("unchecked")
    void profileSearchEscapesSqlLikeMetacharacters() {
        when(profileRepository.findAll(any(Specification.class), any(Pageable.class)))
                .thenReturn(Page.empty());

        service.list(42L, null, null, null, null, null, "50%_off\\today",
                PageRequest.of(0, 20));

        ArgumentCaptor<Specification<CertificateProfile>> specificationCaptor =
                ArgumentCaptor.forClass(Specification.class);
        verify(profileRepository).findAll(specificationCaptor.capture(), any(Pageable.class));
        CriteriaBuilder criteria = mock(CriteriaBuilder.class);
        CriteriaQuery<?> query = mock(CriteriaQuery.class);
        Root<CertificateProfile> root = mock(Root.class);
        Path<Object> path = mock(Path.class);
        Expression<String> lowercasePath = mock(Expression.class);
        Predicate predicate = mock(Predicate.class);
        when(root.get(anyString())).thenReturn(path);
        when(criteria.equal(any(Expression.class), eq(42L))).thenReturn(predicate);
        when(criteria.lower(any())).thenReturn(lowercasePath);
        when(criteria.like(any(), anyString(), eq('\\'))).thenReturn(predicate);
        when(criteria.or(any(Expression.class), any(Expression.class))).thenReturn(predicate);

        specificationCaptor.getValue().toPredicate(root, query, criteria);

        verify(criteria, times(2))
                .like(eq(lowercasePath), eq("%50\\%\\_off\\\\today%"), eq('\\'));
    }

    private static CertificateProfileConfigurationInput withNestedSettings(
            List<Map<String, Object>> sans,
            List<Map<String, Object>> ekus,
            List<String> keyUsages,
            Map<String, Object> providerConfig) {
        return new CertificateProfileConfigurationInput(
                null, "DEVICE", "RSA", 2048, null, "SHA2",
                "CN={{AAD_Device_ID}}", sans, ekus, keyUsages,
                12, "MONTHS", 30, null, providerConfig);
    }

    private static CreateCertificateProfileRequest activeRequest(
            CertificateProfileConfigurationInput configuration) {
        return new CreateCertificateProfileRequest(
                "Corporate Windows", "Device authentication", "source-1",
                ProfileLifecycleStatus.ACTIVE, "WINDOWS", "STANDARD",
                ProfileKind.CERTIFICATE_ENROLLMENT, "SCEP", configuration);
    }

    private static final String GROUP_ID = "8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f";

    private static CertificateProfileConfigurationInput configuration() {
        return new CertificateProfileConfigurationInput(
                null, "DEVICE", "RSA", 2048, null, "SHA2",
                "CN={{AAD_Device_ID}}", List.of(),
                List.of(Map.of("name", "Client Authentication",
                        "objectIdentifier", "1.3.6.1.5.5.7.3.2")),
                List.of("digitalSignature"), 12, "MONTHS", 30, null,
                Map.of("renewalThresholdPercentage", 20,
                        "keyStorageProvider", "useSoftwareKsp",
                        "assignmentGroupIds", List.of(GROUP_ID)));
    }

    private static CertificateProfileConfiguration storedConfiguration(CertificateProfile profile) {
        return CertificateProfileConfiguration.builder()
                .profileId(profile.getId()).organizationId(42L).deviceSourceId(10L)
                .certificateScope("DEVICE").keyAlgorithm("RSA").keySize(2048)
                .signatureHash("SHA2").subjectNameFormat("CN={{AAD_Device_ID}}")
                .subjectAltNameFormatsJson("[]")
                .extendedKeyUsagesJson("[{\"name\":\"Client Authentication\",\"objectIdentifier\":\"1.3.6.1.5.5.7.3.2\"}]")
                .keyUsagesJson("[\"digitalSignature\"]")
                .validityValue(12).validityUnit("MONTHS").renewalWindowDays(30)
                .providerConfigJson("{\"keyStorageProvider\":\"useSoftwareKsp\",\"renewalThresholdPercentage\":20}")
                .build();
    }

    private static CertificateProfile activeProfile() {
        return CertificateProfile.builder()
                .id(100L).profileXref("profile-1").organizationId(42L).deviceSourceId(10L)
                .name("Corporate Windows").description("Device authentication")
                .targetPlatform("WINDOWS").targetVariant("STANDARD")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerProfileId("native-1").providerCorrelationMarker("certping:profile-1")
                .lifecycleStatus(ProfileLifecycleStatus.ACTIVE)
                .profileOrigin(ProfileOrigin.CMS_CREATED).controlMode(ProfileControlMode.CMS_MANAGED)
                .profileKind(ProfileKind.CERTIFICATE_ENROLLMENT).enrollmentMethod("SCEP")
                .desiredRevision(1L).appliedRevision(1L)
                .providerSyncStatus(ProviderSyncStatus.IN_SYNC).rowVersion(4L)
                .build();
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder()
                .id(10L).sourceXref("source-1").organizationId(42L)
                .provider(DeviceSourceProvider.INTUNE)
                .sourceCategory(DeviceSourceCategory.ENDPOINT_MANAGEMENT)
                .connectionProfileRef("intune-primary").displayName("Primary Intune")
                .build();
    }
}
