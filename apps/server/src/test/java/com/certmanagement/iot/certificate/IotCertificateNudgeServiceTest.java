// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.config.IotDeviceSyncProperties;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileConfigurationRepository;
import com.certmanagement.iot.profile.CertificateProfileJsonCodec;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.service.OrgTypeResolver;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateNudgeServiceTest {

    private static final long ORG = 42L;
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-28T12:00:00Z"), ZoneOffset.UTC);
    private static final OffsetDateTime NOW = OffsetDateTime.now(CLOCK);

    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private CertificateProfileConfigurationRepository configurationRepository;
    @Mock private IotDeviceSyncSelectionService selectionService;
    @Mock private IotDeviceSyncRequestRecorder requestRecorder;
    @Mock private IotDeviceSyncCommandPublisher commandPublisher;
    @Mock private OrgTypeResolver orgTypeResolver;

    private IotDeviceSyncProperties properties;
    private IotCertificateNudgeService service;

    @BeforeEach
    void setUp() {
        properties = new IotDeviceSyncProperties();
        properties.setCooldown(Duration.ofMinutes(15));
        service = new IotCertificateNudgeService(
                certificateRepository, sourceRepository, configurationRepository,
                selectionService,
                new IntuneRenewalEligibilityPolicy(
                        new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build())),
                requestRecorder, commandPublisher, orgTypeResolver, properties, CLOCK);
    }

    @Test
    void oneDeviceWithTwoEligibleProfilesProducesOneDeviceSyncCommand() {
        IotDevice device = device();
        IotDeviceCertificate first = certificate(10L, "crt-1", NOW.minusDays(90), NOW.plusDays(10));
        IotDeviceCertificate second = certificate(11L, "crt-2", NOW.minusDays(90), NOW.plusDays(10));
        prepare(device, List.of(first, second), List.of(configuration(10L), configuration(11L)));
        when(orgTypeResolver.resolve(ORG)).thenReturn("B2B");

        DeviceSyncResponse response = service.requestDeviceSync(
                ORG, false, new DeviceSyncRequest(List.of("dev-1")));

        assertThat(response.queuedDevices()).isEqualTo(1);
        assertThat(response.devices()).singleElement().satisfies(result ->
                assertThat(result.certificateXrefs()).containsExactly("crt-1", "crt-2"));
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<IotDeviceSyncCommand>> commands = ArgumentCaptor.forClass(List.class);
        verify(commandPublisher).publishAfterCommit(commands.capture());
        assertThat(commands.getValue()).singleElement().satisfies(command -> {
            assertThat(command.getManagedDeviceId())
                    .isEqualTo("11111111-1111-1111-1111-111111111111");
            assertThat(command.getCertificateXrefs()).containsExactly("crt-1", "crt-2");
            assertThat(command.getRequestedAt()).isEqualTo(NOW.toString());
        });
        verify(requestRecorder, times(2)).record(
                any(), eq(commands.getValue().getFirst().getRequestId()), eq(NOW));
    }

    @Test
    void outsideThresholdIsReportedAndNeverPublished() {
        IotDevice device = device();
        IotDeviceCertificate certificate = certificate(
                10L, "crt-1", NOW.minusDays(10), NOW.plusDays(80));
        prepare(device, List.of(certificate), List.of(configuration(10L)));

        DeviceSyncResponse response = service.requestDeviceSync(
                ORG, false, new DeviceSyncRequest(List.of("dev-1")));

        assertThat(response.queuedDevices()).isZero();
        assertThat(response.devices()).singleElement().satisfies(result -> {
            assertThat(result.reason()).isEqualTo("OUTSIDE_RENEWAL_THRESHOLD");
            assertThat(result.nextAllowedAt()).isEqualTo(NOW.plusDays(62));
        });
        verify(commandPublisher).publishAfterCommit(List.of());
        verify(requestRecorder, never()).record(any(), any(), any());
    }

    @Test
    void missingProfileThresholdDoesNotUseAThirtyDayFallback() {
        IotDevice device = device();
        IotDeviceCertificate certificate = certificate(
                10L, "crt-1", NOW.minusDays(89), NOW.plusDays(1));
        prepare(device, List.of(certificate), List.of());

        DeviceSyncResponse response = service.requestDeviceSync(
                ORG, false, new DeviceSyncRequest(List.of("dev-1")));

        assertThat(response.devices().getFirst().reason())
                .isEqualTo("PROFILE_THRESHOLD_UNAVAILABLE");
        verify(requestRecorder, never()).record(any(), any(), any());
    }

    @Test
    void cooldownPreventsRepeatedPrivilegedActions() {
        IotDevice device = device();
        IotDeviceCertificate certificate = certificate(
                10L, "crt-1", NOW.minusDays(90), NOW.plusDays(10));
        certificate.setLastNudgedAt(NOW.minusMinutes(5));
        prepare(device, List.of(certificate), List.of(configuration(10L)));

        DeviceSyncResponse response = service.requestDeviceSync(
                ORG, false, new DeviceSyncRequest(List.of("dev-1")));

        assertThat(response.devices().getFirst().reason()).isEqualTo("COOLDOWN_ACTIVE");
        assertThat(response.devices().getFirst().nextAllowedAt()).isEqualTo(NOW.plusMinutes(10));
        verify(requestRecorder, never()).record(any(), any(), any());
    }

    @Test
    void nonIntuneSourceIsNeverSentToTheAgent() {
        IotDevice device = device();
        IotDeviceSource source = source();
        source.setProvider(DeviceSourceProvider.JAMF);
        when(selectionService.select(eq(ORG), eq(false), any())).thenReturn(
                new IotDeviceSyncSelectionService.Selection(1, List.of(device), List.of()));
        when(certificateRepository.findCurrentForDeviceSync(ORG, List.of(7L), NOW))
                .thenReturn(List.of());
        when(sourceRepository.findAllById(List.of(3L))).thenReturn(List.of(source));

        DeviceSyncResponse response = service.requestDeviceSync(
                ORG, false, new DeviceSyncRequest(List.of("dev-1")));

        assertThat(response.devices().getFirst().reason())
                .isEqualTo("UNSUPPORTED_OR_INACTIVE_SOURCE");
        verify(requestRecorder, never()).record(any(), any(), any());
    }

    private void prepare(
            IotDevice device,
            List<IotDeviceCertificate> certificates,
            List<CertificateProfileConfiguration> configurations) {
        when(selectionService.select(eq(ORG), eq(false), any())).thenReturn(
                new IotDeviceSyncSelectionService.Selection(1, List.of(device), List.of()));
        when(certificateRepository.findCurrentForDeviceSync(ORG, List.of(device.getId()), NOW))
                .thenReturn(certificates);
        when(configurationRepository.findAllById(any())).thenReturn(configurations);
        when(sourceRepository.findAllById(List.of(device.getDeviceSourceId())))
                .thenReturn(List.of(source()));
    }

    private static IotDevice device() {
        return IotDevice.builder().id(7L).organizationId(ORG).deviceSourceId(3L)
                .deviceXref("dev-1")
                .sourceDeviceId("11111111-1111-1111-1111-111111111111")
                .build();
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder().id(3L).organizationId(ORG).sourceXref("source-1")
                .provider(DeviceSourceProvider.INTUNE).status(DeviceSourceStatus.ACTIVE)
                .connectionProfileRef("intune-primary").build();
    }

    private static IotDeviceCertificate certificate(
            long profileId, String xref, OffsetDateTime validFrom, OffsetDateTime validTo) {
        return IotDeviceCertificate.builder().id(profileId).organizationId(ORG).deviceId(7L)
                .deviceSourceId(3L).profileId(profileId).certificateXref(xref)
                .validFrom(validFrom).validTo(validTo).renewalState("NONE").nudgeAttempts(0)
                .build();
    }

    private static CertificateProfileConfiguration configuration(long profileId) {
        return CertificateProfileConfiguration.builder().profileId(profileId)
                .providerConfigJson("{\"renewalThresholdPercentage\":20}").build();
    }
}
