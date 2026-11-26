// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static com.certmanagement.service.cert.CertPingDnsKeysTest.certPing;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertPingDnsKeyExpiryNoticesTest {

    private static final Instant NOW = Instant.parse("2026-10-20T12:00:00Z");

    @Mock private CredentialReferenceRepository credentials;
    @Mock private OrganizationRepository organizations;
    @Mock private ObjectProvider<OrgAdminNotificationPublisher> publisherProvider;
    @Mock private OrgAdminNotificationPublisher publisher;
    @Mock private SchedulerExecutionPolicy executionPolicy;

    private CertPingDnsKeyExpiryNotices notices;

    @BeforeEach
    void setUp() {
        notices = new CertPingDnsKeyExpiryNotices(credentials,
                new CertPingDnsKeys(credentials, JsonMapper.builderWithJackson2Defaults().findAndAddModules().build()), organizations,
                publisherProvider, executionPolicy, Clock.fixed(NOW, ZoneOffset.UTC));
        lenient().when(executionPolicy.canRun(CertPingDnsKeyExpiryNotices.JOB_NAME)).thenReturn(true);
        lenient().when(publisherProvider.getIfAvailable()).thenReturn(publisher);
        lenient().when(organizations.findNameById(anyLong())).thenReturn(Optional.of("Acme Ltd"));
    }

    @Test
    void aKeyExpiringWithinThirtyDaysIsAnnouncedDeliverOnceToTheOrgAdminsWithTheContractFields() {
        CredentialReferenceEntity key = certPing("cred-1", 7L, "2026-11-10T08:00:00Z");
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(key));

        notices.warnExpiringKeys();

        String idempotencyKey = "certping-dns-key-expiring:" + key.getId() + ":"
                + Instant.parse("2026-11-10T08:00:00Z").getEpochSecond() + ":30";
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishOnceToOrgAdmins(eq("CERTPING_DNS_KEY_EXPIRING"), eq("7"), eq("certping-cert-manager"),
                fields.capture(), eq(idempotencyKey));
        assertThat(fields.getValue())
                .containsEntry("organizationId", 7L)
                .containsEntry("organizationName", "Acme Ltd")
                .containsEntry("credentialName", "CertPing DNS for cred-1")
                .containsEntry("tokenPrefix", "cpk_live_ab12cd34")
                .containsEntry("expiresAt", "2026-11-10T08:00:00Z")
                .containsEntry("leadDays", 30)
                .containsEntry("idempotencyKey", idempotencyKey)
                .hasSize(7);
    }

    @Test
    void aKeyExpiringWithinSevenDaysGetsTheLastNoticeUnderItsOwnKey() {
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(certPing("cred-1", 7L, "2026-10-27T12:00:00Z")));

        notices.warnExpiringKeys();

        verify(publisher).publishOnceToOrgAdmins(anyString(), anyString(), anyString(),
                argThat(fields -> Integer.valueOf(7).equals(fields.get("leadDays"))),
                endsWith(":7"));
    }

    @Test
    void keysAlreadyExpiredOrExpiringAfterThirtyDaysAreNotAnnounced() {
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(certPing("expired", 7L, "2026-10-20T12:00:00Z"),
                        certPing("later", 7L, "2026-11-19T12:00:01Z"),
                        certPing("no-details", 7L, null)));

        notices.warnExpiringKeys();

        verifyNoInteractions(publisher);
    }

    @Test
    void aKeyExpiringExactlyThirtyDaysAheadGetsTheFirstNotice() {
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(certPing("edge", 7L, "2026-11-19T12:00:00Z")));

        notices.warnExpiringKeys();

        verify(publisher).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), endsWith(":30"));
    }

    @Test
    void everyPageIsReadAfterTheLastIdOfTheOneBefore() {
        List<CredentialReferenceEntity> full = IntStream.range(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)
                .mapToObj(i -> withId(certPing("cred-" + i, 7L, "2026-11-10T08:00:00Z"), i + 1L)).toList();
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(full);
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", (long) CertPingDnsKeyExpiryNotices.PAGE_SIZE,
                PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(withId(certPing("cred-last", 7L, "2026-11-10T08:00:00Z"), 1_000L)));

        notices.warnExpiringKeys();

        verify(publisher, times(CertPingDnsKeyExpiryNotices.PAGE_SIZE + 1))
                .publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void aFailedPublishLeavesTheNoticeForTheNextRunAndTheOthersStillGoOut() {
        CredentialReferenceEntity failing = withId(certPing("cred-1", 7L, "2026-11-10T08:00:00Z"), 1L);
        CredentialReferenceEntity next = withId(certPing("cred-2", 8L, "2026-11-10T08:00:00Z"), 2L);
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(failing, next));
        doThrow(new IllegalStateException("queue down")).when(publisher)
                .publishOnceToOrgAdmins(anyString(), eq("7"), anyString(), any(), anyString());

        notices.warnExpiringKeys();

        verify(publisher).publishOnceToOrgAdmins(anyString(), eq("8"), anyString(), any(), anyString());
    }

    @Test
    void aKeyWhoseDetailsCannotBeReadIsSkipped() {
        CredentialReferenceEntity unreadable = certPing("cred-1", 7L, null);
        unreadable.setConfigJson("{\"expiresAt\":\"soon\"}");
        when(credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", 0L, PageRequest.of(0, CertPingDnsKeyExpiryNotices.PAGE_SIZE)))
                .thenReturn(List.of(unreadable));

        notices.warnExpiringKeys();

        verifyNoInteractions(publisher);
    }

    @Test
    void nothingIsReadWithoutANotificationSender() {
        when(publisherProvider.getIfAvailable()).thenReturn(null);

        notices.warnExpiringKeys();

        verifyNoInteractions(credentials);
    }

    @Test
    void nothingRunsWhileTheJobIsSwitchedOff() {
        when(executionPolicy.canRun(CertPingDnsKeyExpiryNotices.JOB_NAME)).thenReturn(false);

        notices.warnExpiringKeys();

        verifyNoInteractions(credentials, publisher);
    }

    private static CredentialReferenceEntity withId(CredentialReferenceEntity credential, long id) {
        credential.setId(id);
        return credential;
    }
}
