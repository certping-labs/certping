// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.security.Permissions;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.certmanagement.service.cert.export.CertExportEligibilityPolicyTest.HANDLE;
import static com.certmanagement.service.cert.export.CertExportEligibilityPolicyTest.XREF;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.RSA_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.agentBundle;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.chainFor;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.fingerprint;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Formats carrying the private key need {@code certificate:deploy} on top of {@code certificate:read}.
 * Runs through the real limiter, policy and recorder; only Redis, the store, the repositories and
 * the audit sink are mocked.
 */
class CertificateExportKeyPermissionTest {

    private static final long ORG_ID = 42L;
    private static final int USER_ID = 7;
    private static final String PASSWORD = "correct horse 9";
    private static final Set<String> VIEWER = Set.of(Permissions.CERTIFICATE_READ);
    private static final Set<String> DEPLOYER = Set.of(Permissions.CERTIFICATE_READ, Permissions.CERTIFICATE_DEPLOY);
    private static final CertExportTestMaterial.Chain CHAIN = chainFor("*.example.com", RSA_LEAF_KEYS);

    private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
    private final AgentSecretStore store = mock(AgentSecretStore.class);
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final CertificateEventRepository events = mock(CertificateEventRepository.class);
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-06T12:15:00Z"));
    private CertificateExportService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("agentSecretStore", store);
        service = new CertificateExportService(certificateRepository,
                new CertExportEligibilityPolicy(beans.getBeanProvider(AgentSecretStore.class), clock),
                beans.getBeanProvider(AgentSecretStore.class),
                new CertExportRateLimiter(redis, new SimpleMeterRegistry(), clock),
                new CertExportAuditRecorder(events, JsonMapper.builderWithJackson2Defaults().build(), clock, auditRecorder));

        var cert = CertExportEligibilityPolicyTest.exportableCert();
        cert.setFingerprintSha256(fingerprint(CHAIN.leaf()));
        cert.setValidTo(OffsetDateTime.now().plusDays(30));
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID)).thenReturn(Optional.of(cert));
        when(store.isReady()).thenReturn(true);
        when(store.isAgentCertificateHandle(HANDLE, XREF)).thenReturn(true);
        when(store.read(HANDLE)).thenReturn(agentBundle(CHAIN, true));
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(1L);
    }

    @ParameterizedTest
    @ValueSource(strings = {"PRIVATE_KEY_PEM", "PKCS12"})
    void viewer_isRefusedKeyFormatsWith403_beforeAnyTokenLookupOrVaultRead(String format) {
        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, VIEWER, XREF, request(format)))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getStatus().value()).isEqualTo(403);
                    assertThat(e.getCode()).isEqualTo(CertExportException.EXPORT_KEY_NOT_PERMITTED);
                });

        assertThat(keyRefusals(1)).singleElement().satisfies(row -> assertThat(row.details().attributes())
                .containsOnly(entry("keyIncluded", "true")));
        verifyNoInteractions(redis, certificateRepository, store, events);
        verify(auditRecorder, never()).record(any());
    }

    @Test
    void viewer_stillDownloadsTheCertificateAndChain() {
        assertThat(service.export(ORG_ID, USER_ID, VIEWER, XREF, request("FULLCHAIN_PEM")).fileName())
                .isEqualTo("_wildcard.example.com-fullchain.pem");
        assertThat(service.export(ORG_ID, USER_ID, VIEWER, XREF, request("CERTIFICATE_PEM")).fileName())
                .isEqualTo("_wildcard.example.com-cert.pem");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PRIVATE_KEY_PEM", "PKCS12"})
    void deployHolder_downloadsKeyFormats(String format) {
        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request(format));

        assertThat(file.content()).isNotEmpty();
        verify(store).read(HANDLE);
        verify(auditRecorder).record(any());
    }

    @Test
    void permissionMatchIsExact() {
        Set<String> nearMisses = Set.of(Permissions.CERTIFICATE_READ, "CERTIFICATE:DEPLOY", "certificate:deploy:all",
                "certificate:*", "ROLE_CERT_MANAGER");

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, nearMisses, XREF, request("PRIVATE_KEY_PEM")))
                .isInstanceOfSatisfying(CertExportException.class,
                        e -> assertThat(e.getCode()).isEqualTo(CertExportException.EXPORT_KEY_NOT_PERMITTED));
    }

    @Test
    void invalidRequest_is400BeforeThePermissionCheck() {
        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, VIEWER, XREF,
                new CertExportRequest("PKCS12", "short", null)))
                .isInstanceOfSatisfying(CertExportException.class,
                        e -> assertThat(e.getCode()).isEqualTo(CertExportException.INVALID_EXPORT_REQUEST));
    }

    @Test
    void repeated403s_writeAtMostOneRowPerUserPerMinute() {
        for (int attempt = 0; attempt < 5; attempt++) {
            refuseKeyExport(USER_ID);
        }
        keyRefusals(1);

        refuseKeyExport(8);
        clock.advance(Duration.ofSeconds(61));
        refuseKeyExport(USER_ID);
        refuseKeyExport(USER_ID);

        assertThat(keyRefusals(3)).hasSize(3);
        verifyNoInteractions(redis, certificateRepository, store);
    }

    private void refuseKeyExport(int userId) {
        assertThatThrownBy(() -> service.export(ORG_ID, userId, VIEWER, XREF, request("PKCS12")))
                .isInstanceOf(CertExportException.class);
    }

    /** The FAILURE rows written so far: refused before the lookup, the access event naming no certificate. */
    private List<AuditEventRow> keyRefusals(int expectedRows) {
        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(auditRecorder, times(expectedRows)).recordFailureDurable(rows.capture());
        assertThat(rows.getAllValues()).allSatisfy(row -> {
            assertThat(row.event()).isEqualTo("access.certificate_export_refused");
            assertThat(row.category()).isEqualTo("ACCESS");
            assertThat(row.errorCode()).isEqualTo("EXPORT_KEY_NOT_PERMITTED");
            assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
            assertThat(row.resourceRef()).isNull();
            assertThat(row.resourceId()).isNull();
            assertThat(row.organizationId()).isEqualTo(ORG_ID);
            assertThat(row.toString()).doesNotContain(PASSWORD, HANDLE, XREF, "password");
        });
        return rows.getAllValues();
    }

    private static CertExportRequest request(String format) {
        return format.equals("PKCS12")
                ? new CertExportRequest(format, PASSWORD, false)
                : new CertExportRequest(format, null, null);
    }
}
