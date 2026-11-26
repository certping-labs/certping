// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.dto.common.ErrorResponse;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.security.Permissions;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Refused exports are audited as FAILURE rows (never 400s, never timeline events), through the real
 * limiter, policy and recorder; only Redis, the store, the repositories and the audit sink are mocked.
 */
class CertificateExportRefusalAuditTest {

    private static final long ORG_ID = 42L;
    private static final int USER_ID = 7;
    private static final String PASSWORD = "correct horse 9";
    private static final Set<String> DEPLOYER = Set.of(Permissions.CERTIFICATE_READ, Permissions.CERTIFICATE_DEPLOY);
    private static final CertExportTestMaterial.Chain CHAIN = chainFor("*.example.com", RSA_LEAF_KEYS);

    private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
    private final AgentSecretStore store = mock(AgentSecretStore.class);
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final CertificateEventRepository events = mock(CertificateEventRepository.class);
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-06T12:15:00Z"));
    private CertificateExportService service;
    private CertificateEntity cert;

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

        cert = CertExportEligibilityPolicyTest.exportableCert();
        cert.setFingerprintSha256(fingerprint(CHAIN.leaf()));
        cert.setValidTo(OffsetDateTime.now().plusDays(30));
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID)).thenReturn(Optional.of(cert));
        when(store.isReady()).thenReturn(true);
        when(store.isAgentCertificateHandle(HANDLE, XREF)).thenReturn(true);
        when(store.read(HANDLE)).thenReturn(agentBundle(CHAIN, true));
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(1L);
    }

    @Test
    void notFound_isAuditedUnderTheCallersOrg_withNoResourceId_andTheSanitisedXref() {
        String requested = "other-org-cert\u0000\n\u001b[2J" + "x".repeat(200);

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, requested, pkcs12()))
                .isInstanceOf(ResourceNotFoundException.class);

        AuditEventRow row = singleRefusal(null);
        assertThat(row.errorCode()).isEqualTo("NOT_FOUND");
        String recordedXref = row.resourceRef();
        assertThat(recordedXref).hasSize(CertExportAuditRecorder.MAX_REQUESTED_XREF_LENGTH)
                .startsWith("other-org-cert[2J").doesNotContain("\u0000", "\n", "\u001b");
        verify(certificateRepository).findByCertificateXrefAndOrganizationId(requested, ORG_ID);
        verifyNoMoreInteractions(certificateRepository);
        verifyNoInteractions(store, events);
    }

    @Test
    void notExportable_isAuditedWithItsReason() {
        when(store.isAgentCertificateHandle(HANDLE, XREF)).thenReturn(false);

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, pkcs12()))
                .isInstanceOf(CertExportException.class);

        assertThat(singleRefusal(9L).errorCode()).isEqualTo("CERT_NOT_EXPORTABLE");
    }

    @Test
    void goneMaterial_isAudited() {
        when(store.read(HANDLE)).thenThrow(new AgentSecretGoneException("destroyed " + HANDLE, null));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOf(CertExportException.class);

        assertThat(singleRefusal(9L).errorCode()).isEqualTo("CERT_MATERIAL_GONE");
    }

    @Test
    void materialMismatch_isAudited() {
        cert.setFingerprintSha256(fingerprint(chainFor("other.example.com", RSA_LEAF_KEYS).leaf()));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("PRIVATE_KEY_PEM")))
                .isInstanceOf(CertExportException.class);

        assertThat(singleRefusal(9L).errorCode()).isEqualTo("CERT_MATERIAL_MISMATCH");
    }

    @Test
    void secretStoreOutage_isAuditedOnEveryAttempt() {
        when(store.read(HANDLE)).thenThrow(new IllegalStateException("vault 500"));

        for (int attempt = 0; attempt < 3; attempt++) {
            assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, pkcs12()))
                    .isInstanceOf(ServiceUnavailableException.class);
        }

        assertThat(refusals(3, 9L)).extracting(AuditEventRow::errorCode).containsOnly("EXPORT_UNAVAILABLE");
    }

    @Test
    @SuppressWarnings("unchecked")
    void rateLimited_writesExactlyOneRowPerWindowHoweverManyRefusals() {
        when(redis.execute(any(RedisScript.class), anyList(), any())).thenReturn(31L, 32L, 33L, 34L);

        for (int attempt = 0; attempt < 4; attempt++) {
            assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                    .isInstanceOfSatisfying(CertExportException.class,
                            e -> assertThat(e.getCode()).isEqualTo("EXPORT_RATE_LIMITED"));
        }

        assertThat(singleRefusal(null).errorCode()).isEqualTo("EXPORT_RATE_LIMITED");
        verifyNoInteractions(certificateRepository);
    }

    @Test
    @SuppressWarnings("unchecked")
    void limiterOutage_refusesPkcs12With503AndNoRetryAfter_auditingAtMostOncePerUserPerMinute() {
        when(redis.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new RedisConnectionFailureException("down"));

        ServiceUnavailableException refused = refuseWithLimiterOutage(USER_ID);
        refuseWithLimiterOutage(USER_ID);
        refuseWithLimiterOutage(USER_ID);
        refusals(1, null);

        clock.advance(Duration.ofSeconds(61));
        refuseWithLimiterOutage(USER_ID);
        refuseWithLimiterOutage(8);
        assertThat(refusals(3, null)).extracting(AuditEventRow::errorCode).containsOnly("EXPORT_UNAVAILABLE");

        ResponseEntity<ErrorResponse> response = new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build())
                .handleServiceUnavailable(refused, new MockHttpServletRequest("POST", "/api/v1/certs/cert-123/export"));
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(response.getHeaders().containsHeader(HttpHeaders.RETRY_AFTER)).isFalse();
        assertThat(refused.getMessage()).isEqualTo(
                "Downloads that include the private key are temporarily unavailable. Try again shortly.");
        verifyNoInteractions(certificateRepository, store);
    }

    @Test
    @SuppressWarnings("unchecked")
    void limiterOutage_stillServesTheFullChain() {
        when(redis.execute(any(RedisScript.class), anyList(), any()))
                .thenThrow(new RedisConnectionFailureException("down"));

        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM"));

        assertThat(file.fileName()).isEqualTo("_wildcard.example.com-fullchain.pem");
        verify(auditRecorder, never()).recordFailureDurable(any());
        verify(auditRecorder, never()).recordFailure(any());
    }

    @Test
    void invalidRequest_isNotAudited() {
        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF,
                new CertExportRequest("PKCS12", "pässwordx", null)))
                .isInstanceOf(CertExportException.class);

        verifyNoInteractions(events, auditRecorder);
    }

    private ServiceUnavailableException refuseWithLimiterOutage(int userId) {
        try {
            service.export(ORG_ID, userId, DEPLOYER, XREF, pkcs12());
        } catch (ServiceUnavailableException e) {
            return e;
        }
        throw new AssertionError("expected a 503");
    }

    private AuditEventRow singleRefusal(Long resourceId) {
        return refusals(1, resourceId).get(0);
    }

    /**
     * The FAILURE rows written so far, each under the caller's org, and checked for secrets. A
     * refusal never writes a timeline event.
     */
    private List<AuditEventRow> refusals(int expectedRows, Long resourceId) {
        verify(events, never()).save(any());
        // Each refusal is also its one failure row, written durably, its reason the outcome: the certificate's
        // certificate.exported failure, or access.certificate_export_refused when no certificate was resolved.
        // Durably, or, for the rate-limited and not-found refusals (no certificate, repeatable at will), through the
        // async writer, throttled.
        List<AuditEventRow> written = org.mockito.Mockito.mockingDetails(auditRecorder).getInvocations().stream()
                .filter(call -> call.getMethod().getName().equals("recordFailureDurable")
                        || call.getMethod().getName().equals("recordFailure"))
                .map(call -> (AuditEventRow) call.getArgument(0)).toList();
        assertThat(written).hasSize(expectedRows);
        assertThat(written).allSatisfy(row -> assertThat(org.mockito.Mockito.mockingDetails(auditRecorder)
                .getInvocations().stream().filter(call -> call.getArgument(0) == row).findFirst().orElseThrow()
                .getMethod().getName()).isEqualTo(List.of("NOT_FOUND", "EXPORT_RATE_LIMITED").contains(row.errorCode())
                        ? "recordFailure" : "recordFailureDurable"));
        verify(auditRecorder, never()).record(any());
        assertThat(written).allSatisfy(row -> {
            assertThat(row.event()).isEqualTo(resourceId == null ? "access.certificate_export_refused"
                    : "certificate.exported");
            assertThat(row.outcome()).isEqualTo(AuditOutcome.FAILURE);
            assertThat(row.organizationId()).isEqualTo(ORG_ID);
            assertThat(row.resourceId()).isEqualTo(resourceId);
            assertThat(row.toString()).doesNotContain(PASSWORD, HANDLE, "PRIVATE KEY", "BEGIN", "password");
        });
        return written;
    }

    private static CertExportRequest pkcs12() {
        return new CertExportRequest("PKCS12", PASSWORD, false);
    }

    private static CertExportRequest request(String format) {
        return new CertExportRequest(format, null, null);
    }
}
