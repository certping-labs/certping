// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.security.GatewayRequestContext;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CertExportAuditRecorderTest {

    private static final String PASSWORD = "correct horse 9";

    private final CertificateEventRepository events = mock(CertificateEventRepository.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final CertExportAuditRecorder recorder =
            new CertExportAuditRecorder(events, JsonMapper.builderWithJackson2Defaults().build(), Clock.systemUTC(), auditRecorder);

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void recordsFormatAndActor_neverPasswordHandleOrKeyMaterial() {
        GatewayRequestContext.set(7, "42", "req-1", "user@example.com");
        CertificateEntity cert = CertExportEligibilityPolicyTest.exportableCert();

        try (CertExportOptions options = CertExportOptions.from(new CertExportRequest("PKCS12", PASSWORD, true))) {
            recorder.recordExport(cert, options);
        }

        ArgumentCaptor<CertificateEventEntity> event = ArgumentCaptor.forClass(CertificateEventEntity.class);
        verify(events).save(event.capture());
        assertThat(event.getValue().getEventType()).isEqualTo("EXPORTED");
        assertThat(event.getValue().getUserId()).isEqualTo(7);
        assertThat(event.getValue().getDetails())
                .contains("\"format\":\"PKCS12\"")
                .doesNotContain(PASSWORD, cert.getCertSecretHandle(), "PRIVATE KEY", "password");

        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(auditRecorder).record(row.capture());
        assertThat(row.getValue().event()).isEqualTo("certificate.exported");
        assertThat(row.getValue().outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(row.getValue().resourceRef()).isEqualTo("cert-123");
        assertThat(row.getValue().details().attributes())
                .containsOnly(Map.entry("keyIncluded", "true"), Map.entry("legacyCipher", "true"));
        assertThat(row.getValue().toString()).doesNotContain(PASSWORD, cert.getCertSecretHandle(), "PRIVATE KEY");
    }

    @Test
    void requestedXref_isStrippedOfControlCharactersAndTruncated() {
        assertThat(CertExportAuditRecorder.sanitiseRequestedXref(null)).isNull();
        assertThat(CertExportAuditRecorder.sanitiseRequestedXref("cert-1\r\n\u0007\u0085")).isEqualTo("cert-1");
        assertThat(CertExportAuditRecorder.sanitiseRequestedXref("é".repeat(150))).isEqualTo("é".repeat(100));
    }

    /**
     * Rate-limited and not-found refusals resolved no certificate and can be repeated at will: one access row per
     * user, outcome and requested xref a minute, through the async writer.
     */
    @Test
    void rateLimitedAndNotFoundRefusalsAreThrottledAndAsync() {
        MutableClock clock = new MutableClock(java.time.Instant.parse("2026-10-08T10:00:00Z"));
        CertExportAuditRecorder throttled = new CertExportAuditRecorder(events, JsonMapper.builderWithJackson2Defaults().build(),
                clock, auditRecorder);
        GatewayRequestContext.set(7, "42", "req-1", null);

        for (int i = 0; i < 5; i++) {
            throttled.recordRateLimited(42L, 7, CertExportFormat.FULLCHAIN_PEM);
            throttled.recordNotFound(42L, CertExportFormat.PKCS12, "cert-probe");
            clock.advance(java.time.Duration.ofSeconds(10));
        }
        throttled.recordNotFound(42L, CertExportFormat.PKCS12, "cert-other");
        throttled.recordRateLimited(42L, 8, CertExportFormat.FULLCHAIN_PEM);

        ArgumentCaptor<AuditEventRow> rows = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(auditRecorder, org.mockito.Mockito.times(4)).recordFailure(rows.capture());
        verify(auditRecorder, org.mockito.Mockito.never()).recordFailureDurable(any());
        assertThat(rows.getAllValues()).extracting(AuditEventRow::event)
                .containsOnly("access.certificate_export_refused");
        assertThat(rows.getAllValues()).extracting(AuditEventRow::errorCode).containsExactly("EXPORT_RATE_LIMITED",
                "NOT_FOUND", "NOT_FOUND", "EXPORT_RATE_LIMITED");
        assertThat(rows.getAllValues().get(2).resourceRef()).isEqualTo("cert-other");

        clock.advance(java.time.Duration.ofMinutes(1));
        throttled.recordNotFound(42L, CertExportFormat.PKCS12, "cert-probe");
        verify(auditRecorder, org.mockito.Mockito.times(5)).recordFailure(any());
    }
}
