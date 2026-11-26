// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CertificateEventEntity;
import com.certmanagement.enums.CertEventType;
import com.certmanagement.enums.EventSource;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.util.MdcIds;
import tools.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

/**
 * Records export attempts in the audit trail as {@code certificate.exported}; a refusal before any certificate was
 * resolved is the access event {@code access.certificate_export_refused} instead. Rows hold the format, whether the
 * private key was included and the outcome only: never key material, file content, passwords or the secret handle.
 *
 * <p>A completed export is written in one short transaction opened after the secret-store read, with a matching
 * event on the certificate's timeline ({@link AuditRecorder#record}). A refused one (403, 404, 409, 410, 429, 502,
 * 503; never 400) is a failure row only, its reason the code the export answered with, written durably in a short
 * transaction of its own after the refusal ({@link AuditRecorder#recordFailureDurable}); it puts nothing on the
 * timeline. Refusals a caller can repeat at will are throttled per user (below); the rate-limited and not-found ones,
 * which resolved no certificate, are written through the async writer instead, at most once per user, outcome and
 * requested xref a minute.
 */
@Component
public class CertExportAuditRecorder {

    static final String OUTCOME_NOT_FOUND = "NOT_FOUND";
    static final String OUTCOME_UNAVAILABLE = "EXPORT_UNAVAILABLE";
    static final int MAX_REQUESTED_XREF_LENGTH = 100;
    /**
     * Refusals that are not rate limited (a limiter outage, a missing key permission) can be repeated
     * as fast as the caller likes; one row per user per minute is enough to show it happened.
     */
    private static final Duration THROTTLED_REFUSAL_AUDIT_EVERY = Duration.ofMinutes(1);
    /** Bounds each throttle's memory whatever the number of distinct users being refused. */
    private static final int THROTTLED_REFUSAL_MAX_USERS = 10_000;

    private final CertificateEventRepository certificateEventRepository;
    private final ObjectMapper objectMapper;
    private final ConcurrentMap<Integer, Boolean> recentLimiterOutageAudits;
    private final ConcurrentMap<Integer, Boolean> recentKeyNotPermittedAudits;
    /** Rate-limited and not-found refusals, keyed by user, outcome and the xref asked for. */
    private final ConcurrentMap<String, Boolean> recentAccessRefusals;
    private final AuditRecorder recorder;

    public CertExportAuditRecorder(CertificateEventRepository certificateEventRepository, ObjectMapper objectMapper,
                                   Clock clock, AuditRecorder recorder) {
        this.recorder = recorder;
        this.certificateEventRepository = certificateEventRepository;
        this.objectMapper = objectMapper;
        this.recentLimiterOutageAudits = perUserThrottle(clock);
        this.recentKeyNotPermittedAudits = perUserThrottle(clock);
        this.recentAccessRefusals = Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(THROTTLED_REFUSAL_AUDIT_EVERY)
                .maximumSize(THROTTLED_REFUSAL_MAX_USERS)
                .<String, Boolean>build()
                .asMap();
    }

    private static ConcurrentMap<Integer, Boolean> perUserThrottle(Clock clock) {
        return Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(THROTTLED_REFUSAL_AUDIT_EVERY)
                .maximumSize(THROTTLED_REFUSAL_MAX_USERS)
                .<Integer, Boolean>build()
                .asMap();
    }

    @Transactional
    public void recordExport(CertificateEntity cert, CertExportOptions options) {
        Map<String, Object> details = exportDetails(cert, options);
        recorder.record(AuditEvents.success(AuditEventType.CERTIFICATE_EXPORTED, subject(cert, options.format(),
                options.legacyPkcs12()).build()));
        certificateEventRepository.save(CertificateEventEntity.builder()
                .certificateXref(cert.getCertificateXref())
                .organizationId(cert.getOrganizationId())
                .eventType(CertEventType.EXPORTED.name())
                .userId(GatewayRequestContext.getUserId())
                .requestId(MdcIds.requestId())
                .correlationId(MdcIds.correlationId())
                .source(EventSource.CERT_MANAGER.value())
                .details(toJson(details))
                .build());
    }

    /**
     * Audits a refusal of an export that resolved {@code cert} in the caller's org, or that was
     * refused before any lookup ({@code cert} null, as for 429).
     *
     * @param outcome the error code returned to the caller
     */
    public void recordRefusal(Long organizationId, CertificateEntity cert, CertExportFormat format, String outcome) {
        // A refusal of a resolved certificate is that certificate's certificate.exported failure; one with no
        // certificate (403 key not permitted, 429, 503 limiter outage) is the access event
        // access.certificate_export_refused instead, never both: one refusal, one row.
        if (cert != null) {
            refused(AuditEventType.CERTIFICATE_EXPORTED, subject(cert, format, false).organizationId(organizationId),
                    outcome);
        } else {
            refused(AuditEventType.ACCESS_CERTIFICATE_EXPORT_REFUSED, AuditSubject.builder()
                    .organizationId(organizationId).format(format.name()).attributes(keyIncluded(format)), outcome);
        }
    }

    /**
     * Audits a 429 refusal ({@code access.certificate_export_refused}), at most once per user per minute, through the
     * async writer: a caller can repeat it at will, and nothing was exported.
     */
    public void recordRateLimited(Long organizationId, Integer userId, CertExportFormat format) {
        if (!firstAccessRefusal(userId, CertExportException.EXPORT_RATE_LIMITED, null)) {
            return;
        }
        AuditEventRow row = AuditEvents.failure(AuditEventType.ACCESS_CERTIFICATE_EXPORT_REFUSED, AuditSubject.builder()
                .organizationId(organizationId).format(format.name()).attributes(keyIncluded(format)).build(),
                AuditReason.of(CertExportException.EXPORT_RATE_LIMITED));
        recorder.recordFailure(row);
    }

    /**
     * Audits a 404 under the caller's org. Nothing is resolved from another org: the row carries no
     * resource id, only the xref the caller sent, stripped of control characters and truncated. At most once per
     * user and xref a minute, through the async writer: probing for certificates can be repeated at will.
     */
    public void recordNotFound(Long callerOrganizationId, CertExportFormat format, String requestedXref) {
        String requested = sanitiseRequestedXref(requestedXref);
        if (!firstAccessRefusal(GatewayRequestContext.getUserId(), OUTCOME_NOT_FOUND, requested)) {
            return;
        }
        // A refusal with no certificate: the access event, not certificate.exported (see recordRefusal).
        AuditEventRow row = AuditEvents.failure(AuditEventType.ACCESS_CERTIFICATE_EXPORT_REFUSED, AuditSubject.builder()
                .organizationId(callerOrganizationId).resourceRef(requested).format(format.name())
                .attributes(keyIncluded(format)).build(), AuditReason.of(OUTCOME_NOT_FOUND));
        recorder.recordFailure(row);
    }

    /**
     * Whether this rate-limited or not-found refusal is the first of its kind (user, outcome, xref) this minute; the
     * rest are not audited.
     */
    private boolean firstAccessRefusal(Integer userId, String outcome, String requestedXref) {
        String key = userId + "|" + outcome + "|" + (requestedXref == null ? "" : requestedXref);
        return recentAccessRefusals.putIfAbsent(key, Boolean.TRUE) == null;
    }

    /**
     * Writes a refusal's row now, after the refusal's own work: it must be on record before the refusal is
     * answered. A row that cannot be written is counted ({@code certping_audit_dropped_total{reason=write_failed}}).
     */
    private void refused(AuditEventType type, AuditSubject.AuditSubjectBuilder subject, String outcome) {
        recorder.recordFailureDurable(AuditEvents.failure(type, subject.build(), AuditReason.of(outcome)));
    }

    private static AuditSubject.AuditSubjectBuilder subject(CertificateEntity cert, CertExportFormat format,
                                                            boolean legacyCipher) {
        Map<String, String> attributes = keyIncluded(format);
        if (format == CertExportFormat.PKCS12 && legacyCipher) {
            attributes.put("legacyCipher", "true");
        }
        return AuditSubject.builder().organizationId(cert.getOrganizationId()).resourceId(cert.getId())
                .resourceRef(cert.getCertificateXref()).domain(cert.getDomain()).format(format.name())
                .attributes(attributes);
    }

    private static Map<String, String> keyIncluded(CertExportFormat format) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("keyIncluded", Boolean.toString(format.includesPrivateKey()));
        return attributes;
    }

    /** Audits a 503 from the rate limiter being unreachable, at most once per user per minute. */
    public void recordLimiterUnavailable(Long organizationId, Integer userId, CertExportFormat format) {
        if (recentLimiterOutageAudits.putIfAbsent(userId, Boolean.TRUE) == null) {
            recordRefusal(organizationId, null, format, OUTCOME_UNAVAILABLE);
        }
    }

    /**
     * Audits a 403 for a private-key format the caller may not download, at most once per user per
     * minute. Refused before the certificate lookup, so the row never says whether the cert exists.
     */
    public void recordKeyNotPermitted(Long organizationId, Integer userId, CertExportFormat format) {
        if (recentKeyNotPermittedAudits.putIfAbsent(userId, Boolean.TRUE) == null) {
            recordRefusal(organizationId, null, format, CertExportException.EXPORT_KEY_NOT_PERMITTED);
        }
    }

    static Map<String, Object> exportDetails(CertificateEntity cert, CertExportOptions options) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("certificateXref", cert.getCertificateXref());
        details.put("format", options.format().name());
        details.put("includesPrivateKey", options.format().includesPrivateKey());
        if (options.format() == CertExportFormat.PKCS12) {
            details.put("legacyPkcs12", options.legacyPkcs12());
        }
        return details;
    }

    static String sanitiseRequestedXref(String requestedXref) {
        if (requestedXref == null) {
            return null;
        }
        return requestedXref.codePoints()
                .filter(codePoint -> !Character.isISOControl(codePoint))
                .limit(MAX_REQUESTED_XREF_LENGTH)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    private String toJson(Map<String, Object> details) {
        try {
            return objectMapper.writeValueAsString(details);
        } catch (JacksonException e) {
            throw new IllegalStateException("Export event details could not be serialized", e);
        }
    }
}
