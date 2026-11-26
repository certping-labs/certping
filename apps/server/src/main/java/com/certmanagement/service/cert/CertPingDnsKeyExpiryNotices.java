// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.credconfig.credjson.dns.CertPingDnsKeyConfig;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.enums.EventSource;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.scheduler.RegisteredJob;
import com.certmanagement.service.scheduler.SchedulerExecutionPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Warns an organization's admins 30 and again 7 days before a CertPing DNS key expires, since its certificates
 * stop renewing then ({@code DNS_KEY_EXPIRED_HOLD}). Each warning is published deliver-once under a key of the
 * credential, its expiry and the lead time, so runs on every pod, and a renewed key's new expiry, are safe.
 * Expiries are read in Java rather than cast in SQL, so no stored config value can fail the scan.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertPingDnsKeyExpiryNotices {

    static final String JOB_NAME = "warn-certping-dns-key-expiry";
    static final String ACTION = "CERTPING_DNS_KEY_EXPIRING";
    static final int FIRST_NOTICE_DAYS = 30;
    static final int LAST_NOTICE_DAYS = 7;
    static final int PAGE_SIZE = 200;

    private final CredentialReferenceRepository credentials;
    private final CertPingDnsKeys keys;
    private final OrganizationRepository organizations;
    private final ObjectProvider<OrgAdminNotificationPublisher> publisher;
    private final SchedulerExecutionPolicy executionPolicy;
    private final Clock clock;

    /** CUSTOMER_PROTECTION in {@code JobPolicy}: the warning keeps renewals from stopping unannounced. */
    @RegisteredJob(JOB_NAME)
    @Scheduled(fixedDelayString = "${certping.dns-keys.expiry-notice-interval:PT6H}",
               initialDelayString = "${certping.dns-keys.expiry-notice-initial-delay:PT5M}")
    public void warnExpiringKeys() {
        if (!executionPolicy.canRun(JOB_NAME)) {
            return;
        }
        OrgAdminNotificationPublisher sender = publisher.getIfAvailable();
        if (sender == null) {
            log.debug("[CertPingDnsKeys] no notification sender configured; expiry notices not sent");
            return;
        }
        Instant now = clock.instant();
        int sent = 0;
        long afterId = 0;
        List<CredentialReferenceEntity> page;
        do {
            page = credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                    DnsCredentialAvailability.CERTPING_PROVIDER, "DNS", "ACTIVE", afterId,
                    PageRequest.of(0, PAGE_SIZE));
            for (CredentialReferenceEntity credential : page) {
                afterId = credential.getId();
                if (warn(sender, credential, now)) {
                    sent++;
                }
            }
        } while (page.size() == PAGE_SIZE);
        if (sent > 0) {
            log.info("[CertPingDnsKeys] expiry notices published={}", sent);
        }
    }

    /** Publishes the notice owed for {@code credential}'s key, if it expires within the notice period. */
    private boolean warn(OrgAdminNotificationPublisher sender, CredentialReferenceEntity credential,
                         Instant now) {
        CertPingDnsKeyConfig key = keys.details(credential).orElse(null);
        Instant expiresAt = key == null ? null : key.getExpiresAt();
        if (expiresAt == null || !expiresAt.isAfter(now)
                || expiresAt.isAfter(now.plus(Duration.ofDays(FIRST_NOTICE_DAYS)))) {
            return false;
        }
        int leadDays = expiresAt.isAfter(now.plus(Duration.ofDays(LAST_NOTICE_DAYS)))
                ? FIRST_NOTICE_DAYS : LAST_NOTICE_DAYS;
        String idempotencyKey = "certping-dns-key-expiring:" + credential.getId() + ":" + expiresAt.getEpochSecond()
                + ":" + leadDays;
        try {
            sender.publishOnceToOrgAdmins(ACTION, String.valueOf(credential.getOrganizationId()),
                    EventSource.CERT_MANAGER.value(), templateFields(credential, key, leadDays, idempotencyKey),
                    idempotencyKey);
            return true;
        } catch (RuntimeException e) {
            log.warn("[CertPingDnsKeys] expiry notice {} not sent yet, the next run retries it: {}",
                    idempotencyKey, e.getMessage());
            return false;
        }
    }

    /** The notifier's payload: everything it renders comes from these fields. */
    Map<String, Object> templateFields(CredentialReferenceEntity credential, CertPingDnsKeyConfig key, int leadDays,
                                       String idempotencyKey) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("organizationId", credential.getOrganizationId());
        fields.put("organizationName", organizations.findNameById(credential.getOrganizationId()).orElse(""));
        fields.put("credentialName", Objects.requireNonNullElse(credential.getDescription(), ""));
        fields.put("tokenPrefix", Objects.requireNonNullElse(key.getTokenPrefix(), ""));
        fields.put("expiresAt", key.getExpiresAt().toString());
        fields.put("leadDays", leadDays);
        fields.put("idempotencyKey", idempotencyKey);
        return fields;
    }
}
