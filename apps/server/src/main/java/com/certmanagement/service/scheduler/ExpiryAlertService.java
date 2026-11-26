// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.messaging.NotificationPublisher;
import com.certmanagement.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Sends expiry alert notifications when a certificate crosses an alert threshold.
 *
 * <p>The thresholds (30, 14, 7, 3 and 1 days by default) replace "one email a day for the whole
 * window", which trained people to ignore the emails. Each certificate is alerted once per
 * threshold it crosses; {@code certificates.expiry_alert_threshold_days} remembers the last one,
 * so a pass that finds the certificate still inside the same threshold stays quiet.
 *
 * <p>Worker-queue pattern: the cron drains one cert per transaction via
 * {@link #tryProcessOneEligible()} until no eligible rows remain. Multi-pod safe via
 * Postgres's {@code SELECT … FOR UPDATE SKIP LOCKED}.
 *
 * <p>State marker: {@code certificates.last_alerted_at}. After each look, set to NOW(); the
 * eligibility query filters {@code last_alerted_at < (NOW() - 24h)} so a certificate is looked at
 * once a day regardless of which pod processed it, whether or not an alert went out.
 *
 * <p>Per-cert work: when a threshold was crossed, publish CERT_EXPIRY_ALERT and only then record the
 * threshold as sent, in one per-row transaction. A failed publish records the look but not the
 * threshold, so one bad row cannot block the queue and the next pass sends the same alert.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@CronJobFor("trigger-expiry-alerts")
public class ExpiryAlertService implements DrainableCron {

    static final List<Integer> DEFAULT_THRESHOLDS = List.of(30, 14, 7, 3, 1);

    /** A certificate is looked at once per this interval (the eligibility cutoff). */
    static final Duration LOOK_INTERVAL = Duration.ofHours(24);

    /** After a failed publish the certificate is eligible again this soon, never within the same drain. */
    static final Duration RETRY_AFTER = Duration.ofMinutes(15);

    private final CertificateRepository  certificateRepository;
    private final NotificationPublisher  notificationPublisher;

    @Value("${certping.jobs.trigger-expiry-alerts.days-before-expiry:30}")
    private int daysBeforeExpiry;

    @Value("${certping.jobs.trigger-expiry-alerts.thresholds-days:30,14,7,3,1}")
    private String thresholdsSetting;

    /** The transaction starts here, on the method DrainRunner calls through the proxy — not on the overload. */
    @Override
    @Transactional
    public boolean tryProcessOneEligible() {
        return tryProcessOneEligible(daysBeforeExpiry, parseThresholds(thresholdsSetting));
    }

    /** {@link #tryProcessOneEligible(int, List)} with the default thresholds. */
    public boolean tryProcessOneEligible(int daysBeforeExpiry) {
        return tryProcessOneEligible(daysBeforeExpiry, DEFAULT_THRESHOLDS);
    }

    /**
     * Claims one eligible cert, stamps it, and sends its alert when it crossed a threshold since the
     * last alert, in a single transaction.
     *
     * @param daysBeforeExpiry look-ahead window in days (e.g. 30); widened to the widest threshold
     * @param thresholds       days-before-expiry values that each earn one alert
     * @return {@code true} if a cert was claimed (drain loop continues), {@code false} when
     *         no eligible certs remain.
     */
    public boolean tryProcessOneEligible(int daysBeforeExpiry, List<Integer> thresholds) {
        OffsetDateTime now         = OffsetDateTime.now(ZoneOffset.UTC);
        int widest = thresholds.stream().mapToInt(Integer::intValue).max().orElse(daysBeforeExpiry);
        OffsetDateTime horizon     = now.plusDays(Math.max(daysBeforeExpiry, widest));
        // Only look at each cert once per 24h.
        OffsetDateTime alertCutoff = now.minus(LOOK_INTERVAL);

        Optional<CertificateEntity> claimed =
                certificateRepository.claimOneExpiringActiveForAlert(now, horizon, alertCutoff);
        if (claimed.isEmpty()) {
            return false;
        }
        CertificateEntity cert = claimed.get();

        long daysRemaining = cert.getValidTo() != null
                ? Duration.between(now, cert.getValidTo()).toDays()
                : 0;

        Integer crossed = thresholdCrossed(daysRemaining, cert.getExpiryAlertThresholdDays(), thresholds);
        if (crossed == null) {
            certificateRepository.updateLastAlertedAt(cert.getCertificateXref(), now);
            log.debug("[ExpiryAlertService] No new threshold: xref={}, daysRemaining={}, lastThreshold={}",
                    cert.getCertificateXref(), daysRemaining, cert.getExpiryAlertThresholdDays());
            return true;
        }

        try {
            notificationPublisher.publish(
                    "CERT_EXPIRY_ALERT",
                    cert.getOrganizationId().toString(),
                    cert.getCertificateXref(),
                    Map.of(
                            "domain",        cert.getDomain(),
                            "validTo",       cert.getValidTo() != null ? cert.getValidTo().toString() : "",
                            "daysRemaining", String.valueOf(daysRemaining),
                            "thresholdDays", String.valueOf(crossed)
                    )
            );
        } catch (Exception e) {
            // Not rethrown: the drain has no per-row catch, and a rollback would leave this row
            // first in line to be claimed again, blocking every certificate behind it. The threshold
            // is NOT recorded: only the look is, dated so the row is eligible again after
            // RETRY_AFTER and not within this drain, and the next pass sends the same alert.
            certificateRepository.updateLastAlertedAt(cert.getCertificateXref(),
                    now.minus(LOOK_INTERVAL).plus(RETRY_AFTER));
            log.error("[CERT_EXPIRY_ALERT_FAILED] publish failed, the next pass sends it again: "
                            + "xref={}, organizationId={}, threshold={}, reason={}",
                    cert.getCertificateXref(), cert.getOrganizationId(), crossed, e.getMessage(), e);
            return true;
        }

        // Only now that the alert is enqueued is its threshold recorded as sent, in the same transaction.
        certificateRepository.recordExpiryAlert(cert.getCertificateXref(), now, crossed);
        log.info("[ExpiryAlertService] Alert sent: xref={}, domain={}, daysRemaining={}, threshold={}, organizationId={}",
                cert.getCertificateXref(), cert.getDomain(), daysRemaining, crossed, cert.getOrganizationId());
        return true;
    }

    /**
     * The tightest threshold {@code daysRemaining} is inside, when it is one the certificate has not
     * been alerted for: null when no threshold is reached or the last alert already covered it. A
     * last threshold smaller than the days remaining means the validity moved out again (renewed in
     * place), so the thresholds start over.
     */
    static Integer thresholdCrossed(long daysRemaining, Integer lastThreshold, List<Integer> thresholds) {
        Integer tightest = null;
        for (Integer threshold : thresholds) {
            if (daysRemaining <= threshold && (tightest == null || threshold < tightest)) {
                tightest = threshold;
            }
        }
        if (tightest == null) {
            return null;
        }
        boolean startOver = lastThreshold != null && lastThreshold < daysRemaining;
        if (lastThreshold == null || startOver || tightest < lastThreshold) {
            return tightest;
        }
        return null;
    }

    /** "30,14,7,3,1" to a list; blank or malformed falls back to the defaults. */
    static List<Integer> parseThresholds(String setting) {
        if (setting == null || setting.isBlank()) {
            return DEFAULT_THRESHOLDS;
        }
        try {
            List<Integer> parsed = Arrays.stream(setting.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(Integer::parseInt)
                    .filter(days -> days > 0)
                    .distinct()
                    .toList();
            return parsed.isEmpty() ? DEFAULT_THRESHOLDS : parsed;
        } catch (NumberFormatException e) {
            log.warn("Ignoring malformed trigger-expiry-alerts.thresholds-days '{}'; using {}", setting, DEFAULT_THRESHOLDS);
            return DEFAULT_THRESHOLDS;
        }
    }
}
