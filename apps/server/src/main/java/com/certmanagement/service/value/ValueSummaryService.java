// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.value;

import com.certmanagement.dto.value.ValueSummaryDto;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * What CertPing has done for one organization: renewals, deployments and issuances it ran, the
 * manual work that saved, and the certificates discovery found that it does not manage yet.
 * Read straight from the certificate event log and the deployment and discovery tables.
 */
@Service
@RequiredArgsConstructor
public class ValueSummaryService {

    /** Time a person spends on one renewal by hand: request, validate, collect, install. */
    public static final int MINUTES_PER_RENEWAL = 60;
    /** Time a person spends installing one certificate on one target by hand. */
    public static final int MINUTES_PER_DEPLOYMENT = 20;
    /** Time a person spends on one new certificate by hand. */
    public static final int MINUTES_PER_ISSUANCE = 30;
    /** "Expiring soon": not yet expired, and expiring within this many days. */
    public static final int EXPIRING_SOON_DAYS = 30;

    private final JdbcTemplate jdbc;
    private final Clock clock;

    public ValueSummaryDto summarize(Long organizationId, int days) {
        Instant since = clock.instant().minus(Duration.ofDays(days));
        Timestamp sinceTs = Timestamp.from(since);

        long issuances = events(organizationId, "ISSUANCE_SUCCESS", sinceTs);
        long renewals = events(organizationId, "RENEWAL_SUCCESS", sinceTs);
        long scheduledRenewals = count("""
                SELECT count(*) FROM certificate_events
                WHERE organization_id = ? AND event_type = 'RENEWAL_REQUESTED' AND user_id IS NULL
                  AND NOT is_deleted AND occurred_at >= ?""", organizationId, sinceTs);
        long deployments = count("""
                SELECT count(*) FROM deployments
                WHERE organization_id = ? AND status = 'SUCCESS' AND NOT is_deleted
                  AND coalesce(completed_at, updated_at) >= ?""", organizationId, sinceTs);
        // A renewal counts as "before expiry" only when it completed before the replaced
        // certificate's not_after. The RENEWAL_SUCCESS event sits on the replaced certificate, which
        // keeps its own valid_to, and occurred_at is when the renewal was applied.
        long renewedBeforeExpiry = count("""
                SELECT count(*) FROM certificate_events e
                JOIN certificates c ON c.certificate_xref = e.certificate_xref
                WHERE e.organization_id = ? AND e.event_type = 'RENEWAL_SUCCESS' AND NOT e.is_deleted
                  AND e.occurred_at >= ? AND c.valid_to IS NOT NULL AND e.occurred_at < c.valid_to""",
                organizationId, sinceTs);
        // The same definition as the discovery page: explicitly not managed (managed = false; an
        // unmatched row is null) and still there (not MISSING).
        long unmanaged = count("""
                SELECT count(*) FROM discovered_cert
                WHERE organization_id = ? AND managed = false AND inventory_status <> 'MISSING'""",
                organizationId);
        // Expiring soon is the next 30 days only; a certificate that already expired is not "expiring".
        Timestamp now = Timestamp.from(clock.instant());
        long unmanagedExpiring = count("""
                SELECT count(*) FROM discovered_cert
                WHERE organization_id = ? AND managed = false AND inventory_status <> 'MISSING'
                  AND not_after IS NOT NULL AND not_after >= ? AND not_after <= ?""",
                organizationId, now, Timestamp.from(clock.instant().plus(Duration.ofDays(EXPIRING_SOON_DAYS))));

        long minutesSaved = renewals * MINUTES_PER_RENEWAL
                + deployments * MINUTES_PER_DEPLOYMENT
                + issuances * MINUTES_PER_ISSUANCE;

        return new ValueSummaryDto(days, since.toString(), issuances, renewals, scheduledRenewals, deployments,
                renewedBeforeExpiry, minutesSaved, unmanaged, unmanagedExpiring,
                new ValueSummaryDto.Assumptions(MINUTES_PER_RENEWAL, MINUTES_PER_DEPLOYMENT, MINUTES_PER_ISSUANCE));
    }

    private long events(Long organizationId, String type, Timestamp since) {
        return count("""
                SELECT count(*) FROM certificate_events
                WHERE organization_id = ? AND event_type = ? AND NOT is_deleted AND occurred_at >= ?""",
                organizationId, type, since);
    }

    private long count(String sql, Object... args) {
        Long value = jdbc.queryForObject(sql, Long.class, args);
        return value == null ? 0 : value;
    }
}
