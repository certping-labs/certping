// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Types;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Aggregate reads and bulk changes over an organization's certificates for the feature lifecycle:
 * deployment targets, automatic renewal schedules and issuances still in flight. Certificates belong
 * to an organization through {@code user_domain_certificate}; soft-deleted certificates are ignored.
 * The impact reads count within an {@link ImpactScope}.
 */
@Repository
@RequiredArgsConstructor
public class CertificateLifecycleRepository {

    /*
     * Optional filters are appended only when their value is present, never as "(:x IS NULL OR ...)":
     * a generic prepared-statement plan for that form cannot use the organization index.
     */
    private static final String ORG_FILTER = " AND udc.organization_id = :organizationId";
    private static final String UDC_ORGANIZATION = "udc.organization_id";
    private static final String AUTO_RENEW_FROM = """
             FROM renewal_schedule s
             JOIN certificates c ON c.certificate_xref = s.certificate_xref AND c.deleted_at IS NULL
             JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id
            WHERE s.enabled = TRUE AND s.is_deleted = FALSE
            """;
    private static final String TARGETS_FROM = """
             FROM domain_credential_config d
             JOIN user_domain_certificate udc ON udc.id = d.user_domain_cert_id
            WHERE d.is_deleted = FALSE AND jsonb_array_length(d.deployment_targets) > 0
            """;
    private static final String PENDING_FROM = """
             FROM certificates c
             JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id
            WHERE c.deleted_at IS NULL AND c.status = 'PENDING'
            """;

    private static final String UPDATE_SCHEDULE = """
            UPDATE renewal_schedule s
            """;
    private static final String ENABLED_SCHEDULES = """
              FROM certificates c
              JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id
             WHERE s.certificate_xref = c.certificate_xref AND c.deleted_at IS NULL
               AND s.enabled = TRUE AND s.is_deleted = FALSE
            """;

    /** The window released schedules that are already due come due over (one hour). */
    public static final long RELEASE_SPREAD_SECONDS = 3600;

    private final NamedParameterJdbcTemplate jdbc;

    /** Deployment targets configured across the organization's certificates. */
    public long countDeploymentTargets(long organizationId) {
        Long count = jdbc.queryForObject("SELECT COALESCE(SUM(jsonb_array_length(d.deployment_targets)), 0)"
                + TARGETS_FROM + ORG_FILTER, orgParams(organizationId), Long.class);
        return count == null ? 0 : count;
    }

    public AffectedOrganizations deploymentTargetOrganizations(ImpactScope scope) {
        return new AffectedOrganizations("SELECT udc.organization_id AS organization_id" + TARGETS_FROM
                + scope.filter(UDC_ORGANIZATION), scope.bind(new MapSqlParameterSource()));
    }

    public RecordImpact deploymentTargetsImpact(ImpactScope scope) {
        return impact("SELECT COALESCE(SUM(jsonb_array_length(d.deployment_targets)), 0) AS records,"
                + " COUNT(DISTINCT udc.organization_id) AS organizations" + TARGETS_FROM
                + scope.filter(UDC_ORGANIZATION), scope.bind(new MapSqlParameterSource()));
    }

    /**
     * Empties the deployment target list of every certificate of the organization, as removing each
     * target one by one would ({@code DomainCredentialConfigService.removeDeploymentTarget}).
     *
     * @return targets removed
     */
    public long clearDeploymentTargets(long organizationId) {
        Long removed = jdbc.queryForObject("""
                WITH cleared AS (
                    SELECT d.id, jsonb_array_length(d.deployment_targets) AS targets
                """ + TARGETS_FROM + ORG_FILTER + """
                       FOR UPDATE OF d
                ), updated AS (
                    UPDATE domain_credential_config d
                       SET deployment_targets = '[]'::jsonb, updated_at = NOW()
                      FROM cleared
                     WHERE d.id = cleared.id
                 RETURNING cleared.targets
                )
                SELECT COALESCE(SUM(targets), 0) FROM updated
                """, orgParams(organizationId), Long.class);
        return removed == null ? 0 : removed;
    }

    /** Certificates set to renew automatically within {@code renewals}, with the nearest expiry. */
    public AutoRenewCount countAutoRenew(long organizationId, AutoRenewScope renewals) {
        return jdbc.queryForObject("SELECT COUNT(*) AS records, MIN(s.valid_to) AS nearest"
                        + AUTO_RENEW_FROM + ORG_FILTER + renewals.filter(),
                renewals.bind(orgParams(organizationId)),
                (rows, rowNum) -> new AutoRenewCount(rows.getLong("records"),
                        rows.getObject("nearest", OffsetDateTime.class)));
    }

    public RecordImpact autoRenewImpact(ImpactScope scope, AutoRenewScope renewals) {
        return impact("SELECT COUNT(*) AS records, COUNT(DISTINCT udc.organization_id) AS organizations"
                        + AUTO_RENEW_FROM + scope.filter(UDC_ORGANIZATION) + renewals.filter(),
                renewals.bind(scope.bind(new MapSqlParameterSource())));
    }

    public AffectedOrganizations autoRenewOrganizations(ImpactScope scope, AutoRenewScope renewals) {
        return new AffectedOrganizations("SELECT udc.organization_id AS organization_id" + AUTO_RENEW_FROM
                + scope.filter(UDC_ORGANIZATION) + renewals.filter(),
                renewals.bind(scope.bind(new MapSqlParameterSource())));
    }

    /** Certificates set to renew automatically within {@code renewals}, per organization of a page. */
    public Map<Long, Long> countAutoRenewByOrganization(Collection<Long> organizationIds, AutoRenewScope renewals) {
        if (organizationIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, Long> counts = new HashMap<>();
        jdbc.query("SELECT udc.organization_id, COUNT(*) AS records" + AUTO_RENEW_FROM
                        + " AND udc.organization_id IN (:organizationIds)" + renewals.filter()
                        + " GROUP BY udc.organization_id",
                renewals.bind(new MapSqlParameterSource("organizationIds", organizationIds)),
                rows -> { counts.put(rows.getLong("organization_id"), rows.getLong("records")); });
        return counts;
    }

    /** One page of organizations, ascending after {@code afterOrganizationId}, with renewals within {@code renewals}. */
    public List<Long> organizationsWithAutoRenew(long afterOrganizationId, int limit, AutoRenewScope renewals) {
        return jdbc.queryForList("SELECT DISTINCT udc.organization_id" + AUTO_RENEW_FROM
                        + " AND udc.organization_id > :after" + renewals.filter()
                        + " ORDER BY udc.organization_id LIMIT :limit",
                renewals.bind(new MapSqlParameterSource("after", afterOrganizationId).addValue("limit", limit)),
                Long.class);
    }

    /**
     * Turns automatic renewal off for the organization's certificates within {@code renewals}, as
     * {@code RenewalScheduleRepository.disableSchedule} does for one.
     *
     * @return schedules disabled
     */
    public int disableAutoRenew(long organizationId, AutoRenewScope renewals) {
        return jdbc.update(UPDATE_SCHEDULE + " SET enabled = FALSE, updated_at = NOW()"
                        + ENABLED_SCHEDULES + ORG_FILTER + renewals.filter(),
                renewals.bind(orgParams(organizationId)));
    }

    /**
     * Turns automatic renewal off for the organization's certificates within {@code renewals} and marks
     * each schedule with {@code holdStatus}, so {@link #releaseHeld} turns exactly those back on. A
     * renewal in flight (schedule IN_PROGRESS or certificate RENEWING) is left alone: its outcome
     * rewrites the status, and the renewal trigger holds the schedule when it next comes due.
     *
     * @return schedules held
     */
    public int holdAutoRenew(long organizationId, AutoRenewScope renewals, String holdStatus) {
        return jdbc.update(UPDATE_SCHEDULE
                        + " SET enabled = FALSE, last_renewal_status = :holdStatus, next_attempt_at = NULL,"
                        + " updated_at = NOW()" + ENABLED_SCHEDULES
                        + " AND s.last_renewal_status IS DISTINCT FROM 'IN_PROGRESS' AND c.status <> 'RENEWING'"
                        + ORG_FILTER + renewals.filter(),
                renewals.bind(orgParams(organizationId)).addValue("holdStatus", holdStatus));
    }

    /**
     * Turns automatic renewal back on for the organization's schedules held with {@code holdStatus},
     * whether the feature lifecycle disabled them or the renewal trigger held them, while their
     * certificate is ACTIVE (or RENEWING: a manual renewal in flight, whose outcome then writes the status;
     * the claim never starts a second one) and unexpired; any other stays held (an expired one needs a
     * new issuance).
     * An overdue schedule comes due at a point spread over {@link #RELEASE_SPREAD_SECONDS} by a hash
     * of its id, so releasing a whole org type cannot send every overdue order to a CA at once.
     *
     * @return schedules turned back on
     */
    public int releaseHeld(long organizationId, String holdStatus) {
        return jdbc.update("""
                UPDATE renewal_schedule s
                   SET enabled = TRUE, last_renewal_status = NULL, next_attempt_at = NULL, updated_at = NOW(),
                       renewal_eligible_at = GREATEST(s.renewal_eligible_at, NOW() + make_interval(secs =>
                           CAST((hashint8(s.id) + 2147483648) % :spreadSeconds AS double precision)))
                  FROM certificates c
                  JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id
                 WHERE s.certificate_xref = c.certificate_xref AND c.deleted_at IS NULL
                   AND s.is_deleted = FALSE AND s.last_renewal_status = :holdStatus
                   AND c.status IN ('ACTIVE', 'RENEWING') AND c.valid_to > NOW()
                """ + ORG_FILTER,
                orgParams(organizationId).addValue("holdStatus", holdStatus)
                        .addValue("spreadSeconds", RELEASE_SPREAD_SECONDS));
    }

    public long countPendingIssuances(long organizationId) {
        Long count = jdbc.queryForObject("SELECT COUNT(*)" + PENDING_FROM + ORG_FILTER,
                orgParams(organizationId), Long.class);
        return count == null ? 0 : count;
    }

    public AffectedOrganizations pendingIssuanceOrganizations(ImpactScope scope) {
        return new AffectedOrganizations("SELECT udc.organization_id AS organization_id" + PENDING_FROM
                + scope.filter(UDC_ORGANIZATION), scope.bind(new MapSqlParameterSource()));
    }

    public RecordImpact pendingIssuancesImpact(ImpactScope scope) {
        return impact("SELECT COUNT(*) AS records, COUNT(DISTINCT udc.organization_id) AS organizations"
                + PENDING_FROM + scope.filter(UDC_ORGANIZATION), scope.bind(new MapSqlParameterSource()));
    }

    /**
     * Live certificates expiring before {@code until}, optionally on one CA or only those with
     * deployment targets, and the organizations holding them.
     */
    public RecordImpact expiringCertificates(ImpactScope scope, OffsetDateTime until, String caProvider,
                                             boolean withDeploymentTargetsOnly) {
        return impact("""
                SELECT COUNT(*) AS records, COUNT(DISTINCT udc.organization_id) AS organizations
                  FROM certificates c
                  JOIN user_domain_certificate udc ON udc.id = c.user_domain_cert_id
                 WHERE c.deleted_at IS NULL
                   AND c.status IN ('ACTIVE', 'RENEWING', 'RENEWAL_FAILED')
                   AND c.valid_to > NOW() AND c.valid_to <= :until
                """ + scope.filter(UDC_ORGANIZATION)
                        + (caProvider == null ? "" : " AND c.ca_provider = :caProvider")
                        + (withDeploymentTargetsOnly ? """
                             AND EXISTS (SELECT 1 FROM domain_credential_config d
                                          WHERE d.user_domain_cert_id = c.user_domain_cert_id
                                            AND d.is_deleted = FALSE
                                            AND jsonb_array_length(d.deployment_targets) > 0)
                          """ : ""),
                scope.bind(new MapSqlParameterSource()).addValue("until", until)
                        .addValue("caProvider", caProvider, Types.VARCHAR));
    }

    private RecordImpact impact(String sql, MapSqlParameterSource params) {
        return jdbc.queryForObject(sql, params,
                (rows, rowNum) -> new RecordImpact(rows.getLong("records"), rows.getLong("organizations")));
    }

    private static MapSqlParameterSource orgParams(Long organizationId) {
        return new MapSqlParameterSource().addValue("organizationId", organizationId, Types.BIGINT);
    }

    /** Certificates set to renew automatically and the soonest of their expiries (null when none). */
    public record AutoRenewCount(long records, OffsetDateTime nearestExpiry) {
    }

    /**
     * Which renewal schedules an auto-renew read or change covers: every CA or one CA.
     *
     * @param caProvider a {@code CaProvider} name, or null for every CA
     */
    public record AutoRenewScope(String caProvider) {

        private static final String CA_FILTER = " AND s.ca_provider = :caProvider";

        public static AutoRenewScope everyCa() {
            return new AutoRenewScope(null);
        }

        public static AutoRenewScope onCa(String caProvider) {
            return new AutoRenewScope(caProvider);
        }

        String filter() {
            return caProvider == null ? "" : CA_FILTER;
        }

        MapSqlParameterSource bind(MapSqlParameterSource params) {
            return params.addValue("caProvider", caProvider, Types.VARCHAR);
        }
    }
}
