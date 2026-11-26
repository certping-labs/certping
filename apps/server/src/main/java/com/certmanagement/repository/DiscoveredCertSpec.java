// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveredCertEntity;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Composable JPA specifications for querying {@link DiscoveredCertEntity}.
 *
 * <p>All parameters are optional — null values are silently skipped so callers
 * can pass every filter field and only the non-null ones are applied.
 */
public final class DiscoveredCertSpec {

    private DiscoveredCertSpec() {}

    /**
     * Builds a {@link Specification} from all supported optional filter parameters.
     *
     * @param organizationId required — always applied
     * @param managed        optional — true/false/null
     * @param domain         optional — case-insensitive substring match
     * @param targetType     optional — exact match (e.g. "AWS_ACM")
     * @param keyAlgorithm   optional — exact match (e.g. "RSA_2048")
     * @param certStatus     optional — exact match (e.g. "ISSUED", "EXPIRED")
     * @param expiresOnOrAfter optional — inclusive lower bound on {@code notAfter} (e.g. now UTC)
     * @param expiresOnOrBefore optional — inclusive upper bound on {@code notAfter} (e.g. now+N days)
     */
    public static Specification<DiscoveredCertEntity> filter(
            Long organizationId,
            Boolean managed,
            String domain,
            String targetType,
            String keyAlgorithm,
            String certStatus,
            OffsetDateTime expiresOnOrAfter,
            OffsetDateTime expiresOnOrBefore) {

        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("organizationId"), organizationId));

            if (managed != null) {
                predicates.add(cb.equal(root.get("managed"), managed));
            }
            if (domain != null && !domain.isBlank()) {
                predicates.add(cb.like(
                        cb.lower(root.get("domain")),
                        "%" + domain.toLowerCase() + "%"));
            }
            if (targetType != null && !targetType.isBlank()) {
                predicates.add(cb.equal(root.get("targetType"), targetType));
            }
            if (keyAlgorithm != null && !keyAlgorithm.isBlank()) {
                predicates.add(cb.equal(root.get("keyAlgorithm"), keyAlgorithm));
            }
            if (certStatus != null && !certStatus.isBlank()) {
                predicates.add(cb.equal(root.get("certStatus"), certStatus));
            }
            if (expiresOnOrAfter != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("notAfter"), expiresOnOrAfter));
            }
            if (expiresOnOrBefore != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("notAfter"), expiresOnOrBefore));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
