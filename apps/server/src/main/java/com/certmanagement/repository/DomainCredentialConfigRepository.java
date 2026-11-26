// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DomainCredentialConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Optional;

@Repository
public interface DomainCredentialConfigRepository extends JpaRepository<DomainCredentialConfigEntity, Long> {

    Optional<DomainCredentialConfigEntity> findByUserDomainCertId(Long userDomainCertId);

    java.util.List<DomainCredentialConfigEntity> findByUserDomainCertIdIn(Collection<Long> userDomainCertIds);

    @Transactional
    @Modifying
    @Query("UPDATE DomainCredentialConfigEntity d SET d.isDeleted = true WHERE d.userDomainCertId IN :udcIds AND d.isDeleted = false")
    int softDeleteByUserDomainCertIdIn(@Param("udcIds") Collection<Long> udcIds);

    @Transactional
    @Modifying
    @Query("UPDATE DomainCredentialConfigEntity d SET d.isDeleted = true WHERE d.userDomainCertId = :udcId AND d.isDeleted = false")
    int softDeleteByUserDomainCertId(@Param("udcId") Long userDomainCertId);

    @Transactional
    @Modifying
    @Query("UPDATE DomainCredentialConfigEntity d SET d.isDeleted = true WHERE d.userDomainCertId IN (SELECT u.id FROM UserDomainCertEntity u WHERE u.organizationId = :orgId) AND d.isDeleted = false")
    int softDeleteByOrganizationId(@Param("orgId") Long orgId);

    /**
     * Drops a credential xref from every active config it appears in:
     *   - removes any {@code dns_config} entry whose VALUE equals the xref (rebuilds the JSONB
     *     map without those entries; preserves all other base-domain → credential mappings)
     *   - removes every occurrence of the xref from the {@code deployment_targets} JSONB array.
     *
     * <p>Called when a {@code CredentialReferenceEntity} is soft-deleted so its xref no longer
     * appears in live configs — otherwise the next renewal picks up a soft-deleted credential
     * and the DNS provider or cloud API rejects the request.
     *
     * <p>Native SQL because both transformations need JSONB operators that JPQL can't express.
     * Returns the number of config rows mutated for logging.
     */
    // Hibernate 6's native-query parser still treats `::name` as a JPQL named parameter
    // (eats one colon), so `'{}'::jsonb` becomes `'{}':jsonb` on the wire and Postgres
    // errors with "syntax error at or near ':'". Use ANSI CAST(... AS ...) instead.
    @Transactional
    @Modifying
    @NativeQuery("""
            UPDATE domain_credential_config
               SET dns_config = COALESCE(
                       (SELECT jsonb_object_agg(k, v)
                          FROM jsonb_each_text(dns_config) AS kv(k, v)
                         WHERE v <> :xref),
                       CAST('{}' AS jsonb)),
                   deployment_targets = COALESCE(deployment_targets - :xref, CAST('[]' AS jsonb)),
                   updated_at = now()
             WHERE is_deleted = false
               AND (
                     CAST(dns_config AS text) LIKE '%' || :xref || '%'
                  OR deployment_targets @> to_jsonb(ARRAY[:xref])
               )
            """)
    int removeCredentialXref(@Param("xref") String credentialXref);
}
