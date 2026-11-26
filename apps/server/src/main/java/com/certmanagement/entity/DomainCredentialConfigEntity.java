// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Live credential configuration for a domain — 1:1 with {@link UserDomainCertEntity}.
 *
 * <p><b>dns_config</b>: flat map of base-domain → credentialXref used at issuance/renewal time
 * to route each SAN domain to the correct DNS API credential. Example:
 * <pre>{ "example.com": "cred-dns-a", "example.org": "cred-dns-b" }</pre>
 *
 * <p><b>deployment_targets</b>: ordered list of deployment credentialXrefs. After a successful
 * issuance or renewal, a {@code CertDeploymentCommand} is published for every xref in this list
 * simultaneously. An empty list means no automatic deployment. Example:
 * <pre>["cred-deploy-azure", "cred-deploy-aws"]</pre>
 *
 * <p>Credential xrefs are resolved to KV paths at publish time via
 * {@link com.certmanagement.entity.CredentialReferenceEntity}. The actual secrets are never
 * stored here — only the xref pointers.
 */
@Entity
@Table(name = "domain_credential_config")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DomainCredentialConfigEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * FK to user_domain_certificate — uniqueness enforced at DB level (1:1 relationship).
     * We store the raw ID here rather than a JPA navigation property because the config
     * is always loaded by ID from the renewal_schedule FK, not by navigating from the cert.
     */
    @Column(name = "user_domain_cert_id", nullable = false, unique = true)
    private Long userDomainCertId;

    /**
     * Map of base-domain → credentialXref for DNS challenge authorisation.
     * The primary domain key matches {@link UserDomainCertEntity#getDomain()}.
     * Additional keys are SAN base domains.
     */
    @Column(name = "dns_config", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Builder.Default
    private Map<String, String> dnsConfig = new LinkedHashMap<>();

    /**
     * Ordered list of deployment credentialXrefs.
     * Each xref must be type=DEPLOYMENT in credential_references.
     * After issuance/renewal a CertDeploymentCommand is published for every xref simultaneously.
     */
    @Column(name = "deployment_targets", nullable = false, columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    @Builder.Default
    private List<String> deploymentTargets = new ArrayList<>();

    @Column(name = "is_deleted", nullable = false)
    @Builder.Default
    private Boolean isDeleted = false;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = OffsetDateTime.now();
        updatedAt = OffsetDateTime.now();
        if (isDeleted == null) {
            isDeleted = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
}
