// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

/**
 * Registry of credentials kept in the agent's secret store (written by CertPing, or pre-loaded by
 * the organization). Stores the secret handle ONLY — never the credential value itself.
 */
@Entity
@Table(name = "credential_references")
@SQLRestriction("is_deleted = false")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialReferenceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "credential_xref", nullable = false, unique = true, length = 100)
    private String credentialXref;

    @Column(name = "organization_id", nullable = false)
    private Long organizationId;

    /**
    * DNS providers: CLOUDFLARE | AWS_ROUTE53 | GODADDY | NAMECHEAP | NAMEDOTCOM | HOSTINGER | CERTPING | AZURE_DNS
    * Deployment providers: AZURE_KV | AWS_ACM | AZURE_APP_GW | AZURE_APP_GW_CONTAINERS |
    * AWS_ALB | AWS_NLB | AWS_API_GW_REST | AWS_API_GW_HTTP | KUBERNETES_SECRETS
     * ACME: LETS_ENCRYPT
     */
    @Column(name = "provider", nullable = false, length = 50)
    private String provider;

    /** DNS | DEPLOYMENT | ACME_ACCOUNT */
    @Column(name = "type", nullable = false, length = 50)
    private String type;

    @Column(name = "description", length = 500)
    private String description;

    /** ACTIVE | DELETED */
    @Column(name = "status", nullable = false, length = 50)
    @Builder.Default
    private String status = "ACTIVE";

    /**
     * Secret store handle — e.g. an Azure Key Vault URI https://{vault}.vault.azure.net/secrets/{name}
     * Nullable only for KUBERNETES_SECRETS when authMethod is SA_INCLUSTER.
     */
    @Column(name = "secret_handle", length = 500)
    private String secretHandle;

    @Column(name = "last_error_message", columnDefinition = "TEXT")
    private String lastErrorMessage;

    /**
     * Credential-scoped deployment settings — never part of the KV credential secret.
     * For {@code KUBERNETES_SECRETS}: {@code authMethod}, {@code clusterName}, {@code namespaces}.
     * Per-certificate deployment payload (ARN / Azure certificate name / k8s nsMaps) is stored in
     * {@code cert_deployment_config}, not here.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "config", columnDefinition = "jsonb")
    private String configJson;

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
