// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.hibernate.annotations.JdbcType;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.dialect.type.PostgreSQLEnumJdbcType;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "integrations")
public class Integration {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "org_id", nullable = false)
    private Long organizationId;

    @Enumerated(EnumType.STRING)
    // The database uses native PostgreSQL enums, so Hibernate must bind these values as
    // PostgreSQL enums instead of plain VARCHAR to avoid runtime operator/cast failures.
    // columnDefinition pins the SQL type name so Hibernate's schema validator matches the
    // actual DB type (`integration_provider`) rather than the default lowercased class name
    // (`integrationprovider`) which would not exist.
    @JdbcType(PostgreSQLEnumJdbcType.class)
    @Column(name = "provider", nullable = false, columnDefinition = "integration_provider")
    private IntegrationProvider provider;

    @Enumerated(EnumType.STRING)
    @JdbcType(PostgreSQLEnumJdbcType.class)
    @Column(name = "status", nullable = false, columnDefinition = "integration_status")
    private IntegrationStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "config", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> config = Map.of();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "secret_refs", nullable = false, columnDefinition = "jsonb")
    private Map<String, String> secretRefs = Map.of();

    @Column(name = "created_by")
    private Long createdBy;

    @Column(name = "updated_by")
    private Long updatedBy;

    @Column(name = "deleted_by")
    private Long deletedBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    protected Integration() {
    }

    public Integration(
            Long organizationId,
            IntegrationProvider provider,
            Map<String, Object> config,
            Map<String, String> secretRefs,
            Long createdBy) {
        this.organizationId = organizationId;
        this.provider = provider;
        this.status = IntegrationStatus.ACTIVE;
        this.config = copyObjectMap(config);
        this.secretRefs = copyStringMap(secretRefs);
        this.createdBy = createdBy;
        this.updatedBy = createdBy;
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public void replaceConfiguration(Map<String, Object> config, Map<String, String> secretRefs, Long updatedBy) {
        this.secretRefs = copyStringMap(secretRefs);
        this.config = copyObjectMap(config);
        this.status = IntegrationStatus.ACTIVE;
        this.updatedBy = updatedBy;
        this.deletedAt = null;
        this.deletedBy = null;
    }

    public void softDelete(Long deletedBy) {
        this.deletedAt = Instant.now();
        this.deletedBy = deletedBy;
        this.updatedBy = deletedBy;
        this.status = IntegrationStatus.DISABLED;
    }

    public Long getId() {
        return id;
    }

    public Long getOrganizationId() {
        return organizationId;
    }

    public IntegrationProvider getProvider() {
        return provider;
    }

    public IntegrationStatus getStatus() {
        return status;
    }

    public Map<String, Object> getConfig() {
        return copyObjectMap(config);
    }

    public Map<String, String> getSecretRefs() {
        return copyStringMap(secretRefs);
    }

    public String getSecretRef(String key) {
        return secretRefs == null ? null : secretRefs.get(key);
    }

    public Long getCreatedBy() {
        return createdBy;
    }

    public Long getUpdatedBy() {
        return updatedBy;
    }

    public Long getDeletedBy() {
        return deletedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    private Map<String, Object> copyObjectMap(Map<String, Object> source) {
        return source == null ? Map.of() : new LinkedHashMap<>(source);
    }

    private Map<String, String> copyStringMap(Map<String, String> source) {
        return source == null ? Map.of() : new LinkedHashMap<>(source);
    }
}
