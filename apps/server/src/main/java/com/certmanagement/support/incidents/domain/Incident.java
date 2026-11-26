// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.domain;

import com.certmanagement.support.integrations.domain.IntegrationProvider;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "incidents")
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "org_id", nullable = false)
    private Long organizationId;

    @Column(name = "actor_user_id")
    private Long actorUserId;

    @Enumerated(EnumType.STRING)
    @Column(name = "source", nullable = false, length = 32)
    private IncidentCreationSource source;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 32)
    private IntegrationProvider provider;

    @Column(name = "alert_id")
    private Long alertId;

    @Column(name = "summary", nullable = false, columnDefinition = "TEXT")
    private String summary;

    @Column(name = "external_incident_id", length = 255)
    private String externalIncidentId;

    @Column(name = "external_reference", nullable = false, length = 255)
    private String externalReference;

    @Column(name = "external_url", columnDefinition = "TEXT")
    private String externalUrl;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Incident() {
    }

    public Incident(
            Long organizationId,
            Long actorUserId,
            IncidentCreationSource source,
            IntegrationProvider provider,
            Long alertId,
            String summary,
            String externalIncidentId,
            String externalReference,
            String externalUrl) {
        this.organizationId = organizationId;
        this.actorUserId = actorUserId;
        this.source = source;
        this.provider = provider;
        this.alertId = alertId;
        this.summary = summary;
        this.externalIncidentId = externalIncidentId;
        this.externalReference = externalReference;
        this.externalUrl = externalUrl;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public Long getOrganizationId() {
        return organizationId;
    }

    public Long getActorUserId() {
        return actorUserId;
    }

    public IncidentCreationSource getSource() {
        return source;
    }

    public IntegrationProvider getProvider() {
        return provider;
    }

    public Long getAlertId() {
        return alertId;
    }

    public String getSummary() {
        return summary;
    }

    public String getExternalIncidentId() {
        return externalIncidentId;
    }

    public String getExternalReference() {
        return externalReference;
    }

    public String getExternalUrl() {
        return externalUrl;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
