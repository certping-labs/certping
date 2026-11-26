// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

/** Durable state for one operator or Intune revocation request. */
@Entity
@Table(name = "iot_certificate_revocation")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotCertificateRevocation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "operation_xref", nullable = false, length = 100)
    private String operationXref;
    @Column(name = "organization_id", nullable = false)
    private Long organizationId;
    @Column(name = "certificate_id")
    private Long certificateId;
    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private IotCertificateRevocationSource source;
    @Column(name = "idempotency_key", length = 100)
    private String idempotencyKey;
    @Column(name = "intune_transaction_id", length = 100)
    private String intuneTransactionId;
    @Column(name = "request_context", length = 1000)
    private String requestContext;
    @Column(name = "request_context_hash", length = 64)
    private String requestContextHash;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private IotRevocationReason reason;
    @Column(name = "operator_note", length = 500)
    private String operatorNote;
    @Column(name = "requested_by_user_id")
    private Long requestedByUserId;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IotCertificateRevocationStatus status;
    @Column(name = "attempt_count", nullable = false)
    private Integer attemptCount;
    @Column(name = "next_attempt_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime nextAttemptAt;
    @Column(name = "dispatched_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime dispatchedAt;
    @Column(name = "ca_observed_reason", length = 100)
    private String caObservedReason;
    @Column(name = "ca_observed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime caObservedAt;
    @Column(name = "error_code", length = 100)
    private String errorCode;
    @Column(name = "error_message", length = 500)
    private String errorMessage;
    @Column(name = "completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime completedAt;
    @Column(name = "created_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;
    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
