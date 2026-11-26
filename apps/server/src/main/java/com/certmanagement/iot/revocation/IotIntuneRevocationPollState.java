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

@Entity
@Table(name = "iot_intune_revocation_poll_state")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotIntuneRevocationPollState {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "organization_id", nullable = false)
    private Long organizationId;
    @Column(name = "device_source_id", nullable = false)
    private Long deviceSourceId;
    @Column(name = "transaction_id", length = 100)
    private String transactionId;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private IotIntuneRevocationPollStatus status;
    @Column(name = "attempt_count", nullable = false)
    private Integer attemptCount;
    @Column(name = "next_attempt_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime nextAttemptAt;
    @Column(name = "requested_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime requestedAt;
    @Column(name = "dispatched_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime dispatchedAt;
    @Column(name = "downloaded_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime downloadedAt;
    @Column(name = "uploaded_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime uploadedAt;
    @Column(name = "last_error_code", length = 100)
    private String lastErrorCode;
    @Column(name = "last_error_message", length = 500)
    private String lastErrorMessage;
    @Column(name = "created_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime createdAt;
    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
