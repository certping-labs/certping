// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.entity;

import com.certmanagement.iot.enums.SyncMode;
import com.certmanagement.iot.enums.SyncStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;

@Entity
@Table(name = "iot_device_source_sync_state")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IotDeviceSourceSyncState {
    @Id
    @Column(name = "device_source_id")
    private Long deviceSourceId;

    @Column(name = "sync_xref", nullable = false, length = 100)
    private String syncXref;

    @Enumerated(EnumType.STRING)
    @Column(name = "sync_status", nullable = false, length = 30)
    private SyncStatus syncStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "sync_mode", nullable = false, length = 30)
    private SyncMode syncMode;

    @Column(name = "requested_by_user_id")
    private Long requestedByUserId;

    @Column(name = "requested_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime requestedAt;

    @Column(name = "started_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime startedAt;

    @Column(name = "completed_at", columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime completedAt;

    @Column(name = "expected_device_count")
    private Integer expectedDeviceCount;

    @Column(name = "processed_device_count", nullable = false)
    private Integer processedDeviceCount;

    @Column(name = "failed_device_count", nullable = false)
    private Integer failedDeviceCount;

    @Column(name = "expected_batch_count")
    private Integer expectedBatchCount;

    @Column(name = "processed_batch_count", nullable = false)
    private Integer processedBatchCount;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "received_batches_json", nullable = false, columnDefinition = "jsonb")
    private String receivedBatchesJson;

    @Column(name = "completion_received", nullable = false)
    private Boolean completionReceived;

    @Column(name = "last_error", length = 1000)
    private String lastError;

    @Column(name = "updated_at", nullable = false, columnDefinition = "TIMESTAMPTZ")
    private OffsetDateTime updatedAt;
}
