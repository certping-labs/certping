// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

@Entity
@Table(name = "cron_runs")
@Getter
@Setter
@NoArgsConstructor
public class CronRun {

    @Id
    @Column(name = "cron_name", length = 100)
    private String cronName;

    @Column(name = "active_pod_count", nullable = false)
    private int activePodCount;

    @Column(name = "last_activity_at", nullable = false)
    private OffsetDateTime lastActivityAt;

    @Column(name = "last_completed_at")
    private OffsetDateTime lastCompletedAt;

    /** When a budget-capped drain may continue; {@code null} when nothing is left to continue. */
    @Column(name = "continuation_due_at")
    private OffsetDateTime continuationDueAt;
}
