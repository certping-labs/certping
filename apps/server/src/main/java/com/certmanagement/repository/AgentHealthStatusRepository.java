// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.AgentHealthStatusEntity;
import com.certmanagement.enums.AgentHealthOverallStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;


@Repository
public interface AgentHealthStatusRepository extends JpaRepository<AgentHealthStatusEntity, Long> {

    /** One row per organization, so this scans the whole (small) table rather than filtering by age. */
    interface HeartbeatState {
        Long getOrganizationId();

        OffsetDateTime getCmsReceivedAt();

        AgentHealthOverallStatus getOverallStatus();

        String getLastErrorCode();

        /** Staleness is judged against the organization's own cadence, not a fixed interval. */
        Integer getCadenceMinutes();
    }

    @Query("""
            SELECT a.organizationId AS organizationId,
                   a.cmsReceivedAt AS cmsReceivedAt,
                   a.overallStatus AS overallStatus,
                   a.lastErrorCode AS lastErrorCode,
                   o.agentHeartbeatCadenceMinutes AS cadenceMinutes
              FROM AgentHealthStatusEntity a
              JOIN Organization o ON o.id = a.organizationId
            """)
    List<HeartbeatState> findHeartbeatState();
}
