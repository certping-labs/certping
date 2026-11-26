// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.AgentDeepHealthCheckMetricEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AgentDeepHealthCheckMetricRepository extends JpaRepository<AgentDeepHealthCheckMetricEntity, Long> {

    List<AgentDeepHealthCheckMetricEntity> findByDeepCheckIdAndOrganizationIdOrderByIdAsc(String deepCheckId, Long organizationId);

    boolean existsByDeepCheckIdAndMetricKey(String deepCheckId, String metricKey);
}
