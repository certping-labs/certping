// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.AgentDeepHealthCheckEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AgentDeepHealthCheckRepository extends JpaRepository<AgentDeepHealthCheckEntity, Long> {

    Optional<AgentDeepHealthCheckEntity> findByDeepCheckId(String deepCheckId);

    Optional<AgentDeepHealthCheckEntity> findByDeepCheckIdAndOrganizationId(String deepCheckId, Long organizationId);

    Page<AgentDeepHealthCheckEntity> findByOrganizationIdOrderByRequestedAtDesc(Long organizationId, Pageable pageable);
}
