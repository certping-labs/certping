// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.AgentDeepHealthCheckChunkEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AgentDeepHealthCheckChunkRepository extends JpaRepository<AgentDeepHealthCheckChunkEntity, Long> {

    boolean existsByDeepCheckIdAndChunkIndex(String deepCheckId, Integer chunkIndex);

    long countByDeepCheckId(String deepCheckId);

    List<AgentDeepHealthCheckChunkEntity> findByDeepCheckIdOrderByChunkIndexAsc(String deepCheckId);
}
