// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Collection;
import java.util.Optional;

public interface IotDeviceEndpointPostureRepository extends JpaRepository<IotDeviceEndpointPosture, Long> {

    Optional<IotDeviceEndpointPosture> findByDeviceId(Long deviceId);

    List<IotDeviceEndpointPosture> findByDeviceIdIn(Collection<Long> deviceIds);

    @Query("""
            SELECT p.operatingSystem, COUNT(d)
            FROM IotDevice d
            LEFT JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY p.operatingSystem
            """)
    List<Object[]> countByOperatingSystem(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT p.complianceState, COUNT(d)
            FROM IotDevice d
            LEFT JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY p.complianceState
            """)
    List<Object[]> countByComplianceState(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT p.isEncrypted, COUNT(d)
            FROM IotDevice d
            LEFT JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY p.isEncrypted
            """)
    List<Object[]> countByEncryption(@Param("organizationId") Long organizationId);

    @Query("""
            SELECT p.isSupervised, COUNT(d)
            FROM IotDevice d
            LEFT JOIN IotDeviceEndpointPosture p ON p.deviceId = d.id
            WHERE d.organizationId = :organizationId AND d.isDeleted = false
            GROUP BY p.isSupervised
            """)
    List<Object[]> countBySupervision(@Param("organizationId") Long organizationId);
}
