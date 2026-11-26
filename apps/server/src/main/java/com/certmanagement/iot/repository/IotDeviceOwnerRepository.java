// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceOwner;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IotDeviceOwnerRepository extends JpaRepository<IotDeviceOwner, Long> {

    Optional<IotDeviceOwner> findByDeviceIdAndIsDeletedFalse(Long deviceId);

    /**
     * Owners for a page of devices.
     *
     * <p>Use this rather than {@code findAllById}: the inherited method has no notion of
     * {@code is_deleted}, so an erased owner would still be read back and rendered. Erasure
     * has to hold on every read path, not just the single-device one.
     */
    List<IotDeviceOwner> findByDeviceIdInAndIsDeletedFalse(Collection<Long> deviceIds);
}
