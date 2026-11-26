// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import com.certmanagement.iot.entity.IotDeviceConnectedThing;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IotDeviceConnectedThingRepository extends JpaRepository<IotDeviceConnectedThing, Long> {

    Optional<IotDeviceConnectedThing> findByDeviceId(Long deviceId);

    List<IotDeviceConnectedThing> findByDeviceIdIn(Collection<Long> deviceIds);
}
