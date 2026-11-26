// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;

@Service
@RequiredArgsConstructor
public class IotIntunePollStateService {
    private final IotIntuneRevocationPollStateRepository repository;
    private final Clock clock;

    public void ensureFor(IotDeviceSource source) {
        if (source.getProvider() != DeviceSourceProvider.INTUNE) {
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        repository.insertIfAbsent(source.getOrganizationId(), source.getId(), now);
    }
}
