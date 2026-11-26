// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

import jakarta.persistence.PostPersist;
import jakarta.persistence.PostRemove;
import jakarta.persistence.PostUpdate;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/** JPA entity listener that publishes {@link CertificateInventoryChangedEvent} for every persisted change. */
@Component
@RequiredArgsConstructor
public class CertificateInventoryEntityListener {

    private final ApplicationEventPublisher eventPublisher;

    @PostPersist
    @PostUpdate
    @PostRemove
    public void onChange(Object entity) {
        eventPublisher.publishEvent(new CertificateInventoryChangedEvent());
    }
}
