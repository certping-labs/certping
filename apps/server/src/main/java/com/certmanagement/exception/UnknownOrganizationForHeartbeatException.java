// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

/**
 * Thrown when a heartbeat targets an {@code organizationId} that has no row in {@code organizations}.
 * Callers (e.g. message processor) may acknowledge the message to avoid infinite redelivery.
 */
public class UnknownOrganizationForHeartbeatException extends RuntimeException {

    private final Long organizationId;

    public UnknownOrganizationForHeartbeatException(Long organizationId) {
        super("No organization for id " + organizationId);
        this.organizationId = organizationId;
    }

    public Long getOrganizationId() {
        return organizationId;
    }
}
