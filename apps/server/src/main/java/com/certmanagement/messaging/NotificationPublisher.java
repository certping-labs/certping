// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import java.util.Map;

/**
 * Contract for publishing cert lifecycle notification events.
 */
public interface NotificationPublisher {

    void publish(String action, String organizationId, String certificateXref,
                 Map<String, Object> details);
}
