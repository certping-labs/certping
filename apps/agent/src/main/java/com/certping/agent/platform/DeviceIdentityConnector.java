// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.message.DeviceIdentityEntry;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Pulls device identities from one management platform.
 *
 * <p>Everything platform-specific lives behind this interface: how credentials are shaped, how
 * the API authenticates, how it pages, and how a raw device maps onto {@link DeviceIdentityEntry}.
 * {@code DeviceIdentitySyncProcessor} owns the parts that are the same everywhere — batching,
 * message framing, completion and error reporting.
 *
 * <p>Adding a platform is one implementation of this interface plus a
 * {@link DeviceIdentityConnectorFor} annotation. No change to the processor, the listener or
 * the message types.
 */
public interface DeviceIdentityConnector {

    /**
     * Proves the credentials and permissions work, without ingesting the fleet.
     *
     * @return a small count worth reporting back — typically how many records a probe call saw
     * @throws com.certping.agent.exception.AgentException with a {@code PLATFORM_*} code on failure
     */
    int testConnection(DeviceSourceProfile profile);

    /** Structured, non-secret health evidence suitable for the server's source-health snapshot. */
    default ConnectionTestResult testConnectionDetails(DeviceSourceProfile profile) {
        return new ConnectionTestResult(testConnection(profile), Map.of());
    }

    /**
     * Streams the complete device list, a page at a time.
     *
     * <p>Always the full set: a partial result would make a device that merely was not returned
     * indistinguishable from one that was deleted, and the server's orphan detection would
     * then mark live devices as gone.
     *
     * @param pageConsumer called once per page; implementations must not buffer the whole fleet
     */
    void streamDevices(DeviceSourceProfile profile, Consumer<List<DeviceIdentityEntry>> pageConsumer);

    record ConnectionTestResult(
            int visibleDeviceSample,
            Map<String, Object> metadata,
            String healthStatus,
            String providerStatus,
            String statusMessage) {

        public ConnectionTestResult(int visibleDeviceSample, Map<String, Object> metadata) {
            this(visibleDeviceSample, metadata, "HEALTHY", "CONNECTED", null);
        }

        public ConnectionTestResult {
            metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        }
    }
}
