// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * The internal gRPC server the notifier calls, bound from {@code certping.internal-grpc.*}.
 *
 * @param enabled                   off only where nothing calls it
 * @param port                      container port; reached over Kubernetes DNS, never through the ingress
 * @param threads                   request threads; each call holds a database connection at most briefly
 * @param maxConcurrentCallsPerConnection calls one client connection may have in flight; the rest
 *                                  queue on the client, so the thread pool's queue stays bounded
 * @param shutdownGrace             how long in-flight calls get to finish when the pod stops
 * @param bindAddress               the address the port is opened on: 127.0.0.1 on one machine
 *                                  (the all-in-one), the pod IP in Kubernetes, the server's name on
 *                                  the notifier network in Compose. A name is resolved at start.
 */
@ConfigurationProperties(prefix = "certping.internal-grpc")
public record InternalGrpcProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("50051") int port,
        @DefaultValue("8") int threads,
        @DefaultValue("32") int maxConcurrentCallsPerConnection,
        @DefaultValue("10s") Duration shutdownGrace,
        @DefaultValue("127.0.0.1") String bindAddress) {
}
