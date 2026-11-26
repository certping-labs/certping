// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import io.grpc.protobuf.services.ProtoReflectionService;
import io.grpc.protobuf.services.ProtoReflectionServiceV1;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Serves {@code NotificationPolicyService} to the notifier on its own port, pod to pod.
 *
 * <p>Every call carries the internal token as metadata (InternalTokenServerInterceptor), and the
 * port opens only on {@code certping.internal-grpc.bind-address}: loopback on one machine, the pod
 * IP in Kubernetes (where a NetworkPolicy also admits only the notifier). Reflection is on so
 * {@code grpcurl} works without the .proto (with the token header); health answers the standard check.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "certping.internal-grpc", name = "enabled", havingValue = "true", matchIfMissing = true)
public class InternalGrpcServer implements SmartLifecycle {

    /**
     * A Service balances connections, not calls, so one long-lived connection would pin a client
     * pod to one server pod. Ageing connections out spreads clients over new pods as they come.
     */
    private static final Duration MAX_CONNECTION_AGE = Duration.ofMinutes(5);
    private static final Duration MAX_CONNECTION_AGE_GRACE = Duration.ofSeconds(30);

    /** Every method is held to {@link RequestSizeServerInterceptor#DEFAULT_MAX_REQUEST_BYTES}. */
    static final int MAX_INBOUND_MESSAGE_BYTES = RequestSizeServerInterceptor.DEFAULT_MAX_REQUEST_BYTES;

    private final InternalGrpcProperties properties;
    private final NotificationPolicyGrpcService notificationPolicy;
    private final RequestContextServerInterceptor requestContext;
    private final RequestSizeServerInterceptor requestSize = new RequestSizeServerInterceptor(
            Set.of());

    private volatile Server server;
    private volatile ExecutorService executor;
    private volatile HealthStatusManager health;

    private final InternalTokenServerInterceptor internalToken;

    public InternalGrpcServer(InternalGrpcProperties properties,
                              NotificationPolicyGrpcService notificationPolicy,
                              RequestContextServerInterceptor requestContext,
                              @Value("${certping.transport.internal-token:}") String internalToken) {
        this.properties = properties;
        this.notificationPolicy = notificationPolicy;
        this.requestContext = requestContext;
        this.internalToken = new InternalTokenServerInterceptor(internalToken);
    }

    /** Where the port is opened: {@code bindAddress}, resolved now, or every interface for "0.0.0.0". */
    static InetSocketAddress bindAddress(InternalGrpcProperties properties) {
        String host = properties.bindAddress() == null || properties.bindAddress().isBlank()
                ? "127.0.0.1" : properties.bindAddress().trim();
        try {
            return new InetSocketAddress(InetAddress.getByName(host), properties.port());
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Internal gRPC bind address " + host + " does not resolve", e);
        }
    }

    @Override
    @SuppressWarnings("deprecation") // v1alpha reflection too: grpcurl before 1.9 asks only for it
    public synchronized void start() {
        if (server != null) {
            return;
        }
        executor = Executors.newFixedThreadPool(properties.threads(), threadFactory());
        health = new HealthStatusManager();
        InetSocketAddress address = bindAddress(properties);
        Server built = NettyServerBuilder.forAddress(address)
                .executor(executor)
                .maxInboundMessageSize(MAX_INBOUND_MESSAGE_BYTES)
                .maxConcurrentCallsPerConnection(properties.maxConcurrentCallsPerConnection())
                .maxConnectionAge(MAX_CONNECTION_AGE.toMillis(), TimeUnit.MILLISECONDS)
                .maxConnectionAgeGrace(MAX_CONNECTION_AGE_GRACE.toMillis(), TimeUnit.MILLISECONDS)
                // The size check runs inside the request context, so a refusal is logged and counted.
                // The token check is the last listed, so it runs first: nothing reaches a service,
                // health or reflection without the internal token.
                .addService(ServerInterceptors.intercept(notificationPolicy, requestSize, requestContext, internalToken))
                .addService(ServerInterceptors.intercept(health.getHealthService(), requestSize, internalToken))
                .addService(ServerInterceptors.intercept(ProtoReflectionServiceV1.newInstance(), requestSize, internalToken))
                .addService(ServerInterceptors.intercept(ProtoReflectionService.newInstance(), requestSize, internalToken))
                .build();
        try {
            built.start();
        } catch (IOException e) {
            executor.shutdownNow();
            throw new UncheckedIOException("Internal gRPC server could not bind " + address, e);
        }
        server = built;
        health.setStatus("", ServingStatus.SERVING);
        health.setStatus(NotificationPolicyGrpcService.SERVICE_NAME, ServingStatus.SERVING);
        log.info("[INTERNAL_GRPC_STARTED] address={} port={} threads={}", address.getAddress().getHostAddress(),
                built.getPort(), properties.threads());
    }

    @Override
    public synchronized void stop() {
        Server running = server;
        if (running == null) {
            return;
        }
        health.enterTerminalState();
        running.shutdown();
        try {
            if (!running.awaitTermination(properties.shutdownGrace().toMillis(), TimeUnit.MILLISECONDS)) {
                running.shutdownNow();
            }
        } catch (InterruptedException e) {
            running.shutdownNow();
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdownNow();
            server = null;
        }
        log.info("[INTERNAL_GRPC_STOPPED]");
    }

    @Override
    public boolean isRunning() {
        return server != null;
    }

    /** The bound port; differs from the setting only when that is 0, in tests. */
    public int port() {
        return server.getPort();
    }

    /** The bound socket address. */
    public SocketAddress boundAddress() {
        return server.getListenSockets().get(0);
    }

    private static ThreadFactory threadFactory() {
        AtomicInteger count = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "internal-grpc-" + count.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
