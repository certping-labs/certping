// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import com.certmanagement.internal.v1.AllowsNotificationRequest;
import com.certmanagement.internal.v1.AllowsNotificationResponse;
import com.certmanagement.internal.v1.NotificationPolicyServiceGrpc;
import com.certmanagement.service.notification.NotificationPreferenceService;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.health.v1.HealthGrpc;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.MetadataUtils;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The internal gRPC port opens on the configured address and answers only the internal token. */
class InternalGrpcServerTest {

    private static final String TOKEN = "internal-token-value";

    private final NotificationPreferenceService preferences = mock(NotificationPreferenceService.class);
    private InternalGrpcServer server;
    private ManagedChannel channel;

    @AfterEach
    void stop() throws InterruptedException {
        if (channel != null) {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void itBindsTheConfiguredAddress() {
        start("127.0.0.1", TOKEN);

        InetSocketAddress bound = (InetSocketAddress) server.boundAddress();
        assertThat(bound.getAddress().isLoopbackAddress()).isTrue();
        assertThat(bound.getAddress().isAnyLocalAddress()).isFalse();
        assertThat(bound.getPort()).isEqualTo(server.port()).isPositive();
    }

    @Test
    void theDefaultBindAddressIsLoopback() {
        InetSocketAddress address = InternalGrpcServer.bindAddress(properties(null));
        assertThat(address.getAddress().isLoopbackAddress()).isTrue();
    }

    @Test
    void anUnresolvableBindAddressFailsStart() {
        assertThatThrownBy(() -> InternalGrpcServer.bindAddress(properties("no-such-host.invalid")))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("no-such-host.invalid");
    }

    @Test
    void aCallWithoutTheTokenIsRejected() {
        start("127.0.0.1", TOKEN);

        assertUnauthenticated(policy(null));
        assertUnauthenticated(policy("Bearer wrong"));
        assertUnauthenticated(policy(TOKEN));
        assertThatThrownBy(() -> HealthGrpc.newBlockingStub(channel()).withDeadlineAfter(5, TimeUnit.SECONDS)
                .check(HealthCheckRequest.getDefaultInstance()))
                .isInstanceOfSatisfying(StatusRuntimeException.class,
                        e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED));
        verify(preferences, never()).allows(anyLong(), anyString());
    }

    @Test
    void aCallWithTheTokenIsAnswered() {
        when(preferences.allows(7L, "CERT_EXPIRY_ALERT")).thenReturn(true);
        start("127.0.0.1", TOKEN);

        AllowsNotificationResponse answer = policy("Bearer " + TOKEN).allowsNotification(request());
        assertThat(answer.getAllowed()).isTrue();
        assertThat(HealthGrpc.newBlockingStub(channel())
                .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(auth("Bearer " + TOKEN)))
                .check(HealthCheckRequest.getDefaultInstance()).getStatus()).isEqualTo(ServingStatus.SERVING);
    }

    @Test
    void withNoTokenConfiguredEveryCallIsRejected() {
        start("127.0.0.1", "");

        assertUnauthenticated(policy("Bearer "));
        assertUnauthenticated(policy(null));
    }

    private void assertUnauthenticated(NotificationPolicyServiceGrpc.NotificationPolicyServiceBlockingStub stub) {
        assertThatThrownBy(() -> stub.allowsNotification(request()))
                .isInstanceOfSatisfying(StatusRuntimeException.class,
                        e -> assertThat(e.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED));
    }

    private NotificationPolicyServiceGrpc.NotificationPolicyServiceBlockingStub policy(String authorization) {
        var stub = NotificationPolicyServiceGrpc.newBlockingStub(channel()).withDeadlineAfter(5, TimeUnit.SECONDS);
        return authorization == null ? stub : stub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(auth(authorization)));
    }

    private static Metadata auth(String authorization) {
        Metadata headers = new Metadata();
        headers.put(InternalTokenServerInterceptor.AUTHORIZATION, authorization);
        return headers;
    }

    private static AllowsNotificationRequest request() {
        return AllowsNotificationRequest.newBuilder().setOrganizationId(7L).setAction("CERT_EXPIRY_ALERT").build();
    }

    private ManagedChannel channel() {
        if (channel == null) {
            channel = NettyChannelBuilder.forAddress("127.0.0.1", server.port()).usePlaintext().build();
        }
        return channel;
    }

    private void start(String bindAddress, String token) {
        server = new InternalGrpcServer(properties(bindAddress), new NotificationPolicyGrpcService(preferences),
                new RequestContextServerInterceptor(new SimpleMeterRegistry()), token);
        server.start();
    }

    private static InternalGrpcProperties properties(String bindAddress) {
        return new InternalGrpcProperties(true, 0, 2, 8, Duration.ofSeconds(1), bindAddress);
    }
}
