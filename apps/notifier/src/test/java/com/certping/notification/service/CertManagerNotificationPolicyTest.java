// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certmanagement.internal.v1.AllowsNotificationRequest;
import com.certmanagement.internal.v1.AllowsNotificationResponse;
import com.certmanagement.internal.v1.NotificationPolicyServiceGrpc;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.model.NotificationEvent;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import io.grpc.stub.StreamObserver;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The notifier's question to the server over a real gRPC channel (in process): a turned-off category
 * suppresses, and a slow, unavailable or failing server delivers, each counted. The startup check
 * runs over TCP, the connection it warms.
 */
class CertManagerNotificationPolicyTest {

    private static final long ORG = 42L;

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final List<AllowsNotificationRequest> asked = new CopyOnWriteArrayList<>();
    private final AtomicReference<Metadata> headers = new AtomicReference<>();
    private volatile BiConsumer<AllowsNotificationRequest, StreamObserver<AllowsNotificationResponse>> answer;

    private Server server;
    private ManagedChannel channel;
    private CertManagerNotificationPolicy policy;

    @BeforeEach
    void start() throws Exception {
        String name = InProcessServerBuilder.generateName();
        NotificationPolicyServiceGrpc.NotificationPolicyServiceImplBase service =
                new NotificationPolicyServiceGrpc.NotificationPolicyServiceImplBase() {
                    @Override
                    public void allowsNotification(AllowsNotificationRequest request,
                                                   StreamObserver<AllowsNotificationResponse> response) {
                        asked.add(request);
                        answer.accept(request, response);
                    }
                };
        ServerInterceptor captureHeaders = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata metadata,
                                                               ServerCallHandler<Q, R> next) {
                headers.set(metadata);
                return next.startCall(call, metadata);
            }
        };
        server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(ServerInterceptors.intercept(service, captureHeaders)).build().start();
        channel = InProcessChannelBuilder.forName(name).build();
        policy = new CertManagerNotificationPolicy(channel, meters);
    }

    @AfterEach
    void stop() throws InterruptedException {
        channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    private static NotificationEvent event(Long organizationId, NotificationAction action) {
        return NotificationEvent.builder()
                .organizationId(organizationId)
                .notificationAction(action)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .requestId("cert-renewed:CERT-1")
                .correlationId("corr-7")
                .build();
    }

    private void answers(boolean allowed, String category) {
        answer = (request, response) -> {
            response.onNext(AllowsNotificationResponse.newBuilder().setAllowed(allowed).setCategory(category).build());
            response.onCompleted();
        };
    }

    private double failed(String reason) {
        return meters.counter(CertManagerNotificationPolicy.CHECK_FAILED_METRIC, "reason", reason).count();
    }

    @Test
    void anAllowedNotificationIsDelivered() {
        answers(true, "");

        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        assertThat(asked).singleElement().satisfies(request -> {
            assertThat(request.getOrganizationId()).isEqualTo(ORG);
            assertThat(request.getAction()).isEqualTo("CERT_RENEWAL_SUCCESS");
        });
        assertThat(meters.timer(CertManagerNotificationPolicy.CHECK_METRIC, "outcome", "allowed").count()).isEqualTo(1);
    }

    @Test
    void aTurnedOffCategorySuppressesAndIsCounted() {
        answers(false, "CERTIFICATE_ACTIVITY");

        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS)))
                .contains("CERTIFICATE_ACTIVITY");
        assertThat(meters.counter(CertManagerNotificationPolicy.SUPPRESSED_METRIC, "action", "CERT_RENEWAL_SUCCESS",
                "category", "CERTIFICATE_ACTIVITY").count()).isEqualTo(1);
        assertThat(meters.timer(CertManagerNotificationPolicy.CHECK_METRIC, "outcome", "suppressed").count())
                .isEqualTo(1);
    }

    @Test
    void theCallCarriesTheEventsIds() {
        answers(true, "");

        policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS));

        assertThat(headers.get().get(CertManagerNotificationPolicy.REQUEST_ID)).isEqualTo("cert-renewed:CERT-1");
        assertThat(headers.get().get(CertManagerNotificationPolicy.CORRELATION_ID)).isEqualTo("corr-7");
    }

    @Test
    void everyCallCarriesTheInternalToken() {
        answers(true, "");
        CertManagerNotificationPolicy withToken = new CertManagerNotificationPolicy(channel, " internal-1 ", meters);

        withToken.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS));

        assertThat(headers.get().get(CertManagerNotificationPolicy.AUTHORIZATION)).isEqualTo("Bearer internal-1");
        assertThat(headers.get().get(CertManagerNotificationPolicy.REQUEST_ID)).isEqualTo("cert-renewed:CERT-1");
    }

    @Test
    void theStartupHealthCheckCarriesTheTokenToo() throws Exception {
        AtomicReference<String> sent = new AtomicReference<>();
        CountDownLatch checked = new CountDownLatch(1);
        ServerInterceptor record = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata metadata,
                                                               ServerCallHandler<Q, R> next) {
                sent.set(metadata.get(CertManagerNotificationPolicy.AUTHORIZATION));
                checked.countDown();
                return next.startCall(call, metadata);
            }
        };
        Server certManager = NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0))
                .addService(ServerInterceptors.intercept(new HealthStatusManager().getHealthService(), record))
                .build().start();
        CertManagerNotificationPolicy configured =
                new CertManagerNotificationPolicy("127.0.0.1:" + certManager.getPort(), "internal-2", meters);
        try {
            assertThat(checked.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(sent.get()).isEqualTo("Bearer internal-2");
        } finally {
            configured.destroy();
            certManager.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void aSlowAnswerDeliversAfterTheOneSecondDeadline() {
        answer = (request, response) -> { };

        long started = System.nanoTime();
        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

        assertThat(millis).isBetween(900L, 3000L);
        assertThat(asked).hasSize(1);
        assertThat(failed("DEADLINE_EXCEEDED")).isEqualTo(1);
    }

    @Test
    void anUnavailableCertManagerDeliversWithoutARetry() {
        answer = (request, response) -> response.onError(Status.UNAVAILABLE.asRuntimeException());

        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();

        assertThat(asked).hasSize(1);
        assertThat(failed("UNAVAILABLE")).isEqualTo(1);
    }

    @Test
    void anyOtherErrorDelivers() {
        answer = (request, response) -> response.onError(Status.INTERNAL.asRuntimeException());
        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();

        answer = (request, response) -> {
            throw new IllegalStateException("boom");
        };
        assertThat(policy.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();

        assertThat(failed("INTERNAL")).isEqualTo(1);
        assertThat(failed("UNKNOWN")).isEqualTo(1);
    }

    @Test
    void aNotificationWithNoOrganizationIsNeverAsked() {
        answers(false, "REPORTS");

        assertThat(policy.suppressedCategory(event(null, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        assertThat(policy.suppressedCategory(event(0L, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        assertThat(policy.suppressedCategory(event(ORG, null))).isEmpty();
        assertThat(asked).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(value = NotificationAction.class, names = {"PASSWORD_CHANGE_SUCCESS", "RESET_PASSWORD",
            "SYSTEM_DLQ_ALERT", "SYSTEM_QUEUE_DEPTH_WARNING", "SYSTEM_QUEUE_ALERT_RESOLVED"})
    void authAndPlatformEmailsAreNeverAsked(NotificationAction action) {
        answers(false, "REPORTS");

        assertThat(policy.suppressedCategory(event(ORG, action))).isEmpty();
        assertThat(asked).isEmpty();
    }

    @Test
    void withNoAddressNothingIsAskedAndEverythingIsDelivered() throws Exception {
        CertManagerNotificationPolicy unconfigured = new CertManagerNotificationPolicy(" ", meters);

        assertThat(unconfigured.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        unconfigured.destroy();
        assertThat(asked).isEmpty();
    }

    @Test
    void aConfiguredAddressBuildsAChannelThatShutsDown() throws Exception {
        CertManagerNotificationPolicy configured = new CertManagerNotificationPolicy("localhost:1", meters);

        assertThat(configured.suppressedCategory(event(ORG, NotificationAction.CERT_RENEWAL_SUCCESS))).isEmpty();
        configured.destroy();
        assertThat(failed("UNAVAILABLE")).isEqualTo(1);
    }

    @Test
    void startupConnectsWithAHealthCheckBeforeAnyNotification() throws Exception {
        List<String> called = new CopyOnWriteArrayList<>();
        CountDownLatch firstCall = new CountDownLatch(1);
        ServerInterceptor record = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata metadata,
                                                               ServerCallHandler<Q, R> next) {
                called.add(call.getMethodDescriptor().getFullMethodName());
                firstCall.countDown();
                return next.startCall(call, metadata);
            }
        };
        Server certManager = NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0))
                .addService(ServerInterceptors.intercept(new HealthStatusManager().getHealthService(), record))
                .build().start();
        CertManagerNotificationPolicy configured =
                new CertManagerNotificationPolicy("127.0.0.1:" + certManager.getPort(), meters);
        try {
            assertThat(firstCall.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(called).containsExactly("grpc.health.v1.Health/Check");
        } finally {
            configured.destroy();
            certManager.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void startupNeitherWaitsForNorFailsOnACertManagerThatNeverAnswers() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            silent.setSoTimeout(5000);

            long started = System.nanoTime();
            CertManagerNotificationPolicy configured =
                    new CertManagerNotificationPolicy("127.0.0.1:" + silent.getLocalPort(), meters);
            long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

            try (Socket connected = silent.accept()) {
                assertThat(connected.isConnected()).isTrue();
            }
            assertThat(millis).isLessThan(CertManagerNotificationPolicy.WARM_UP_DEADLINE.toMillis() / 2);
            configured.destroy();
        }
    }
}
