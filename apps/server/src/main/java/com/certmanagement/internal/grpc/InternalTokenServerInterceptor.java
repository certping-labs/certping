// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Every call to the internal gRPC server carries the internal token ({@code CERTPING_INTERNAL_TOKEN})
 * as {@code authorization: Bearer <token>} metadata, compared in constant time; any other call is
 * closed UNAUTHENTICATED before it reaches a service. With no token configured every call is
 * refused: only the notifier calls this port, and it holds the token.
 */
@Slf4j
class InternalTokenServerInterceptor implements ServerInterceptor {

    static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    private final byte[] token;

    InternalTokenServerInterceptor(String token) {
        String trimmed = token == null ? "" : token.trim();
        this.token = trimmed.getBytes(StandardCharsets.UTF_8);
        if (trimmed.isEmpty()) {
            log.warn("[INTERNAL_GRPC_NO_TOKEN] CERTPING_INTERNAL_TOKEN is not set: every internal gRPC call is refused");
        }
    }

    @Override
    public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
        if (!authorized(headers.get(AUTHORIZATION))) {
            call.close(Status.UNAUTHENTICATED.withDescription("internal token required"), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        return next.startCall(call, headers);
    }

    boolean authorized(String authorization) {
        if (token.length == 0 || authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        return MessageDigest.isEqual(token, authorization.substring(7).trim().getBytes(StandardCharsets.UTF_8));
    }
}
