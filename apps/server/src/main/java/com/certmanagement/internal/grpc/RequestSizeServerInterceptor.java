// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.internal.grpc;

import com.google.protobuf.MessageLite;
import io.grpc.ForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;

import java.util.Set;

/**
 * Holds every method but the ones named to {@link #DEFAULT_MAX_REQUEST_BYTES}. If the server's own cap
 * is raised for a method that needs larger requests, this keeps the others, which take a few ids or a
 * code, from being handed hundreds of kilobytes to parse and hold. No method is named today.
 *
 * <p>An oversized request is closed RESOURCE_EXHAUSTED before it reaches the method, as the
 * transport would have closed it.
 */
class RequestSizeServerInterceptor implements ServerInterceptor {

    static final int DEFAULT_MAX_REQUEST_BYTES = 64 * 1024;

    private final Set<String> largeRequestMethods;

    RequestSizeServerInterceptor(Set<String> largeRequestMethods) {
        this.largeRequestMethods = Set.copyOf(largeRequestMethods);
    }

    @Override
    public <Q, R> ServerCall.Listener<Q> interceptCall(ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
        ServerCall.Listener<Q> listener = next.startCall(call, headers);
        if (largeRequestMethods.contains(call.getMethodDescriptor().getFullMethodName())) {
            return listener;
        }
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
            private boolean refused;

            @Override
            public void onMessage(Q message) {
                if (refused) {
                    return;
                }
                if (message instanceof MessageLite request && request.getSerializedSize() > DEFAULT_MAX_REQUEST_BYTES) {
                    refused = true;
                    call.close(Status.RESOURCE_EXHAUSTED.withDescription(
                            "request is " + request.getSerializedSize() + " bytes, at most " + DEFAULT_MAX_REQUEST_BYTES), new Metadata());
                    return;
                }
                super.onMessage(message);
            }

            @Override
            public void onHalfClose() {
                if (!refused) {
                    super.onHalfClose();
                }
            }
        };
    }
}
