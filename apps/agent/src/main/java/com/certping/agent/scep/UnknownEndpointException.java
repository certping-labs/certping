// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/** {@code endpointId} does not resolve to a configured SCEP endpoint. HTTP 400. */
public class UnknownEndpointException extends RuntimeException {
    public UnknownEndpointException(String endpointId) {
        super("unknown endpointId: " + endpointId);
    }
}
