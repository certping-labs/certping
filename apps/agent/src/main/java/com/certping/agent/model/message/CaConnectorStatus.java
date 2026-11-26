// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

/**
 * Provider-neutral connector states, ordered from healthy to worst.
 *
 * <p>The distinctions are the ones an operator acts on differently — which is why
 * "unreachable" and "unauthorized" are not collapsed into a single error state.
 */
public enum CaConnectorStatus {

    /** Reachable, authenticated, and configured well enough to issue. */
    HEALTHY,

    /** Usable, but something will bite later — e.g. an EOL CA version, or a permissive profile. */
    DEGRADED,

    /** Operator has not finished configuring it. Not a fault; nothing is broken yet. */
    UNCONFIGURED,

    /** Endpoint did not answer: network, DNS, TLS, or the API is switched off. */
    UNREACHABLE,

    /** Endpoint answered and rejected our credential. */
    UNAUTHORIZED,

    /** Answered, credential accepted, but the connector still cannot work. */
    ERROR
}
