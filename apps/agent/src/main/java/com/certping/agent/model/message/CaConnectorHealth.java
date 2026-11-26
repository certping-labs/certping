// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Health of a single CA connector.
 *
 * <p>Every field is provider-neutral. Provider-specific detail belongs in {@link #profiles} or
 * {@link #issues}, both of which are open key/value shapes, rather than in new top-level fields —
 * that is what keeps this payload stable as CAs are added.
 */
@Data
@Builder
public class CaConnectorHealth {

    /** Matches {@code CaProvider}, e.g. {@code EJBCA}, {@code DIGICERT}. */
    private String caProvider;

    /**
     * Stable id for this connector within the agent. One per provider today; a discriminator
     * once an agent can hold two connections to the same provider.
     */
    private String connectorId;

    /** False when the operator has not turned this connector on — not a fault. */
    private Boolean enabled;

    /** See {@link CaConnectorStatus}. Sent as a string so an unknown value cannot break parsing. */
    private String status;

    private String checkedAt;

    /** Round trip for the reachability probe. Null when the probe never ran. */
    private Long latencyMs;

    /** Non-secret endpoint the connector talks to, for operator display. Never credentials. */
    private String endpoint;

    /** Product identification as reported by the CA itself, when it exposes it. */
    private CaProductInfo product;

    /** How the agent authenticates, e.g. {@code CLIENT_CERT}, {@code OAUTH_CLIENT_CREDENTIALS}, {@code API_KEY}. */
    private String authMethod;

    /** What this connector can currently do, e.g. {@code SIGN_CSR}, {@code REVOKE}, {@code DISCOVER}. */
    private List<String> capabilities;

    /** Profile-ish references this connector is configured to use. */
    private List<CaProfileRef> profiles;

    /** Anything an operator needs to act on. Empty when healthy. */
    private List<CaHealthIssue> issues;
}
