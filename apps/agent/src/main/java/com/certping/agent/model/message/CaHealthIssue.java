// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

/**
 * One actionable problem with a connector.
 *
 * <p>{@code remediation} is the point of this type: a status code tells an operator something is
 * wrong, this tells them what to do about it. It is written for a human, not for parsing.
 */
@Data
@Builder
public class CaHealthIssue {

    /** {@code ERROR} blocks issuance; {@code WARN} does not, yet. */
    private String severity;

    /** Stable machine-readable code, e.g. {@code EJBCA_REST_DISABLED}, {@code CA_CONFIG_MISSING}. */
    private String code;

    /** What is wrong. Must never contain credentials. */
    private String message;

    /** What the operator should do. Null when there is nothing useful to say. */
    private String remediation;
}
