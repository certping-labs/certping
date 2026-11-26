// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

/**
 * What the CA says it is.
 *
 * <p>Always probed, never configured. A stored copy goes stale the moment the customer upgrades,
 * at which point the agent would be reporting a fact that is no longer true.
 */
@Data
@Builder
public class CaProductInfo {

    /** e.g. {@code EJBCA}, {@code step-ca}, {@code DigiCert ONE}. */
    private String name;

    /** e.g. {@code 9.3.7}. Null when the CA does not report one. */
    private String version;

    /** e.g. {@code Community}, {@code Enterprise}. Null when the concept does not apply. */
    private String edition;

    /** Whatever the CA returned, verbatim, for support tickets. */
    private String raw;
}
