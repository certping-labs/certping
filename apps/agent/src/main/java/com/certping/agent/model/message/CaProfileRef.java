// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;

/**
 * A named thing on the CA that this connector issues against.
 *
 * <p>Intentionally just {@code kind} + {@code name}: CAs disagree wildly on what a "profile" is
 * (EJBCA splits certificate and end entity profiles, DigiCert has products, Smallstep has
 * provisioners), and modelling that union would guarantee churn.
 */
@Data
@Builder
public class CaProfileRef {

    /** e.g. {@code CA}, {@code CERTIFICATE_PROFILE}, {@code END_ENTITY_PROFILE}, {@code PRODUCT}, {@code PROVISIONER}. */
    private String kind;

    private String name;

    /**
     * Whether the agent confirmed this exists on the CA. Null when it could not be checked —
     * which is the honest answer for a CA that exposes no way to enumerate profiles.
     */
    private Boolean verified;
}
