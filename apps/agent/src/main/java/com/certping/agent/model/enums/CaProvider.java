// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.enums;

public enum CaProvider {
    LETS_ENCRYPT,
    DIGICERT,
    GLOBALSIGN,
    /** Customer-operated EJBCA. Signing-only today (machine identity / SCEP path). */
    EJBCA,
    /** Customer-operated or hosted Smallstep step-ca. */
    SMALLSTEP
}
