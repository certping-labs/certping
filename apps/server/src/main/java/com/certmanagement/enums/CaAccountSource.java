// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/** Whose account at the CA placed the order. */
public enum CaAccountSource {
    /** CertPing's own CA credentials, held by the agent. */
    PLATFORM,
    /** A CA credential the organization added. */
    CUSTOMER;

    /** The source today's issuance uses for {@code ca}: Let's Encrypt needs no account and gets none. */
    public static CaAccountSource forIssuance(CaProvider ca, boolean customerCredential) {
        if (ca == null || ca == CaProvider.LETS_ENCRYPT) {
            return null;
        }
        return customerCredential ? CUSTOMER : PLATFORM;
    }
}
