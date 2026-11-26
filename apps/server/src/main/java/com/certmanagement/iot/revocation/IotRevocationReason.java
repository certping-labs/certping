// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

/** Safe RFC 5280 leaf-certificate revocation reasons shared by EJBCA and Smallstep. */
public enum IotRevocationReason {
    UNSPECIFIED,
    KEY_COMPROMISE,
    AFFILIATION_CHANGED,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    PRIVILEGES_WITHDRAWN
}
