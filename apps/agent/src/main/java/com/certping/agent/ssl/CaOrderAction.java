// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

/**
 * How a commercial CA delivered a certificate: under a new order the CA charges for, or as a free replacement
 * inside an order's purchased term.
 */
public enum CaOrderAction {
    NEW_ORDER,
    REPLACEMENT
}
