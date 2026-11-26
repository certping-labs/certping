// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

/**
 * Supported certificate authority providers.
 * Mirrors the CaProvider enum in the agent (apps/agent).
 */
public enum CaProvider {
    LETS_ENCRYPT,
    DIGICERT,
    GLOBALSIGN
}
