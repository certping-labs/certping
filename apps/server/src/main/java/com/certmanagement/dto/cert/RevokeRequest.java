// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import lombok.Data;

/**
 * Request body for POST /revoke.
 * Actor identity comes from JWT userId in {@code GatewayRequestContext}.
 */
@Data
public class RevokeRequest {

    /**
     * RFC 5280 revocation reason.
     * Accepted values: UNSPECIFIED | KEY_COMPROMISE | CA_COMPROMISE |
     * AFFILIATION_CHANGED | SUPERSEDED | CESSATION_OF_OPERATION
     */
    private String reason;
}
