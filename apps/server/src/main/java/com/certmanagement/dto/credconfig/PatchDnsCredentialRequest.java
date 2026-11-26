// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PatchDnsCredentialRequest {

    /**
     * The domain key in dns_config to update (primary or any SAN domain).
     * e.g. "example.org"
     */
    @NotBlank
    private String targetDomain;

    /**
     * The new DNS credentialXref to bind to this domain.
     * Must be type=DNS, status=ACTIVE.
     */
    @NotBlank
    private String credentialXref;
}
