// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import com.certmanagement.validation.ValidDomain;
import com.certmanagement.validation.ValidSanPattern;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

/**
 * Request body for {@code POST /api/v1/certs/issue-manual}.
 *
 * <p>No DNS credential is needed — the user manages their own DNS zone.
 * Only Let's Encrypt (ACME DNS-01) is supported for the manual flow.
 */
@Data
public class IssueManualRequest {

    @NotBlank
    @ValidDomain
    private String domain;

    private boolean wildcard;
    private boolean san;

    /**
     * KV path to an existing ACME account key, when retrying after an expired order.
     * Null on first issuance — the agent creates a new account and returns the path.
     */
    private String acmeAccountHandle;

    /** SAN domain entries (domain patterns only — no DNS credential for the manual flow). */
    @Valid
    private List<SanDomainEntry> sanDomainEntries;

    @Data
    public static class SanDomainEntry {

        @NotEmpty
        private List<@ValidSanPattern String> patterns;
    }
}
