// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Which certificate authorities this agent can issue from, sent with every heartbeat.
 *
 * <p>Metadata only. Nothing here may ever carry key material: no ACME account key,
 * no GlobalSign API key or secret. The ACME part names the account by its URL and key type; the
 * others only say whether the operator configured them.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaStatus {

    private Acme acme;
    private Configured globalsign;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Acme {
        private String directoryUrl;
        /** PRODUCTION or STAGING for the Let's Encrypt directories, CUSTOM for anything else. */
        private String environment;
        /** The contact registered on new accounts; empty when none is configured. */
        private String contactEmail;
        private List<AcmeAccount> accounts;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AcmeAccount {
        private String organizationId;
        /** Null for an account registered before the agent recorded it. */
        private String accountUrl;
        /** For example "RSA 2048". */
        private String keyType;
        /** ISO-8601; null when the creation time was not recorded. */
        private String createdAt;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Configured {
        private boolean configured;
    }
}
