// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * The {@code caStatus} an agent sends with its heartbeat: which CAs it can issue from.
 *
 * <p>Only the fields named here are read, stored and returned; anything else in the payload is
 * dropped on parsing. That is deliberate: whatever an agent sends, no key material can reach the
 * database or an API through this object, because it has no field that could hold it.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentCaStatus {

    private Acme acme;
    private Configured globalsign;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Acme {
        private String directoryUrl;
        private String environment;
        private String contactEmail;
        private List<AcmeAccount> accounts;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AcmeAccount {
        private String organizationId;
        private String accountUrl;
        private String keyType;
        private String createdAt;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Configured {
        private boolean configured;
    }
}
