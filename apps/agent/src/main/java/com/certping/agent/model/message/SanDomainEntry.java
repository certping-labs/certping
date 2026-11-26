// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * One SAN group: the DNS provider type + KV credential path covering these domain patterns.
 * Patterns may be exact (api.example.com) or wildcard (*.example.com).
 */
@Data
@NoArgsConstructor
public class SanDomainEntry {
    private String dnsProvider;
    private String dnsCredentialHandle;
    private List<String> patterns;
}
