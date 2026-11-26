// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery;

import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.model.message.DiscoveryFailedScope;

import java.util.List;

/**
 * What a discovery scan found, plus the scopes it could not read. An empty {@code failedScopes}
 * means the scan saw everything it was asked to scan.
 */
public record DiscoveryResult(List<DiscoveredCertEntry> certificates, List<DiscoveryFailedScope> failedScopes) {

    public DiscoveryResult {
        certificates = certificates == null ? List.of() : List.copyOf(certificates);
        failedScopes = failedScopes == null ? List.of() : List.copyOf(failedScopes);
    }

    public static DiscoveryResult complete(List<DiscoveredCertEntry> certificates) {
        return new DiscoveryResult(certificates, List.of());
    }

    public boolean partial() {
        return !failedScopes.isEmpty();
    }
}
