// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;

/** Smallstep revocation backed by step-ca's durable store and verified signed CRL. */
@Service
@RequiredArgsConstructor
public class SmallstepRevocationService {
    private final SmallstepClient client;
    private final AgentProperties properties;

    public Result revoke(String issuerDn, String serialNumber, String reason) {
        requireEnabled();
        return client.revoke(issuerDn, serialNumber, reason);
    }

    public void assertRenewalAllowed(X509Certificate certificate) {
        requireEnabled();
        if (client.isRevoked(certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(16))) {
            throw new PermanentAgentException("SMALLSTEP_CERTIFICATE_REVOKED",
                    "Smallstep reports the renewal certificate as revoked");
        }
    }

    /** Verifies that a fresh, signed CRL is available before reporting revocation capability. */
    public void verifyReady() {
        requireEnabled();
        client.verifyRevocationReady();
    }

    private void requireEnabled() {
        if (!properties.getSmallstep().isEnabled()) {
            throw new PermanentAgentException("SMALLSTEP_DISABLED",
                    "Smallstep is disabled. Set agent.smallstep.enabled=true.");
        }
    }

    public record Result(boolean alreadyRevoked, String reason, String observedAt) {}
}
