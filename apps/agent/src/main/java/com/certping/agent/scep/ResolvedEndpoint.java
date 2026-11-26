// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.scep.ca.ScepCaBackend;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * One resolved SCEP endpoint. {@code endpointId} is the route key in {@code /scep/v1/{endpointId}}
 * and {@code connectionProfileRef} names the local device-source connection that owns the route —
 * they are equal except for the temporary {@code default} compatibility alias, whose route key is
 * {@code default} while it still resolves to a real source. Neither is ever a certificate
 * {@code profileXref}: every Intune certificate profile using the same connection shares this
 * endpoint. Carries no credential material — Intune credentials are resolved on demand from
 * {@code DeviceSourceCredentialRegistry} by {@code connectionProfileRef}.
 */
public record ResolvedEndpoint(
        String endpointId,
        String organizationId,
        String connectionProfileRef,
        DevicePlatformType provider,
        List<String> caps,
        ScepCaBackend caBackend) {

    public X509Certificate raCert() {
        return caBackend.getRaCertificate();
    }

    public PrivateKey raPrivateKey() {
        return caBackend.getRaPrivateKey();
    }

    public List<X509Certificate> caChain() {
        return caBackend.getCaChain();
    }
}
