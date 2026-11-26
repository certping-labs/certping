// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.model.enums.CaProvider;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The result of a CA-backend sign: the issued leaf and its chain, plus the identifiers only the
 * backend knows — the CA provider and the name the CA filed the device under (EJBCA end entity).
 * These feed the {@code SCEP_CERT_ISSUED} record so the server can key revocation and correlate the
 * certificate back to the device.
 */
public record IssuedCertificate(
        List<X509Certificate> chain,
        String endEntityName,
        CaProvider caProvider,
        String caName,
        String provisionerName) {

    public IssuedCertificate(List<X509Certificate> chain, String endEntityName, CaProvider caProvider) {
        this(chain, endEntityName, caProvider, null, null);
    }

    public X509Certificate leaf() {
        return chain.get(0);
    }
}
