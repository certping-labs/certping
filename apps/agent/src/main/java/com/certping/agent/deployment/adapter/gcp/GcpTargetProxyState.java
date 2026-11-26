// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import java.util.List;

/**
 * The certificate fields of a target proxy: its {@code sslCertificates} (Certificate Manager
 * prefixes stripped) and the certificate map it serves from, or {@code null} if none.
 */
public record GcpTargetProxyState(List<String> sslCertificates, String certificateMap) {

    public boolean usesCertificateMap() {
        return certificateMap != null && !certificateMap.isBlank();
    }
}
