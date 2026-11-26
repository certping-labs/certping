// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import java.util.List;

record KubernetesCertificateMetadata(
        String domain,
        String keyAlgorithm,
        String signatureAlgorithm,
        String notBefore,
        String notAfter,
        String issuer,
        String serialNumber,
        String certStatus,
        String subjectDn,
        List<String> sanDomains,
        String keyUsage,
        String extendedKeyUsage) {
}
