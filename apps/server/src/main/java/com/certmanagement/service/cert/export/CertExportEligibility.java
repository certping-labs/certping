// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import java.util.Arrays;
import java.util.List;

/**
 * The {@code export} object on the certificate detail DTO.
 *
 * @param available whether {@code POST .../export} can be attempted for the certificate
 * @param reason    why it cannot, or {@code null} when it can
 * @param formats   the formats on offer; empty when unavailable
 */
public record CertExportEligibility(boolean available, CertExportUnavailableReason reason,
                                   List<CertExportFormat> formats) {

    private static final List<CertExportFormat> ALL_FORMATS = List.copyOf(Arrays.asList(CertExportFormat.values()));

    private static final List<CertExportFormat> WITHOUT_PRIVATE_KEY = ALL_FORMATS.stream()
            .filter(format -> !format.includesPrivateKey()).toList();

    public static CertExportEligibility exportable() {
        return new CertExportEligibility(true, null, ALL_FORMATS);
    }

    /** The certificate and chain only: CertPing holds no private key for the certificate. */
    public static CertExportEligibility exportableWithoutPrivateKey() {
        return new CertExportEligibility(true, null, WITHOUT_PRIVATE_KEY);
    }

    public static CertExportEligibility unavailable(CertExportUnavailableReason reason) {
        return new CertExportEligibility(false, reason, List.of());
    }
}
