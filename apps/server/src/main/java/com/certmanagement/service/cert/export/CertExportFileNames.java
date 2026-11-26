// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * Turns a certificate's common name into a file-name stem safe for a {@code Content-Disposition}
 * header and every desktop file system: only {@code [a-z0-9._-]}, a leading wildcard label written
 * as {@code _wildcard}, no dot runs or leading dots, bounded length.
 */
final class CertExportFileNames {

    static final int MAX_STEM_LENGTH = 100;
    private static final String FALLBACK_STEM = "certificate";

    private CertExportFileNames() {
    }

    /**
     * The file-name stem for an export: the leaf's subject CN (what the customer sees in their
     * tooling, wildcard included), else the certificate's primary domain, wildcard-prefixed when the
     * certificate is a wildcard.
     */
    static String stemFor(X509Certificate leaf, String primaryDomain, boolean wildcard) {
        RDN[] commonNames = X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded()).getRDNs(BCStyle.CN);
        if (commonNames.length > 0) {
            return safeCommonName(IETFUtils.valueToString(commonNames[0].getFirst().getValue()));
        }
        boolean needsWildcardLabel = wildcard && primaryDomain != null && !primaryDomain.startsWith("*.");
        return safeCommonName(needsWildcardLabel ? "*." + primaryDomain : primaryDomain);
    }

    static String safeCommonName(String commonName) {
        if (commonName == null) {
            return FALLBACK_STEM;
        }
        String stem = commonName.strip().toLowerCase(Locale.ROOT)
                .replace("*", "_wildcard")
                .replaceAll("[^a-z0-9._-]", "-")
                .replaceAll("\\.{2,}", ".")
                .replaceAll("^[.-]+", "")
                .replaceAll("[.-]+$", "");
        if (stem.length() > MAX_STEM_LENGTH) {
            stem = stem.substring(0, MAX_STEM_LENGTH).replaceAll("[.-]+$", "");
        }
        return stem.isEmpty() ? FALLBACK_STEM : stem;
    }

    static String fileName(String commonName, CertExportFormat format) {
        return safeCommonName(commonName) + format.fileNameSuffix();
    }
}
