// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import java.util.UUID;

/**
 * New certificate xrefs: {@code cert-} plus a random UUID (41 characters, the columns hold 100). The old
 * {@code cert-} plus {@code System.nanoTime()} collided when certificates were created at the same moment
 * on different servers or threads, and a collision is a 409 on the unique certificate_xref.
 */
public final class CertificateXrefs {

    public static final String PREFIX = "cert-";

    private CertificateXrefs() {
    }

    public static String newXref() {
        return PREFIX + UUID.randomUUID();
    }
}
