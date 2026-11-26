// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

/**
 * A rendered export, ready to stream.
 *
 * @param content   the file bytes; may hold private key material, so the caller must not log or cache it
 * @param mediaType the {@code Content-Type} to serve it with
 * @param fileName  the sanitised {@code Content-Disposition} file name
 */
public record ExportedCertificateFile(byte[] content, String mediaType, String fileName) {

    /** Never prints the content. */
    @Override
    public String toString() {
        return "ExportedCertificateFile[mediaType=" + mediaType + ", fileName=" + fileName
                + ", bytes=" + (content == null ? 0 : content.length) + "]";
    }
}
