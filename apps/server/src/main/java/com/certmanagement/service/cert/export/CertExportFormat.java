// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.security.Permissions;

import java.util.Set;

/** The file shapes a certificate can be exported in, with the media type and file-name suffix each is served with. */
public enum CertExportFormat {

    FULLCHAIN_PEM(CertExportFormat.PEM_MEDIA_TYPE, "-fullchain.pem", false),
    CERTIFICATE_PEM(CertExportFormat.PEM_MEDIA_TYPE, "-cert.pem", false),
    /** The leaf alone, binary DER. */
    CERTIFICATE_DER("application/pkix-cert", "-cert.der", false),
    /** The whole chain as a PKCS#7 certificate bundle (.p7b), for Windows and Tomcat. */
    PKCS7("application/x-pkcs7-certificates", "-chain.p7b", false),
    PRIVATE_KEY_PEM(CertExportFormat.PEM_MEDIA_TYPE, "-privkey.pem", true),
    PKCS12("application/x-pkcs12", ".pfx", true);

    private static final String PEM_MEDIA_TYPE = "application/x-pem-file";

    private final String mediaType;
    private final String fileNameSuffix;
    private final boolean includesPrivateKey;

    CertExportFormat(String mediaType, String fileNameSuffix, boolean includesPrivateKey) {
        this.mediaType = mediaType;
        this.fileNameSuffix = fileNameSuffix;
        this.includesPrivateKey = includesPrivateKey;
    }

    public String mediaType() {
        return mediaType;
    }

    public String fileNameSuffix() {
        return fileNameSuffix;
    }

    public boolean includesPrivateKey() {
        return includesPrivateKey;
    }

    /**
     * Whether a caller holding {@code callerPermissions} may download this format. Every format needs
     * {@code certificate:read} (enforced on the endpoint); one carrying the private key also needs
     * {@code certificate:deploy}, the permission that already hands keys to deployment targets. The
     * match is exact, as in {@code CustomPermissionEvaluator}.
     */
    public boolean isPermittedFor(Set<String> callerPermissions) {
        return !includesPrivateKey || callerPermissions.contains(Permissions.CERTIFICATE_DEPLOY);
    }
}
