// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

/** Why a certificate cannot be exported; serialised by name in the certificate DTO and the 409 body. */
public enum CertExportUnavailableReason {
    /** {@code CERTIFICATE_DOWNLOAD} is off for the org; DTO only (the export endpoint answers 423). */
    FEATURE_DISABLED,
    /** No longer produced: every CA the platform stores can be exported. Kept for older clients. */
    NOT_LETS_ENCRYPT,
    NOT_PLATFORM_STORED,
    NOT_ACTIVE,
    EXPIRED,
    KEY_HELD_EXTERNALLY,
    NO_MATERIAL
}
