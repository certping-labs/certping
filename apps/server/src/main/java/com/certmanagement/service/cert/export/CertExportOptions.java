// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.exception.CertExportException;

import java.util.Arrays;

/**
 * A validated export request. Holds the PKCS12 password as a {@code char[]} so it can be wiped once
 * the file is built; {@link #close()} does that and must be called (try-with-resources).
 *
 * <p>Wiping is best-effort: wipes the password char[] and PKCS#8 buffer we own; copies held by the
 * servlet/Jackson layers cannot be cleared.
 */
public final class CertExportOptions implements AutoCloseable {

    static final int MIN_PASSWORD_LENGTH = 8;
    static final int MAX_PASSWORD_LENGTH = 128;
    /**
     * Printable ASCII (space to tilde) only: PKCS#12 implementations disagree on how they encode
     * other password characters (BMPString, UTF-8, the platform charset), so a file protected with
     * an accent or emoji can fail to open on some servers.
     */
    private static final char FIRST_PRINTABLE_ASCII = 0x20;
    private static final char LAST_PRINTABLE_ASCII = 0x7E;
    static final String UNSUPPORTED_PASSWORD_CHARACTERS_MESSAGE = "Use letters, numbers and standard "
            + "symbols only (no accents or emoji) — some servers can't open files protected with other characters.";

    private final CertExportFormat format;
    private final char[] password;
    private final boolean legacyPkcs12;

    private CertExportOptions(CertExportFormat format, char[] password, boolean legacyPkcs12) {
        this.format = format;
        this.password = password;
        this.legacyPkcs12 = legacyPkcs12;
    }

    /**
     * Validates {@code request}.
     *
     * @throws CertExportException 400 INVALID_EXPORT_REQUEST for a missing or unknown format, or a
     *                             PKCS12 password that is missing, out of length bounds or holds a
     *                             character outside printable ASCII
     */
    public static CertExportOptions from(CertExportRequest request) {
        if (request == null || request.format() == null) {
            throw CertExportException.invalidRequest("format is required.");
        }
        CertExportFormat format = parseFormat(request.format());
        if (format != CertExportFormat.PKCS12) {
            return new CertExportOptions(format, null, false);
        }
        validatePassword(request.password());
        return new CertExportOptions(format, request.password().toCharArray(),
                Boolean.TRUE.equals(request.legacyPkcs12()));
    }

    private static CertExportFormat parseFormat(String raw) {
        for (CertExportFormat candidate : CertExportFormat.values()) {
            if (candidate.name().equals(raw)) {
                return candidate;
            }
        }
        throw CertExportException.invalidRequest(
                "format must be one of " + Arrays.toString(CertExportFormat.values()) + ".");
    }

    private static void validatePassword(String password) {
        if (password == null) {
            throw CertExportException.invalidRequest("password is required for PKCS12.");
        }
        int length = password.codePointCount(0, password.length());
        if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
            throw CertExportException.invalidRequest("password must be " + MIN_PASSWORD_LENGTH + " to "
                    + MAX_PASSWORD_LENGTH + " characters.");
        }
        if (!password.chars().allMatch(CertExportOptions::isPrintableAscii)) {
            throw CertExportException.invalidRequest(UNSUPPORTED_PASSWORD_CHARACTERS_MESSAGE);
        }
    }

    private static boolean isPrintableAscii(int character) {
        return character >= FIRST_PRINTABLE_ASCII && character <= LAST_PRINTABLE_ASCII;
    }

    public CertExportFormat format() {
        return format;
    }

    /** The PKCS12 password, or {@code null} for the PEM formats. The caller must not keep a copy. */
    public char[] password() {
        return password;
    }

    public boolean legacyPkcs12() {
        return legacyPkcs12;
    }

    @Override
    public void close() {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
