// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Encodes DER as an RFC 7468 PEM block straight into bytes, so no copy of key material sits in a String. */
final class PemBlockEncoder {

    private static final int LINE_LENGTH = 64;
    private static final byte[] NEWLINE = {'\n'};
    private static final Base64.Encoder ENCODER = Base64.getMimeEncoder(LINE_LENGTH, NEWLINE);

    private PemBlockEncoder() {
    }

    static byte[] encode(String type, byte[] der) {
        byte[] header = ("-----BEGIN " + type + "-----\n").getBytes(StandardCharsets.US_ASCII);
        byte[] footer = ("\n-----END " + type + "-----\n").getBytes(StandardCharsets.US_ASCII);
        byte[] body = ENCODER.encode(der);
        try {
            byte[] pem = new byte[header.length + body.length + footer.length];
            System.arraycopy(header, 0, pem, 0, header.length);
            System.arraycopy(body, 0, pem, header.length, body.length);
            System.arraycopy(footer, 0, pem, header.length + body.length, footer.length);
            return pem;
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }
}
